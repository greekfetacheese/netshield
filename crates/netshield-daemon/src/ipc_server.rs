//! The control socket between the root daemon and its (unprivileged) clients.
//!
//! Wire format: one JSON value per line over a `SOCK_STREAM` Unix socket, using the types
//! in [`netshield_core::ipc`]. The server owns the listener, the client registry and the
//! snapshots that `ListRules` / `Status` / `SetMode` answer from; requests that need policy
//! state (`Decide`, rule edits) are handed to the daemon loop through a channel, so a
//! client never waits on a packet verdict to read the status panel.
//!
//! Authentication is `SO_PEERCRED`: the credentials are fixed when the client connects, so
//! a peer that later changes its UID cannot inherit access it was denied. The server
//! refuses to start at all unless it runs as root, because the socket's ownership and mode
//! are the only thing standing between a local user and the firewall.
//!
//! Every frame is bounded by [`MAX_FRAME_LEN`]: the reader accumulates at most that many
//! bytes and closes the connection rather than letting a client grow the buffer without
//! limit.

use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use log::{debug, info, warn};
use netshield_core::Rule;
use netshield_core::ipc::{
   MAX_FRAME_LEN, Mode, PROTOCOL_VERSION, Request, Response, StatusInfo, decode_line, encode_line,
   frame_len_ok,
};

use crate::netlink::socket::peer_uid;

/// The largest frame the reader accepts, quoted in the refusal log line.
const FRAME_LIMIT: usize = MAX_FRAME_LEN;

/// Bytes taken from the socket per call, so an oversized frame is noticed early.
const READ_CHUNK: usize = 4096;

/// Why the control socket could not be created.
#[derive(Debug)]
pub enum IpcError {
   /// The process is not root, so it must not own the control socket.
   NotRoot,
   /// A filesystem or socket operation failed.
   Io(io::Error),
   /// `socket_path` exists and is not a Unix socket, so removing it could destroy data.
   NotASocket(PathBuf),
}

impl fmt::Display for IpcError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::NotRoot => f.write_str(
            "must run as root (the control socket is root-owned and authenticates peers \
             with SO_PEERCRED)",
         ),
         Self::Io(error) => write!(f, "control socket I/O error: {error}"),
         Self::NotASocket(path) => write!(
            f,
            "refusing to remove {}: it exists and is not a Unix socket",
            path.display()
         ),
      }
   }
}

impl std::error::Error for IpcError {
   fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
      match self {
         Self::Io(error) => Some(error),
         _ => None,
      }
   }
}

impl From<io::Error> for IpcError {
   fn from(error: io::Error) -> Self {
      Self::Io(error)
   }
}

/// An authenticated client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
   pub uid: u32,
}

/// Reads the process's effective UID from `/proc/self/status`.
pub fn effective_uid() -> Option<u32> {
   parse_effective_uid(&fs::read_to_string("/proc/self/status").ok()?)
}

/// Extracts the effective UID from the `Uid:` line (`real`, `effective`, `saved`, `fs`).
fn parse_effective_uid(status: &str) -> Option<u32> {
   status
      .lines()
      .find_map(|line| line.strip_prefix("Uid:"))
      .and_then(|fields| fields.split_whitespace().nth(1))
      .and_then(|effective| effective.parse().ok())
}

/// Whether `uid` may talk to this daemon.
///
/// Root is always allowed; otherwise exactly the configured UID. `None` is root only, and
/// never a wildcard, matching [`netshield_core::Config::allowed_uid`].
fn peer_allowed(uid: u32, allowed_uid: Option<u32>) -> bool {
   uid == 0 || Some(uid) == allowed_uid
}

/// The ownership the control socket gets after bind: uid, gid and mode.
///
/// Without an `allowed_uid` the socket stays `root:root 0660`. With one it is handed to
/// that user and their primary group so their GUI can open it, and `SO_PEERCRED` still
/// decides which UIDs may actually use it. A user whose group cannot be resolved keeps
/// the safe `root:root` default rather than guessing a gid.
fn socket_ownership(allowed_uid: Option<u32>) -> (u32, u32, u32) {
   match allowed_uid.and_then(|uid| primary_gid(uid).map(|gid| (uid, gid))) {
      Some((uid, gid)) => (uid, gid, 0o660),
      None => (0, 0, 0o660),
   }
}

/// The primary gid of `uid`, read from `/etc/passwd`.
///
/// Reading the passwd file rather than calling `getpwuid_r` keeps the ownership fix to a
/// single `unsafe` call (`chown`). A malformed line is skipped, never a panic.
fn primary_gid(uid: u32) -> Option<u32> {
   let passwd = fs::read_to_string("/etc/passwd").ok()?;
   passwd.lines().find_map(|line| {
      let mut fields = line.split(':');
      let _name = fields.next()?;
      let _password = fields.next()?;
      let entry_uid: u32 = fields.next()?.parse().ok()?;
      let entry_gid: u32 = fields.next()?.parse().ok()?;
      (entry_uid == uid).then_some(entry_gid)
   })
}

/// Hands the socket to `allowed_uid` and its primary group, then applies the mode.
///
/// The mode is set after the chown because `chown` clears the set-id bits; doing it in
/// this order means a later ownership change can never relax the access bits. A missing
/// passwd entry leaves the socket `root:root`, which the GUI cannot open, so it is
/// logged rather than guessed at.
fn apply_socket_ownership(path: &Path, allowed_uid: Option<u32>) -> io::Result<()> {
   let (uid, gid, mode) = socket_ownership(allowed_uid);
   let mut ownership = Ok(());
   if let Some(requested) = allowed_uid {
      if uid == requested {
         ownership = chown_socket(path, uid, gid);
      } else {
         warn!(
            "could not look up the primary group of uid {requested}: the control socket \
             stays root:root and the GUI cannot connect"
         );
      }
   }
   fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
   ownership
}

/// Changes ownership of the socket file at `path` to `uid:gid`.
fn chown_socket(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
   let path = CString::new(path.as_os_str().as_bytes())
      .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
   // SAFETY: `path` is a valid NUL-terminated C string built from a `Path` (a path byte
   // cannot contain a NUL without failing the conversion above), and `uid`/`gid` are
   // passed by value. `-1` is not passed for either field, so ownership is the only
   // attribute this call changes.
   let result = unsafe { libc::chown(path.as_ptr(), uid, gid) };
   if result == 0 {
      Ok(())
   } else {
      Err(io::Error::last_os_error())
   }
}

/// The snapshots the server answers from, published by the daemon loop.
struct State {
   mode: Mode,
   rules: Vec<Rule>,
   status: Option<StatusInfo>,
}

/// One connected client's write half.
struct Client {
   writer: Mutex<UnixStream>,
}

/// State shared by the acceptor, the reader threads and the daemon loop.
struct Shared {
   clients: Mutex<HashMap<u64, Client>>,
   state: Mutex<State>,
   requests: Mutex<mpsc::Receiver<(u64, Request)>>,
   sender: mpsc::Sender<(u64, Request)>,
   next_client: AtomicU64,
}

impl Shared {
   fn register(&self, stream: &UnixStream) -> io::Result<u64> {
      let writer = stream.try_clone()?;
      let id = self.next_client.fetch_add(1, Ordering::Relaxed);
      self.clients.lock().expect("client registry").insert(
         id,
         Client {
            writer: Mutex::new(writer),
         },
      );
      Ok(id)
   }

   fn unregister(&self, id: u64) {
      self.clients.lock().expect("client registry").remove(&id);
   }

   fn clients(&self) -> usize {
      self.clients.lock().expect("client registry").len()
   }

   fn send(&self, id: u64, message: &Response) {
      let bytes = match encode_line(message) {
         Ok(bytes) => bytes,
         Err(err) => {
            warn!(
               "could not encode {} for a control client: {err}",
               kind(message)
            );
            return;
         }
      };
      let clients = self.clients.lock().expect("client registry");
      let Some(client) = clients.get(&id) else {
         return;
      };
      let mut writer = client.writer.lock().expect("client writer");
      if let Err(err) = writer.write_all(&bytes) {
         debug!("control client {id}: write failed: {err}");
      }
   }

   /// Sends `message` to every connected client, forgetting the ones that are gone.
   fn broadcast(&self, message: &Response) {
      let bytes = match encode_line(message) {
         Ok(bytes) => bytes,
         Err(err) => {
            warn!(
               "could not encode {} for broadcast: {err}",
               kind(message)
            );
            return;
         }
      };

      let mut gone = Vec::new();
      {
         let clients = self.clients.lock().expect("client registry");
         for (id, client) in clients.iter() {
            let mut writer = client.writer.lock().expect("client writer");
            if writer.write_all(&bytes).is_err() {
               gone.push(*id);
            }
         }
      }
      if gone.is_empty() {
         return;
      }
      let mut clients = self.clients.lock().expect("client registry");
      for id in gone {
         clients.remove(&id);
      }
   }
}

/// A short label for a response, so a log line never dumps every rule.
fn kind(message: &Response) -> &'static str {
   match message {
      Response::Hello { .. } => "Hello",
      Response::Rules { .. } => "Rules",
      Response::Prompt(_) => "Prompt",
      Response::PromptClosed { .. } => "PromptClosed",
      Response::Connection(_) => "Connection",
      Response::Status(_) => "Status",
      Response::Error { .. } => "Error",
   }
}

/// The listening socket, its peer policy and the shared client state.
pub struct IpcServer {
   listener: UnixListener,
   path: PathBuf,
   allowed_uid: Option<u32>,
   shared: Arc<Shared>,
}

impl IpcServer {
   /// Binds `socket_path`, replacing a stale socket file and creating the parent directory.
   ///
   /// Refuses to run unless the caller is root. The socket file is mode `0660`; a parent
   /// directory this call creates is mode `0750`, while an existing one (for example
   /// `/run`) is left exactly as the system set it up.
   pub fn bind(socket_path: &Path, allowed_uid: Option<u32>) -> Result<Self, IpcError> {
      if effective_uid() != Some(0) {
         warn!("refusing to bind the control socket: not running as root");
         return Err(IpcError::NotRoot);
      }

      if let Some(parent) = socket_path.parent()
         && !parent.as_os_str().is_empty()
         && !parent.exists()
      {
         fs::create_dir_all(parent)?;
         fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
      }

      remove_stale_socket(socket_path)?;
      let listener = UnixListener::bind(socket_path)?;
      if let Err(err) = apply_socket_ownership(socket_path, allowed_uid) {
         warn!(
            "could not give the control socket to allowed uid {allowed_uid:?}: {err}; \
             the GUI cannot connect"
         );
      }

      let (sender, receiver) = mpsc::channel();
      info!(
         "control socket listening on {} (allowed uid {:?})",
         socket_path.display(),
         allowed_uid
      );
      Ok(Self {
         listener,
         path: socket_path.to_path_buf(),
         allowed_uid,
         shared: Arc::new(Shared {
            clients: Mutex::new(HashMap::new()),
            state: Mutex::new(State {
               mode: Mode::Alert,
               rules: Vec::new(),
               status: None,
            }),
            requests: Mutex::new(receiver),
            sender,
            next_client: AtomicU64::new(1),
         }),
      })
   }

   /// Accepts connections on a background thread; each connection gets its own reader.
   ///
   /// The acceptor only authenticates and registers; it never parses a request, so a slow
   /// or silent client cannot hold up the accept loop for everyone else.
   pub fn spawn(self) -> IpcHandle {
      let shared = Arc::clone(&self.shared);
      let allowed_uid = self.allowed_uid;
      let listener = self.listener;
      let path = self.path;

      let acceptor =
         thread::Builder::new().name("netshield-ipc-accept".to_owned()).spawn(move || {
            for accepted in listener.incoming() {
               let stream = match accepted {
                  Ok(stream) => stream,
                  Err(err) => {
                     warn!("control socket accept failed: {err}");
                     continue;
                  }
               };
               let reader_shared = Arc::clone(&shared);
               let reader = thread::Builder::new()
                  .name("netshield-ipc-client".to_owned())
                  .spawn(move || serve(stream, reader_shared, allowed_uid));
               if let Err(err) = reader {
                  warn!("could not spawn a control reader: {err}");
               }
            }
            debug!(
               "control socket acceptor on {} stopped",
               path.display()
            );
         });

      if let Err(err) = acceptor {
         warn!("could not spawn the control acceptor; clients cannot connect: {err}");
      }

      IpcHandle {
         shared: self.shared,
      }
   }
}

/// A cloneable handle the daemon loop uses to broadcast and collect requests.
#[derive(Clone)]
pub struct IpcHandle {
   shared: Arc<Shared>,
}

impl IpcHandle {
   /// Sends one message to every connected client, dropping any that have gone away.
   pub fn broadcast(&self, message: &Response) {
      self.shared.broadcast(message);
   }

   /// Whether at least one client is connected.
   ///
   /// Every authenticated connection receives broadcasts — the protocol has no separate
   /// "listening" flag that could suppress a prompt — so a connected client counts as a
   /// subscriber, which is what the "no GUI attached" warning needs.
   pub fn is_subscribed(&self) -> bool {
      self.clients() > 0
   }

   /// Number of connected clients.
   pub fn clients(&self) -> usize {
      self.shared.clients()
   }

   /// Removes one request from the channel the reader threads feed.
   ///
   /// `None` means no client is talking; the daemon loop calls this every iteration and
   /// must not block on it.
   pub fn try_recv(&self) -> Option<(u64, Request)> {
      self.shared.requests.lock().expect("request channel").try_recv().ok()
   }

   /// Publishes the rule snapshot that `ListRules` answers with.
   pub fn set_rules(&self, rules: &[Rule]) {
      self.shared.state.lock().expect("ipc state").rules = rules.to_vec();
   }

   /// Publishes the status snapshot that `Status` answers with.
   ///
   /// The mode in the snapshot is taken from the server's own state, not from `status`:
   /// a `SetMode` can arrive between the daemon's last apply and this publish, and echoing
   /// the daemon's stale mode would silently undo the client's request.
   pub fn set_status(&self, status: StatusInfo) {
      let mut state = self.shared.state.lock().expect("ipc state");
      let status = StatusInfo {
         mode: state.mode,
         ..status
      };
      state.status = Some(status);
   }

   /// The mode the server most recently published.
   ///
   /// `SetMode` is answered by the server so the status panel updates immediately; the
   /// daemon loop reads this each iteration and applies the behaviour change.
   pub fn mode(&self) -> Mode {
      self.shared.state.lock().expect("ipc state").mode
   }
}

impl fmt::Debug for IpcHandle {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.debug_struct("IpcHandle").field("clients", &self.shared.clients()).finish()
   }
}

/// Removes a socket file left behind by a previous run, refusing anything else.
fn remove_stale_socket(path: &Path) -> Result<(), IpcError> {
   let metadata = match fs::symlink_metadata(path) {
      Ok(metadata) => metadata,
      Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
      Err(error) => return Err(IpcError::Io(error)),
   };
   if !metadata.file_type().is_socket() {
      return Err(IpcError::NotASocket(path.to_path_buf()));
   }
   fs::remove_file(path)?;
   Ok(())
}

/// Serves one client: authenticate, handshake, then dispatch until it disconnects.
fn serve(mut stream: UnixStream, shared: Arc<Shared>, allowed_uid: Option<u32>) {
   let uid = match peer_uid(std::os::fd::AsRawFd::as_raw_fd(&stream)) {
      Ok(uid) => uid,
      Err(err) => {
         warn!("could not read a control peer's credentials, closing it: {err}");
         return;
      }
   };
   if !peer_allowed(uid, allowed_uid) {
      warn!("refusing the control socket to uid {uid}: not root and not the allowed user");
      return;
   }
   let client = Peer { uid };
   let id = match shared.register(&stream) {
      Ok(id) => id,
      Err(err) => {
         warn!("could not register a control client: {err}");
         return;
      }
   };
   debug!(
      "control client {id} connected as uid {}",
      client.uid
   );

   let mut buffered = Vec::new();
   if !handshake(&mut stream, &shared, id, &mut buffered) {
      shared.unregister(id);
      return;
   }

   loop {
      let frame = match read_frame(&mut stream, &mut buffered) {
         Ok(Some(frame)) => frame,
         Ok(None) => break,
         Err(ReadError::TooLong) => {
            warn!("closing control client {id}: a frame exceeded {FRAME_LIMIT} bytes");
            break;
         }
         Err(ReadError::Io(err)) => {
            debug!("control client {id} read failed: {err}");
            break;
         }
      };

      let request: Request = match decode_line(&frame) {
         Ok(request) => request,
         Err(err) => {
            shared.send(
               id,
               &Response::Error {
                  message: format!("malformed request: {err}"),
               },
            );
            warn!("closing control client {id}: malformed request: {err}");
            break;
         }
      };

      if !dispatch(id, request, &shared) {
         break;
      }
   }

   shared.unregister(id);
   debug!("control client {id} disconnected");
}

/// Reads and validates the mandatory first frame.
///
/// Returns `false` after answering with [`Response::Error`], which also closes the
/// connection: a client that does not speak this protocol version cannot be served safely.
fn handshake(stream: &mut UnixStream, shared: &Shared, id: u64, buffered: &mut Vec<u8>) -> bool {
   let frame = match read_frame(stream, buffered) {
      Ok(Some(frame)) => frame,
      Ok(None) => return false,
      Err(ReadError::TooLong) => {
         warn!("closing control client {id}: the first frame exceeded {FRAME_LIMIT} bytes");
         return false;
      }
      Err(ReadError::Io(err)) => {
         debug!("control client {id} disconnected before Hello: {err}");
         return false;
      }
   };

   let version = match decode_line::<Request>(&frame) {
      Ok(Request::Hello { version, .. }) => version,
      Ok(_) => {
         shared.send(
            id,
            &Response::Error {
               message: "the first message must be Hello".to_owned(),
            },
         );
         return false;
      }
      Err(err) => {
         shared.send(
            id,
            &Response::Error {
               message: format!("malformed Hello: {err}"),
            },
         );
         return false;
      }
   };

   if version != PROTOCOL_VERSION {
      shared.send(
         id,
         &Response::Error {
            message: format!(
               "protocol version {version} is not supported (this daemon speaks {PROTOCOL_VERSION})"
            ),
         },
      );
      warn!("closing control client {id}: protocol version {version} != {PROTOCOL_VERSION}");
      return false;
   }
   true
}

/// Handles one decoded request; `false` closes the connection.
fn dispatch(id: u64, request: Request, shared: &Shared) -> bool {
   match request {
      Request::Hello { .. } => {
         shared.send(
            id,
            &Response::Error {
               message: "Hello was already sent".to_owned(),
            },
         );
         false
      }
      Request::Subscribe => {
         debug!("control client {id} subscribed to events");
         true
      }
      Request::ListRules => {
         let rules = shared.state.lock().expect("ipc state").rules.clone();
         shared.send(id, &Response::Rules { rules });
         true
      }
      Request::Status => {
         let status = shared.state.lock().expect("ipc state").status.clone();
         match status {
            Some(status) => {
               shared.send(id, &Response::Status(status));
               true
            }
            None => {
               shared.send(
                  id,
                  &Response::Error {
                     message: "the daemon has not published its status yet".to_owned(),
                  },
               );
               true
            }
         }
      }
      Request::SetMode { mode } => {
         let mut state = shared.state.lock().expect("ipc state");
         state.mode = mode;
         if let Some(status) = state.status.as_mut() {
            status.mode = mode;
         }
         drop(state);
         debug!("control client {id} set the mode to {mode:?}");
         true
      }
      other => {
         if shared.sender.send((id, other)).is_err() {
            warn!("control request channel is closed; request dropped");
            return false;
         }
         true
      }
   }
}

/// Why a frame could not be read.
#[derive(Debug)]
enum ReadError {
   Io(io::Error),
   TooLong,
}

impl From<io::Error> for ReadError {
   fn from(error: io::Error) -> Self {
      Self::Io(error)
   }
}

/// Removes the control socket file at shutdown; a missing file is success.
pub fn remove_socket_file(path: &Path) -> io::Result<()> {
   match fs::remove_file(path) {
      Ok(()) => Ok(()),
      Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
      Err(error) => Err(error),
   }
}

/// Reads one newline-terminated frame, or `None` at a clean end of stream.
///
/// The accumulator is checked against [`FRAME_LIMIT`] before every read, so an endless
/// line is refused once it grows past the limit instead of being buffered to exhaustion.
fn read_frame<R: Read>(
   reader: &mut R,
   buffered: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, ReadError> {
   loop {
      if let Some(end) = buffered.iter().position(|byte| *byte == b'\n') {
         let frame: Vec<u8> = buffered.drain(..=end).collect();
         if !frame_len_ok(frame.len()) {
            return Err(ReadError::TooLong);
         }
         return Ok(Some(frame));
      }
      if buffered.len() > FRAME_LIMIT {
         return Err(ReadError::TooLong);
      }

      let mut chunk = [0u8; READ_CHUNK];
      let read = reader.read(&mut chunk)?;
      if read == 0 {
         return Ok(None);
      }
      buffered.extend_from_slice(&chunk[..read]);
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use netshield_core::ipc::{ClientKind, DecideRequest, ScopeChoice};
   use netshield_core::rule::{Action, AppMatcher, DestMatcher, Duration, RuleId};
   use std::io::Cursor;
   use std::time::Duration as StdDuration;

   fn shared() -> Arc<Shared> {
      let (sender, receiver) = mpsc::channel();
      Arc::new(Shared {
         clients: Mutex::new(HashMap::new()),
         state: Mutex::new(State {
            mode: Mode::Alert,
            rules: Vec::new(),
            status: None,
         }),
         requests: Mutex::new(receiver),
         sender,
         next_client: AtomicU64::new(1),
      })
   }

   fn hello(version: u32) -> Vec<u8> {
      encode_line(&Request::Hello {
         version,
         client: ClientKind::Cli,
      })
      .expect("hello encodes")
   }

   fn rule() -> Rule {
      Rule {
         id: RuleId::new_unique(),
         enabled: true,
         app: AppMatcher::Any,
         dest: DestMatcher::Any,
         action: Action::Allow,
         duration: Duration::Forever,
         note: None,
         created_at: 1,
         updated_at: 1,
         last_matched: None,
         hits: 0,
      }
   }

   fn status(mode: Mode, rules: usize) -> StatusInfo {
      StatusInfo {
         daemon_pid: 7,
         mode,
         rule_count: rules,
         pending_prompts: 0,
         queue_num: 0,
         queue_drops: 0,
         table_verified: true,
         started_at: 1,
      }
   }

   fn temp_socket(name: &str) -> PathBuf {
      let nanos = std::time::SystemTime::now()
         .duration_since(std::time::UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      std::env::temp_dir().join(format!("netshield-ipc-{name}-{nanos}.sock"))
   }

   fn our_uid() -> Option<u32> {
      effective_uid()
   }

   fn pair() -> (UnixStream, UnixStream) {
      UnixStream::pair().expect("socketpair")
   }

   fn read_response(client: &mut UnixStream, buffered: &mut Vec<u8>) -> Response {
      let frame = read_frame(client, buffered).expect("readable").expect("a frame");
      decode_line(&frame).expect("a decodable response")
   }

   #[test]
   fn root_and_the_allowed_uid_are_accepted_and_nothing_else_is() {
      assert!(peer_allowed(0, None));
      assert!(peer_allowed(0, Some(1000)));
      assert!(peer_allowed(1000, Some(1000)));
      assert!(!peer_allowed(1000, None), "None means root only");
      assert!(!peer_allowed(1001, Some(1000)));
   }

   #[test]
   fn socket_ownership_defaults_to_root_root_when_no_uid_is_allowed() {
      assert_eq!(socket_ownership(None), (0, 0, 0o660));
   }

   // The chown itself is not tested: it needs root and a real user's passwd entry, and
   // the socket path is a live filesystem object. Only the decision is unit-tested.
   #[test]
   fn socket_ownership_keeps_the_mode_after_a_chown() {
      let (uid, gid, mode) = socket_ownership(Some(0));
      assert_eq!((uid, gid), (0, 0), "root's primary group is 0");
      assert_eq!(
         mode, 0o660,
         "chown clears set-id bits, so the mode is applied after"
      );
   }

   #[test]
   fn effective_uid_reads_the_second_uid_field() {
      let status = "Name:\tnetshieldd\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
      assert_eq!(parse_effective_uid(status), Some(0));
      assert_eq!(parse_effective_uid("Name:\tnetshieldd\n"), None);
      assert_eq!(parse_effective_uid("Uid:\tnot-a-number\n"), None);
   }

   #[test]
   fn a_frame_round_trips_through_the_reader() {
      let mut input = Cursor::new(b"{\"kind\":\"subscribe\"}\n{\"kind\":\"status\"}\n".to_vec());
      let mut buffered = Vec::new();
      let first = read_frame(&mut input, &mut buffered).expect("readable").expect("a frame");
      assert_eq!(
         decode_line::<Request>(&first).expect("decodable"),
         Request::Subscribe
      );
      let second = read_frame(&mut input, &mut buffered).expect("readable").expect("a frame");
      assert_eq!(
         decode_line::<Request>(&second).expect("decodable"),
         Request::Status
      );
      assert!(
         read_frame(&mut input, &mut buffered).expect("readable").is_none(),
         "end of stream"
      );
   }

   #[test]
   fn an_endless_line_is_refused_once_it_exceeds_the_limit() {
      let endless = vec![b'a'; FRAME_LIMIT + READ_CHUNK + 1];
      let mut input = Cursor::new(endless);
      let mut buffered = Vec::new();
      assert!(matches!(
         read_frame(&mut input, &mut buffered),
         Err(ReadError::TooLong)
      ));
   }

   #[test]
   fn a_frame_at_the_limit_is_still_accepted() {
      let mut body = vec![b' '; FRAME_LIMIT - 1];
      body.push(b'\n');
      let mut input = Cursor::new(body);
      let mut buffered = Vec::new();
      let frame = read_frame(&mut input, &mut buffered).expect("readable").expect("a frame");
      assert_eq!(frame.len(), FRAME_LIMIT);
   }

   #[test]
   fn stale_socket_files_are_removed_but_regular_files_are_refused() {
      let path = temp_socket("stale");
      let listener = UnixListener::bind(&path).expect("bind a fixture socket");
      drop(listener);
      assert!(
         path.exists(),
         "the fixture leaves a socket file behind"
      );
      remove_stale_socket(&path).expect("a stale socket is removed");
      assert!(!path.exists());
      remove_stale_socket(&path).expect("a missing path is success");

      let regular = temp_socket("regular");
      fs::write(&regular, b"important").expect("write a fixture file");
      assert!(matches!(
         remove_stale_socket(&regular),
         Err(IpcError::NotASocket(_))
      ));
      assert!(regular.exists(), "the file must still be there");
      let _ = fs::remove_file(&regular);
   }

   #[test]
   fn client_and_status_snapshots_are_published_through_the_handle() {
      let shared = shared();
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      assert_eq!(handle.clients(), 0);
      assert!(!handle.is_subscribed());

      let rule = rule();
      handle.set_rules(std::slice::from_ref(&rule));
      handle.set_status(status(Mode::Alert, 1));
      assert_eq!(
         handle.mode(),
         Mode::Alert,
         "the server owns the mode state"
      );

      let state = shared.state.lock().expect("ipc state");
      assert_eq!(state.rules, vec![rule]);
      assert_eq!(state.status, Some(status(Mode::Alert, 1)));
   }

   #[test]
   fn publishing_a_status_does_not_undo_a_newer_set_mode() {
      let shared = shared();
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      handle.set_status(status(Mode::Alert, 0));
      shared.state.lock().expect("ipc state").mode = Mode::Silent;
      handle.set_status(status(Mode::Alert, 0));
      assert_eq!(handle.mode(), Mode::Silent);
      assert_eq!(
         shared.state.lock().expect("ipc state").status.as_ref().expect("status").mode,
         Mode::Silent
      );
   }

   #[test]
   fn bind_refuses_a_non_root_caller() {
      if our_uid() == Some(0) {
         return;
      }
      let path = temp_socket("nonroot");
      let err = match IpcServer::bind(&path, Some(1000)) {
         Ok(_) => panic!("a non-root caller must be refused"),
         Err(err) => err,
      };
      assert!(matches!(err, IpcError::NotRoot));
      assert!(err.to_string().contains("root"));
      assert!(!path.exists(), "no socket file is created");
   }

   #[test]
   fn a_socketpair_serves_hello_list_rules_and_status() {
      let (server, mut client) = pair();
      let shared = shared();
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      let rule = rule();
      handle.set_rules(std::slice::from_ref(&rule));
      handle.set_status(status(Mode::Alert, 1));

      let uid = our_uid().expect("our own uid");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, Some(uid)));

      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      client
         .write_all(&encode_line(&Request::ListRules).expect("list rules"))
         .expect("send");
      client.write_all(&encode_line(&Request::Status).expect("status")).expect("send");

      let mut buffered = Vec::new();
      assert_eq!(
         read_response(&mut client, &mut buffered),
         Response::Rules { rules: vec![rule] }
      );
      assert!(matches!(
         read_response(&mut client, &mut buffered),
         Response::Status(_)
      ));

      drop(client);
      reader.join().expect("reader thread");
      assert_eq!(handle.clients(), 0);
   }

   #[test]
   fn a_version_mismatch_is_an_error_and_closes_the_connection() {
      let (server, mut client) = pair();
      let shared = shared();
      let uid = our_uid().expect("our own uid");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, Some(uid)));

      client.write_all(&hello(PROTOCOL_VERSION + 1)).expect("hello");
      let mut buffered = Vec::new();
      match read_response(&mut client, &mut buffered) {
         Response::Error { message } => assert!(message.contains("protocol version")),
         other => panic!("expected Error, got {other:?}"),
      }

      let mut rest = Vec::new();
      assert_eq!(
         client.read_to_end(&mut rest).expect("read to eof"),
         0,
         "the server must close after a bad handshake"
      );
      reader.join().expect("reader thread");
   }

   #[test]
   fn a_first_message_that_is_not_hello_is_an_error() {
      let (server, mut client) = pair();
      let shared = shared();
      let uid = our_uid().expect("our own uid");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, Some(uid)));

      client.write_all(&encode_line(&Request::Status).expect("status")).expect("send");
      let mut buffered = Vec::new();
      match read_response(&mut client, &mut buffered) {
         Response::Error { message } => assert!(message.contains("Hello")),
         other => panic!("expected Error, got {other:?}"),
      }
      reader.join().expect("reader thread");
   }

   #[test]
   fn set_mode_updates_the_published_snapshot() {
      let (server, mut client) = pair();
      let shared = shared();
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      handle.set_status(status(Mode::Alert, 0));
      let uid = our_uid().expect("our own uid");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, Some(uid)));

      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      client
         .write_all(&encode_line(&Request::SetMode { mode: Mode::Silent }).expect("set mode"))
         .expect("send");
      client.write_all(&encode_line(&Request::Status).expect("status")).expect("send");

      let mut buffered = Vec::new();
      match read_response(&mut client, &mut buffered) {
         Response::Status(status) => assert_eq!(status.mode, Mode::Silent),
         other => panic!("expected Status, got {other:?}"),
      }
      assert_eq!(handle.mode(), Mode::Silent);

      drop(client);
      reader.join().expect("reader thread");
   }

   #[test]
   fn a_decision_is_forwarded_to_the_daemon_loop() {
      let (server, mut client) = pair();
      let shared = shared();
      let probe = Arc::clone(&shared);
      let uid = our_uid().expect("our own uid");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, Some(uid)));

      let decide = Request::Decide(DecideRequest {
         prompt_id: 9,
         action: Action::Allow,
         duration: Duration::Once,
         scope: ScopeChoice::AnyConnection,
      });
      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      client.write_all(&encode_line(&decide).expect("decide")).expect("send");

      // The reader thread owns the channel inside `Shared`; poll the same server state
      // through a handle rather than guessing at its scheduling.
      let handle = IpcHandle { shared: probe };
      let mut forwarded = None;
      for _ in 0..100 {
         if let Some((_, request)) = handle.try_recv() {
            forwarded = Some(request);
            break;
         }
         thread::sleep(StdDuration::from_millis(10));
      }
      assert_eq!(forwarded, Some(decide));

      drop(client);
      reader.join().expect("reader thread");
   }

   #[test]
   fn an_unauthenticated_peer_is_closed_before_any_request_is_served() {
      let (server, mut client) = pair();
      let shared = shared();
      let allowed = our_uid().map(|uid| uid.wrapping_add(1));
      let reader = thread::spawn(move || serve(server, shared, allowed));

      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      let mut rest = Vec::new();
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      // Closing a socket that still holds unread client bytes makes the kernel answer
      // with RST, so "closed without serving" is either a clean EOF or ECONNRESET.
      match client.read_to_end(&mut rest) {
         Ok(0) => {}
         Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
         other => panic!("expected the peer to be closed, got {other:?}"),
      }
      assert!(
         rest.is_empty(),
         "the server must not answer an unauthorised peer"
      );
      reader.join().expect("reader thread");
   }
}
