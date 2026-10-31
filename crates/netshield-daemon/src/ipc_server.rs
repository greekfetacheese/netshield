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
//!
//! Outbound frames never go to a socket from the thread that produces them. Each client
//! owns a writer thread and a bounded queue; the daemon loop and the reader threads only
//! enqueue, so a peer that stops reading cannot block packet processing.

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration as StdDuration;

use log::{debug, info, warn};
use netshield_core::Rule;
use netshield_core::ipc::{
   MAX_FRAME_LEN, Mode, PROTOCOL_VERSION, Request, Response, StatusInfo, decode_line, encode_line,
   frame_len_ok,
};
use netshield_core::rule::{Action, Duration, socket_rule_refusal};

use crate::netlink::socket::peer_creds;

/// The largest frame the reader accepts, quoted in the refusal log line.
const FRAME_LIMIT: usize = MAX_FRAME_LEN;

/// Bytes taken from the socket per call, so an oversized frame is noticed early.
const READ_CHUNK: usize = 4096;

/// Frames buffered per control client before the daemon sheds that client.
///
/// The bound buys a busy GUI about a second of lag without ever stalling the firewall,
/// and caps what a peer that stops reading can make the daemon hold in memory. A client
/// that cannot drain a queue this deep is not reading at all, so the packet path wins.
const CLIENT_QUEUE_FRAMES: usize = 1024;

/// How long one frame may take to reach a control client before its writer gives up.
///
/// A GUI that has not drained 64 KiB in five seconds is gone: either it stopped reading
/// or the peer is hostile. Without this bound the writer thread parks inside `write_all`
/// for ever after the client is shed, holding its socket and its stack, so a peer that
/// connects and never reads would grow the daemon by one thread per connection. The writer
/// must not outlive the client, so a timed-out write ends the thread instead of retrying.
const WRITE_TIMEOUT: StdDuration = StdDuration::from_secs(5);

/// Concurrent control clients the daemon serves before refusing new ones.
///
/// A desktop has one GUI and maybe a CLI probe, so 64 concurrent control connections is
/// already pathological: the limit turns "a peer that connects and never reads" from a
/// thread and socket leak into a refusal, while leaving ample room for the real clients.
const MAX_CLIENTS: usize = 64;

/// Registry slots held back for the configured GUI binary.
///
/// The GUI must always be able to attach: without a reservation, foreign peers of the same
/// uid can take every slot, and the GUI is locked out exactly when it is needed. Eight
/// slots are more than any real GUI opens and still leave 56 for every other client.
const RESERVED_GUI_SLOTS: usize = 8;

/// How long a connecting peer has to finish the handshake before it is closed.
///
/// A peer that connects and says nothing is not a client: it holds a registry slot, a
/// writer thread and a socket while it never becomes one. The timeout bounds exactly the
/// un-handshaked state, so it cannot disturb a GUI that has already introduced itself and
/// then sits idle for hours.
const HANDSHAKE_TIMEOUT: StdDuration = StdDuration::from_secs(5);

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
///
/// The uid decides whether the peer may talk to the daemon at all; the pid decides whether
/// it is the configured GUI and may therefore change state, checked against
/// `/proc/<pid>/exe`. A pid of `0` means the kernel did not report one and can never match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
   pub pid: u32,
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

/// The GUI identity the control socket enforces, fixed once at bind time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuiPolicy {
   /// The uid permitted to talk to the socket at all; `None` is root only.
   pub allowed_uid: Option<u32>,
   /// The only executable allowed to change firewall state; `None` keeps the uid-only rule
   /// for a config installed before the key existed, and is warned about at bind time.
   pub gui_path: Option<PathBuf>,
}

/// Whether a peer may change firewall state: only the configured GUI executable.
///
/// `exe` is the peer's already-resolved `/proc/<pid>/exe`, so the caller does one `readlink`
/// per state-changing request and uses the same answer for the audit line. With a
/// `gui_path` the executable must equal it; a different path, an unreadable link or pid 0
/// is a refusal. Without one the historical uid-only rule stands, which [`IpcServer::bind`]
/// warns about because any process of that uid then qualifies.
/// This is one half of the gate: [`provenance_refusal`] then decides whether the process
/// behind that path can be trusted to run the code it appears to.
fn peer_may_mutate(policy: &GuiPolicy, peer: &Peer, exe: Option<&Path>) -> bool {
   match policy.gui_path.as_deref() {
      Some(gui_path) => peer.pid != 0 && exe == Some(gui_path),
      None => peer_allowed(peer.uid, policy.allowed_uid),
   }
}

/// Why a state-changing request was refused, phrased as the requirement it failed.
fn refusal(policy: &GuiPolicy) -> String {
   match policy.gui_path.as_deref() {
      Some(path) => format!(
         "changing firewall state requires the configured GUI executable {}",
         path.display()
      ),
      None => "changing firewall state requires the allowed uid".to_owned(),
   }
}

/// Resolves the executable `/proc/<pid>/exe` points at.
///
/// `readlink` on a deleted binary returns the original path with a trailing `" (deleted)"`,
/// which is stripped so a GUI replaced by an upgrade keeps working until it restarts.
/// Any error or non-UTF-8 target is `None`, which the caller treats as not-the-GUI.
fn executable_path(pid: u32) -> Option<PathBuf> {
   let target = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
   let bytes = target.as_os_str().as_bytes();
   let suffix = b" (deleted)";
   if let Some(path) = bytes.strip_suffix(suffix) {
      return Some(PathBuf::from(OsStr::from_bytes(path)));
   }
   Some(target)
}

/// Whether a request only reads daemon state.
fn is_read_only(request: &Request) -> bool {
   matches!(
      request,
      Request::Hello { .. } | Request::Subscribe | Request::ListRules | Request::Status
   )
}

/// Variables that make a dynamic loader load code the peer chose.
///
/// `LD_PRELOAD` and `LD_AUDIT` inject a library unconditionally; the rest steer glibc's
/// module/locale search or the Vulkan/GL loaders, which is the same capability without
/// `LD_PRELOAD`. `LD_LIBRARY_PATH` is deliberately **not** here: it is set by ordinary build
/// tooling (cargo sets it for test binaries) and only matters if something from a writable
/// directory actually gets loaded, which `provenance_refusal` decides on evidence.
const LOADER_VARIABLE_NAMES: [&str; 6] = [
   "LD_PRELOAD",
   "LD_AUDIT",
   "GLIBC_TUNABLES",
   "GCONV_PATH",
   "NLSPATH",
   "LOCPATH",
];

/// Prefixes with the same effect the exact names have (Vulkan drivers/layers, Mesa, GLX, GBM).
const LOADER_VARIABLE_PREFIXES: [&str; 4] = ["VK_", "MESA_", "__GLX_", "GBM_"];

/// One executable mapping from the peer's `/proc/<pid>/maps`, with the property that decides
/// whether it could have been planted: its directory is writable by the peer's own uid.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExecutableMapping {
   path: PathBuf,
   /// The file's parent directory is writable by the uid that owns the process.
   writable_directory: bool,
}

/// Extracts `TracerPid` from a peer's `/proc/<pid>/status`.
///
/// A missing or unparsable field is `None`, which [`provenance_refusal`] treats as a refusal:
/// a trace the daemon cannot rule out is a trace it cannot allow.
fn parse_tracer_pid(status: &str) -> Option<u32> {
   status
      .lines()
      .find_map(|line| line.strip_prefix("TracerPid:"))
      .and_then(|fields| fields.split_whitespace().next())
      .and_then(|pid| pid.parse().ok())
}

/// Whether a peer may change firewall state, judged on evidence about the running process.
///
/// Every input is `Option` because a read that failed is a refusal: a gate that cannot see the
/// evidence must not answer "allowed". `own_exe` is the peer's already-resolved
/// `/proc/<pid>/exe` — the one mapping allowed to come from a writable directory, because a
/// development build of the GUI legitimately lives in `target/`.
fn provenance_refusal(
   tracer_pid: Option<u32>,
   environment: Option<&[Vec<u8>]>,
   mappings: Option<&[ExecutableMapping]>,
   own_exe: Option<&Path>,
) -> Option<String> {
   match tracer_pid {
      None => return Some("cannot read the peer's tracer from /proc/<pid>/status".to_owned()),
      Some(0) => {}
      Some(pid) => {
         return Some(format!(
            "the peer is being traced (TracerPid {pid}), so the code running in it is not the executable it appears to be"
         ));
      }
   }

   let environment = match environment {
      Some(environment) => environment,
      None => return Some("cannot read the peer's environment".to_owned()),
   };
   for entry in environment {
      let name = match entry.iter().position(|byte| *byte == b'=') {
         Some(index) => &entry[..index],
         None => entry.as_slice(),
      };
      let denied = LOADER_VARIABLE_NAMES.iter().any(|denied| denied.as_bytes() == name)
         || LOADER_VARIABLE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix.as_bytes()));
      if denied {
         return Some(format!(
            "the peer was started with {} set, so its loader can load code the owner did not approve",
            String::from_utf8_lossy(name)
         ));
      }
   }

   let mappings = match mappings {
      Some(mappings) => mappings,
      None => return Some("cannot read the peer's executable mappings".to_owned()),
   };
   for mapping in mappings {
      if mapping.writable_directory && own_exe != Some(mapping.path.as_path()) {
         return Some(format!(
            "the peer has executable code mapped from {}, a directory its own user can write",
            mapping.path.display()
         ));
      }
   }

   None
}

/// Whether `directory` can be written by `uid` or by anyone.
///
/// A directory that cannot be inspected is reported as not writable: it cannot be proven
/// plantable, and the environment check still covers the direct loader vectors.
fn directory_is_writable(directory: &Path, uid: u32) -> bool {
   match fs::metadata(directory) {
      Ok(meta) => (meta.uid() == uid && meta.mode() & 0o200 != 0) || meta.mode() & 0o002 != 0,
      Err(_) => false,
   }
}

/// Parses the executable mappings out of a peer's `/proc/<pid>/maps`.
///
/// Each line is `start-end perms offset dev inode path`; only rows with `x` in `perms` and a
/// real path survive, because those are the ones whose code can have been planted. The parent
/// directory of each distinct path is inspected once, so a library with many segments costs a
/// single `stat`.
fn executable_mappings(maps: &[u8], uid: u32) -> Vec<ExecutableMapping> {
   let mut mappings = Vec::new();
   let mut directories: HashMap<PathBuf, bool> = HashMap::new();
   for line in maps.split(|byte| *byte == b'\n') {
      let mut fields = line.splitn(6, |byte| *byte == b' ');
      let _range = fields.next();
      match fields.next() {
         Some(perms) if perms.contains(&b'x') => {}
         _ => continue,
      }
      let _offset = fields.next();
      let _device = fields.next();
      let _inode = fields.next();
      let path = match fields.next() {
         Some(path) if !path.is_empty() && path[0] != b'[' => path,
         _ => continue,
      };
      let path = path.strip_suffix(b" (deleted)").unwrap_or(path);
      let path = PathBuf::from(OsStr::from_bytes(path));
      let writable_directory = match path.parent() {
         Some(directory) => {
            if let Some(known) = directories.get(directory) {
               *known
            } else {
               let writable = directory_is_writable(directory, uid);
               directories.insert(directory.to_path_buf(), writable);
               writable
            }
         }
         None => false,
      };
      mappings.push(ExecutableMapping {
         path,
         writable_directory,
      });
   }
   mappings
}

/// Reads the evidence [`provenance_refusal`] decides on, or says which read failed.
///
/// The peer's own uid is needed to judge writability, because a directory the peer's user
/// owns and may write is as plantable as a world-writable one.
fn peer_provenance(pid: u32, uid: u32, own_exe: Option<&Path>) -> Result<(), String> {
   let tracer = fs::read_to_string(format!("/proc/{pid}/status"))
      .ok()
      .and_then(|status| parse_tracer_pid(&status));

   let environment = fs::read(format!("/proc/{pid}/environ")).ok().map(|raw| {
      raw.split(|byte| *byte == 0)
         .filter(|entry| !entry.is_empty())
         .map(<[u8]>::to_vec)
         .collect::<Vec<Vec<u8>>>()
   });

   let mappings = fs::read(format!("/proc/{pid}/maps"))
      .ok()
      .map(|raw| executable_mappings(&raw, uid));

   provenance_refusal(
      tracer,
      environment.as_deref(),
      mappings.as_deref(),
      own_exe,
   )
   .map_or(Ok(()), Err)
}

/// Why a request needs root, or `None` when the desktop user may make it.
///
/// Two requests change what the firewall permits in a way that outlives the click or the session,
/// and neither is anchored to a prompt the user was looking at: turning enforcement off (`SetMode`)
/// and writing a rule by hand (`UpsertRule` with `Forever`). On a desktop where any process of the
/// user's uid can start the GUI with its own loader, or click its window, neither is evidence of the
/// owner's intent — so they are made from a root shell (`netshieldctl`), which an unprivileged
/// process cannot forge.
///
/// A prompt answer may be permanent. The peer is already provenance-checked before this runs, and
/// the permanence it creates is the one the user asked for at that prompt, so `Decide` is not gated
/// here — including `Decide` with `Duration::Forever`. What is gated is the same rule written without
/// a prompt in front of anyone.
///
/// `existing` is the rule set the daemon is serving, used for the two cases that depend on what is
/// already stored. The toggle is gated in both widening directions — a denial switched off and an
/// allow switched back on — because the daemon writes it to the store, so either survives a restart.
fn persistence_refusal(peer_uid: u32, request: &Request, existing: &[Rule]) -> Option<String> {
   const PERMANENT: &str = "a permanent rule requires root: `sudo netshieldctl allow --exe <path> --dest <scope> --duration forever`";

   if peer_uid == 0 {
      return None;
   }

   match request {
      Request::SetMode { .. } => Some(
         "changing the mode requires root: `sudo netshieldctl set-mode alert|silent`".to_owned(),
      ),
      Request::UpsertRule { rule } if rule.duration == Duration::Forever => {
         let unchanged = existing.iter().any(|stored| {
            stored.id == rule.id
               && stored.app == rule.app
               && stored.dest == rule.dest
               && stored.duration == Duration::Forever
               // Switching a disabled rule on is the same grant `SetRuleEnabled` refuses.
               && (stored.enabled || !rule.enabled)
         });
         if unchanged {
            None
         } else {
            Some(PERMANENT.to_owned())
         }
      }
      Request::DeleteRule { id } => match existing.iter().find(|rule| rule.id == *id) {
         // A missing entry is not evidence that the rule is harmless: the snapshot can lag the
         // policy, and a delete of a denial is a grant.
         None => Some(
            "this rule is not in the daemon's published rule set yet; try again in a moment"
               .to_owned(),
         ),
         Some(rule) if rule.action == Action::Deny => Some(
            "withdrawing a denial requires root: `sudo netshieldctl delete <rule-id>`".to_owned(),
         ),
         Some(_) => None,
      },
      Request::SetRuleEnabled { id, enabled } => {
         let Some(stored) = existing.iter().find(|rule| rule.id == *id) else {
            return Some(
               "this rule is not in the daemon's published rule set yet; try again in a moment"
                  .to_owned(),
            );
         };
         if stored.enabled == *enabled {
            return None;
         }
         match (stored.action, *enabled) {
            // A denial that stops applying is a grant, and the toggle is written to the store.
            (Action::Deny, false) => Some(
               "switching a denial off requires root: `sudo netshieldctl disable <rule-id>`"
                  .to_owned(),
            ),
            // A rule that stops applying stops allowing; switching it back on re-grants it.
            (Action::Allow, true) => Some(
               "switching a rule back on requires root: `sudo netshieldctl enable <rule-id>`"
                  .to_owned(),
            ),
            _ => None,
         }
      }
      _ => None,
   }
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

/// Sets the socket's mode, then hands it to `allowed_uid` and its primary group.
///
/// The mode comes first, while the file is still owned by root and no extra capability
/// is needed. "chmod after chown" is the intuitive order and the wrong one here: once
/// the socket belongs to the GUI user, changing its mode needs `CAP_FOWNER`, which the
/// hardened unit does not grant. `chown` only clears the set-id bits and we never set
/// them, so the mode survives the ownership change. If the chown fails the mode is kept
/// and the error is returned for the caller to log; a missing passwd entry leaves the
/// socket `root:root`, which the GUI cannot open, so it is logged rather than guessed at.
fn apply_socket_ownership(path: &Path, allowed_uid: Option<u32>) -> io::Result<()> {
   let (uid, gid, mode) = socket_ownership(allowed_uid);
   fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
   if let Some(requested) = allowed_uid {
      if uid == requested {
         return chown_socket(path, uid, gid);
      }
      warn!(
         "could not look up the primary group of uid {requested}: the control socket \
          stays root:root and the GUI cannot connect"
      );
   }
   Ok(())
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

/// One connected client's outbound path: a bounded queue its writer thread drains.
///
/// The registry holds only this handle, never the socket, so no thread that produces a
/// frame can end up blocked in the kernel behind a peer that stopped reading.
struct Client {
   queue: mpsc::SyncSender<Vec<u8>>,
   /// Frames this client could not accept, quoted in the line that sheds it.
   dropped: AtomicU64,
}

/// How handing a frame to a client's writer thread ended.
enum Enqueue {
   /// The frame is queued; the writer thread will send it in order.
   Queued,
   /// The queue is full, so the client is not draining its socket.
   Stalled,
   /// The writer thread is gone, so the registry entry is stale.
   Gone,
}

/// What a connecting peer may claim from the registry's cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
   /// The configured GUI binary, which may use the reserved slots.
   Gui,
   /// Any other peer: capped below [`MAX_CLIENTS`] while a GUI path is configured.
   Foreign { max: usize },
}

/// Hands one encoded frame to a client's writer thread without ever blocking.
fn enqueue(client: &Client, bytes: &[u8]) -> Enqueue {
   match client.queue.try_send(bytes.to_vec()) {
      Ok(()) => Enqueue::Queued,
      Err(mpsc::TrySendError::Full(_)) => {
         client.dropped.fetch_add(1, Ordering::Relaxed);
         Enqueue::Stalled
      }
      Err(mpsc::TrySendError::Disconnected(_)) => Enqueue::Gone,
   }
}

/// Drains one client's frame queue onto its socket.
///
/// The thread owns the write half, so frames leave in the order they were enqueued. It
/// exits when the client is unregistered (the last sender is dropped) or a write fails;
/// either way the failure stays on this thread instead of the packet path. The socket
/// carries [`WRITE_TIMEOUT`], so a peer that never reads makes the write fail with
/// `WouldBlock`/`TimedOut` after that bound instead of parking the thread for ever; every
/// write error, including `BrokenPipe`/`ConnectionReset`, ends the writer without a retry.
fn write_frames(mut writer: UnixStream, receiver: mpsc::Receiver<Vec<u8>>) {
   if let Err(err) = writer.set_write_timeout(Some(WRITE_TIMEOUT)) {
      debug!("control client writer cannot bound its write, stopping: {err}");
      return;
   }
   for bytes in receiver {
      if let Err(err) = writer.write_all(&bytes) {
         debug!("control client writer stopped: {err}");
         break;
      }
   }
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
   /// Registers a client and starts its writer thread.
   ///
   /// The count is checked and the new entry inserted under one lock, so concurrent
   /// acceptors cannot both slip past [`MAX_CLIENTS`]. A refusal is an
   /// [`io::ErrorKind::ConnectionAborted`] error and leaves the registry untouched; the
   /// caller drops the socket. The configured GUI keeps a slot: a [`Admission::Foreign`]
   /// peer is capped below the full registry, so a flood of ordinary clients cannot lock it
   /// out.
   fn register(&self, stream: &UnixStream, admission: Admission) -> io::Result<u64> {
      let limit = match admission {
         Admission::Gui => MAX_CLIENTS,
         Admission::Foreign { max } => max.min(MAX_CLIENTS),
      };
      let mut clients = self.clients.lock().expect("client registry");
      if clients.len() >= limit {
         return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("control client limit of {limit} reached"),
         ));
      }
      let writer = stream.try_clone()?;
      let id = self.next_client.fetch_add(1, Ordering::Relaxed);
      let (queue, receiver) = mpsc::sync_channel(CLIENT_QUEUE_FRAMES);
      let name = format!("netshield-ipc-writer-{id}");
      thread::Builder::new()
         .name(name)
         .spawn(move || write_frames(writer, receiver))?;
      clients.insert(
         id,
         Client {
            queue,
            dropped: AtomicU64::new(0),
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
      let outcome = {
         let clients = self.clients.lock().expect("client registry");
         clients.get(&id).map(|client| enqueue(client, &bytes))
      };
      match outcome {
         None | Some(Enqueue::Queued) => {}
         Some(Enqueue::Stalled) => self.shed(id, message),
         Some(Enqueue::Gone) => {
            debug!(
               "control client {id} is gone; its {} frame was dropped",
               kind(message)
            );
            self.unregister(id);
         }
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

      let mut stalled = Vec::new();
      let mut gone = Vec::new();
      {
         let clients = self.clients.lock().expect("client registry");
         for (id, client) in clients.iter() {
            match enqueue(client, &bytes) {
               Enqueue::Queued => {}
               Enqueue::Stalled => stalled.push(*id),
               Enqueue::Gone => gone.push(*id),
            }
         }
      }
      for id in gone {
         debug!("control client {id} is gone; unregistering it");
         self.unregister(id);
      }
      for id in stalled {
         self.shed(id, message);
      }
   }

   /// Unregisters a client that cannot keep up and warns about it once.
   ///
   /// The client is removed on the first full queue, so the warning needs no timer of its
   /// own: there is exactly one per client. Dropping the queue sender ends its writer
   /// thread and discards the backlog, which is the whole point — a peer that does not
   /// read its socket is either dead or hostile, and the packet path must not wait for it.
   fn shed(&self, id: u64, message: &Response) {
      let dropped = self
         .clients
         .lock()
         .expect("client registry")
         .remove(&id)
         .map(|client| client.dropped.load(Ordering::Relaxed));
      let Some(dropped) = dropped else {
         return;
      };
      warn!(
         "control client {id} cannot keep up; closing it or the firewall stalls \
          ({dropped} {} frame(s) could not be queued; its backlog is discarded)",
         kind(message)
      );
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
   policy: GuiPolicy,
   shared: Arc<Shared>,
}

impl IpcServer {
   /// Binds `socket_path`, replacing a stale socket file and creating the parent directory.
   ///
   /// Refuses to run unless the caller is root. The socket file is mode `0660`; a parent
   /// directory this call creates is mode `0750`, while an existing one (for example
   /// `/run`) is left exactly as the system set it up.
   pub fn bind(
      socket_path: &Path,
      allowed_uid: Option<u32>,
      gui_path: Option<PathBuf>,
   ) -> Result<Self, IpcError> {
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

      if gui_path.is_none() {
         warn!(
            "no gui_path configured: any process running as uid {} can change rules and mode",
            allowed_uid.map_or_else(|| "root".to_owned(), |uid| uid.to_string())
         );
      }

      let (sender, receiver) = mpsc::channel();
      info!(
         "control socket listening on {} (allowed uid {:?}, gui path {:?})",
         socket_path.display(),
         allowed_uid,
         gui_path
      );
      Ok(Self {
         listener,
         path: socket_path.to_path_buf(),
         policy: GuiPolicy {
            allowed_uid,
            gui_path,
         },
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
      let policy = self.policy;
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
               let reader_policy = policy.clone();
               let reader = thread::Builder::new()
                  .name("netshield-ipc-client".to_owned())
                  .spawn(move || serve(stream, reader_shared, reader_policy));
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
fn serve(stream: UnixStream, shared: Arc<Shared>, policy: GuiPolicy) {
   serve_with_timeout(stream, shared, policy, HANDSHAKE_TIMEOUT)
}

/// [`serve`] with an explicit handshake bound, so a test need not wait [`HANDSHAKE_TIMEOUT`].
fn serve_with_timeout(
   mut stream: UnixStream,
   shared: Arc<Shared>,
   policy: GuiPolicy,
   handshake_timeout: StdDuration,
) {
   let cred = match peer_creds(std::os::fd::AsRawFd::as_raw_fd(&stream)) {
      Ok(cred) => cred,
      Err(err) => {
         warn!("could not read a control peer's credentials, closing it: {err}");
         return;
      }
   };
   if !peer_allowed(cred.uid, policy.allowed_uid) {
      warn!(
         "refusing the control socket to uid {}: not root and not the allowed user",
         cred.uid
      );
      return;
   }
   let client = Peer {
      pid: cred.pid,
      uid: cred.uid,
   };
   let exe = executable_path(client.pid);
   let gui = policy.gui_path.as_deref().is_some_and(|path| exe.as_deref() == Some(path));
   let admission = if gui {
      Admission::Gui
   } else {
      Admission::Foreign {
         max: if policy.gui_path.is_some() {
            MAX_CLIENTS - RESERVED_GUI_SLOTS
         } else {
            MAX_CLIENTS
         },
      }
   };
   let id = match shared.register(&stream, admission) {
      Ok(id) => id,
      Err(err) => {
         warn!("could not register a control client: {err}");
         return;
      }
   };
   debug!(
      "control client {id} connected as uid {} (pid {}, exe {exe:?})",
      client.uid, client.pid
   );

   let mut buffered = Vec::new();
   // The bound covers the un-handshaked state only: a peer that never speaks must not hold
   // a slot for ever, while a real GUI sits silent for hours once it has said Hello.
   if let Err(err) = stream.set_read_timeout(Some(handshake_timeout)) {
      warn!("could not bound a control client's handshake timeout: {err}");
   }
   if !handshake(&mut stream, &shared, id, &mut buffered) {
      shared.unregister(id);
      return;
   }
   // Clear the bound now: idleness after the handshake is healthy, and the loop below treats
   // a timed-out read as a dead peer, which would close a GUI that simply has nothing to say.
   if let Err(err) = stream.set_read_timeout(None) {
      warn!("could not clear a control client's handshake timeout: {err}");
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

      if !dispatch(id, request, &shared, &policy, &client) {
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
///
/// The read/mutate split is enforced here. A read-only request is served for any peer that
/// passed [`peer_allowed`]. A state-changing one is refused unless the peer is the GUI,
/// and the executable is re-read before every such request: a process can `exec` a
/// different binary after connecting, so the check at accept time is not enough.
fn dispatch(id: u64, request: Request, shared: &Shared, policy: &GuiPolicy, peer: &Peer) -> bool {
   if !is_read_only(&request) {
      let exe = executable_path(peer.pid);
      if !peer_may_mutate(policy, peer, exe.as_deref()) {
         let message = refusal(policy);
         warn!(
            "refusing the control request from client {id} (pid {}, exe {exe:?}): {message}",
            peer.pid
         );
         shared.send(id, &Response::Error { message });
         return false;
      }
      if let Err(reason) = peer_provenance(peer.pid, peer.uid, exe.as_deref()) {
         warn!(
            "refusing a policy change from client {id} (pid {}, exe {exe:?}): {reason}",
            peer.pid
         );
         shared.send(id, &Response::Error { message: reason });
         return false;
      }
      info!(
         "control client {id} (pid {}, exe {exe:?}) {request:?}",
         peer.pid
      );
   }

   if !is_read_only(&request) {
      let existing: Vec<Rule> = shared.state.lock().expect("ipc state").rules.clone();
      if let Some(reason) = persistence_refusal(peer.uid, &request, &existing) {
         warn!(
            "refusing a policy change from client {id} (pid {}): {reason}",
            peer.pid
         );
         shared.send(id, &Response::Error { message: reason });
         return false;
      }
   }

   // A rule the socket may not express is answered with an error instead of being forwarded: the
   // daemon loop applies whatever reaches it verbatim, and one request must not be a silent
   // allow-all on disk. The connection stays open — this is a refusal of the request, not of the
   // peer.
   if let Request::UpsertRule { rule } = &request
      && let Some(reason) = socket_rule_refusal(rule)
   {
      warn!(
         "refusing a rule from client {id} (pid {}): {reason}",
         peer.pid
      );
      shared.send(
         id,
         &Response::Error {
            message: reason.to_owned(),
         },
      );
      return true;
   }

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
   use std::time::Instant;

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
         mutation_gated: true,
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

   /// The `/proc` prefix the daemon's writer threads appear under.
   ///
   /// Linux truncates a thread name to 15 bytes, so `netshield-ipc-writer-<id>` reads back
   /// as `netshield-ipc-w`; the shortened prefix is what the kernel actually reports.
   const WRITER_PREFIX: &str = "netshield-ipc-w";

   /// The ids of this process's threads whose `/proc` name starts with `prefix`.
   ///
   /// Ids rather than a count: tests share the process and exactly one other test may have
   /// a writer thread parked for up to [`WRITE_TIMEOUT`], so "our writer is gone" is "no id
   /// outside the baseline set is alive", which cannot be satisfied by an unrelated thread
   /// dying at the same moment.
   fn threads_named(prefix: &str) -> Vec<u32> {
      let tasks = fs::read_dir("/proc/self/task").expect("this process's thread directory");
      tasks
         .filter_map(Result::ok)
         .filter(|task| {
            fs::read_to_string(task.path().join("comm"))
               .is_ok_and(|comm| comm.trim_end().starts_with(prefix))
         })
         .filter_map(|task| task.file_name().to_str()?.parse().ok())
         .collect()
   }

   /// Serialises the tests that create many writer threads, so they never overlap.
   fn serial() -> std::sync::MutexGuard<'static, ()> {
      static LOCK: Mutex<()> = Mutex::new(());
      LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
   }

   /// Polls `predicate` every 100 ms until `deadline`, returning whether it became true.
   fn wait_until(deadline: Instant, mut predicate: impl FnMut() -> bool) -> bool {
      loop {
         if predicate() {
            return true;
         }
         if Instant::now() >= deadline {
            return false;
         }
         thread::sleep(StdDuration::from_millis(100));
      }
   }

   /// The policy the pre-existing tests run under: the configured uid may change state
   /// because no `gui_path` is set, which is the compatibility branch.
   fn policy(allowed_uid: Option<u32>) -> GuiPolicy {
      GuiPolicy {
         allowed_uid,
         gui_path: None,
      }
   }

   /// The path of this test binary, which is its own peer's `/proc/<pid>/exe`.
   fn self_exe() -> PathBuf {
      fs::read_link("/proc/self/exe").expect("the test binary's own exe")
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

   // The successful chown is not tested: it needs root and a real user's passwd entry,
   // and the socket path is a live filesystem object. The decision and the failure
   // ordering are unit-tested below.
   #[test]
   fn socket_ownership_keeps_the_mode_after_a_chown() {
      assert_eq!(
         socket_ownership(None),
         (0, 0, 0o660),
         "no allowed uid means root owns the socket"
      );

      let (uid, gid, mode) = socket_ownership(Some(0));
      assert_eq!((uid, gid), (0, 0), "root's primary group is 0");
      assert_eq!(
         mode, 0o660,
         "chown clears set-id bits, so the mode is applied before it"
      );
   }

   #[test]
   fn a_failed_chown_still_leaves_the_socket_at_the_right_mode() {
      if our_uid() == Some(0) {
         return;
      }
      let path = temp_socket("chown-failure");
      fs::write(&path, b"").expect("write a fixture file");
      fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("start at 0600");

      // Root's passwd entry always resolves, so this reaches the chown; an unprivileged
      // process cannot give the file away to root, and the failure must not undo the
      // mode that was applied first. The exact errno depends on the sandbox (`EPERM`
      // outside it, `EINVAL` under it), so only the failure itself is asserted.
      let err =
         apply_socket_ownership(&path, Some(0)).expect_err("chowning to root needs CAP_CHOWN");
      assert!(err.raw_os_error().is_some(), "{err}");
      let mode = fs::metadata(&path).expect("fixture metadata").permissions().mode();
      assert_eq!(
         mode & 0o777,
         0o660,
         "the failed chown must not leave the socket at the umask mode"
      );
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn effective_uid_reads_the_second_uid_field() {
      let status = "Name:\tnetshieldd\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
      assert_eq!(parse_effective_uid(status), Some(0));
      assert_eq!(parse_effective_uid("Name:\tnetshieldd\n"), None);
      assert_eq!(parse_effective_uid("Uid:\tnot-a-number\n"), None);
   }

   #[test]
   fn the_frame_reader_caps_the_line_length() {
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

      let endless = vec![b'a'; FRAME_LIMIT + READ_CHUNK + 1];
      let mut input = Cursor::new(endless);
      let mut buffered = Vec::new();
      assert!(matches!(
         read_frame(&mut input, &mut buffered),
         Err(ReadError::TooLong)
      ));

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
   fn a_client_that_never_reads_cannot_stall_the_loop() {
      let shared = shared();
      let (server, _client) = pair();

      // Make "never reads" deterministic before the writer thread exists: fill this
      // direction's socket buffer with non-blocking writes from the server end, so the
      // writer has no room to absorb a frame and blocks on its first write. Otherwise the
      // writer could swallow a few hundred frames into the socket buffer before the queue
      // filled, leaving the outcome dependent on the kernel's buffer size.
      {
         let mut filler = server.try_clone().expect("fill the socket buffer");
         filler.set_nonblocking(true).expect("non-blocking");
         let chunk = [b'x'; READ_CHUNK];
         while filler.write(&chunk).is_ok() {}
         filler.set_nonblocking(false).expect("blocking again");
      }
      // The peer end is never read from here on.

      shared
         .register(&server, Admission::Foreign { max: MAX_CLIENTS })
         .expect("register the silent client");
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      assert_eq!(handle.clients(), 1);

      let status = status(Mode::Alert, 0);
      let started = Instant::now();
      for _ in 0..CLIENT_QUEUE_FRAMES + 50 {
         shared.broadcast(&Response::Status(status.clone()));
      }
      let elapsed = started.elapsed();
      assert!(
         elapsed < StdDuration::from_secs(2),
         "a silent client blocked the loop for {elapsed:?}"
      );
      assert_eq!(
         handle.clients(),
         0,
         "a client that cannot keep up must be unregistered"
      );
   }

   #[test]
   fn a_client_that_never_speaks_is_closed_after_the_handshake_timeout() {
      let _serial = serial();
      let shared = shared();
      let (server, mut peer) = pair();

      let serviced = Arc::clone(&shared);
      thread::spawn(move || {
         serve_with_timeout(
            server,
            serviced,
            policy(Some(1000)),
            StdDuration::from_millis(50),
         );
      });

      // The peer never writes, so the server sends nothing either: EOF here is the server
      // dropping the socket, which proves the connection was closed instead of polled for
      // a registration that a 50 ms window may already have erased.
      peer.set_read_timeout(Some(StdDuration::from_secs(2))).expect("read timeout");
      let mut byte = [0u8; 1];
      assert!(
         matches!(peer.read(&mut byte), Ok(0)),
         "an un-handshaked client must be closed"
      );
      assert!(
         wait_until(Instant::now() + StdDuration::from_secs(2), || {
            shared.clients() == 0
         }),
         "an un-handshaked client must be closed"
      );
   }

   #[test]
   fn a_shed_client_stops_its_writer_thread() {
      let _serial = serial();
      // Another test's writer could still be alive here, so only the return to this
      // baseline is asserted, and the poll below waits for every writer to be gone.
      let baseline = threads_named(WRITER_PREFIX);

      let shared = shared();
      let (server, _client) = pair();

      // The same deterministic setup as `a_client_that_never_reads_cannot_stall_the_loop`:
      // fill this direction's socket buffer from the server end before the writer exists,
      // so the writer blocks on its first byte and is parked in `write_all`, not merely
      // holding a full queue.
      {
         let mut filler = server.try_clone().expect("fill the socket buffer");
         filler.set_nonblocking(true).expect("non-blocking");
         let chunk = [b'x'; READ_CHUNK];
         while filler.write(&chunk).is_ok() {}
         filler.set_nonblocking(false).expect("blocking again");
      }
      // The peer end is never read from here on.

      shared
         .register(&server, Admission::Foreign { max: MAX_CLIENTS })
         .expect("register the silent client");
      // The name is applied by the thread itself; a count taken before that would miss the
      // writer and let the test pass without ever observing a parked one, so confirm the
      // thread is visible before shedding it.
      assert!(
         wait_until(Instant::now() + StdDuration::from_secs(2), || {
            threads_named(WRITER_PREFIX).iter().any(|id| !baseline.contains(id))
         }),
         "the registered client's writer thread never appeared"
      );

      let status = status(Mode::Alert, 0);
      for _ in 0..CLIENT_QUEUE_FRAMES + 50 {
         shared.broadcast(&Response::Status(status.clone()));
      }
      assert_eq!(shared.clients(), 0, "a silent client is shed");

      // The writer is parked in a write that the socket timeout now bounds; it can only
      // disappear once that `write_all` returns and the thread runs off the end of its
      // loop, so this waits out `WRITE_TIMEOUT` plus scheduling slack.
      let deadline = Instant::now() + WRITE_TIMEOUT * 3;
      assert!(
         wait_until(deadline, || {
            threads_named(WRITER_PREFIX).iter().all(|id| baseline.contains(id))
         }),
         "a shed client's writer thread outlived WRITE_TIMEOUT: {:?} writer thread(s) still \
          alive, baseline {baseline:?}",
         threads_named(WRITER_PREFIX)
      );
   }

   #[test]
   fn the_client_registry_refuses_more_than_the_limit() {
      let _serial = serial();
      let shared = shared();
      // Hold every peer end so no writer sees EOF and no socket is dropped early.
      let mut peers = Vec::with_capacity(MAX_CLIENTS);
      for _ in 0..MAX_CLIENTS {
         let (server, peer) = pair();
         shared
            .register(&server, Admission::Foreign { max: MAX_CLIENTS })
            .expect("register within the limit");
         peers.push(peer);
      }
      assert_eq!(shared.clients(), MAX_CLIENTS);

      let (server, _peer) = pair();
      let err = shared
         .register(&server, Admission::Foreign { max: MAX_CLIENTS })
         .expect_err("the registry is full");
      assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
      assert!(
         err.to_string().contains(&MAX_CLIENTS.to_string()),
         "the refusal must name the limit, got: {err}"
      );
      assert_eq!(
         shared.clients(),
         MAX_CLIENTS,
         "a refused client must not be registered"
      );
   }

   #[test]
   fn the_configured_gui_is_admitted_when_foreign_clients_have_filled_the_registry() {
      let _serial = serial();
      let shared = shared();
      let foreign_max = MAX_CLIENTS - RESERVED_GUI_SLOTS;
      // Hold every peer end so no writer sees EOF and no socket is dropped early.
      let mut peers = Vec::with_capacity(foreign_max);
      for _ in 0..foreign_max {
         let (server, peer) = pair();
         shared
            .register(&server, Admission::Foreign { max: foreign_max })
            .expect("register within the foreign limit");
         peers.push(peer);
      }
      assert_eq!(shared.clients(), foreign_max);

      let (server, _peer) = pair();
      let err = shared
         .register(&server, Admission::Foreign { max: foreign_max })
         .expect_err("foreign clients are held below the reserved slots");
      assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);

      let (server, _peer) = pair();
      shared
         .register(&server, Admission::Gui)
         .expect("the reserved slot admits the configured GUI");
      assert_eq!(
         shared.clients(),
         foreign_max + 1,
         "the GUI takes one of the slots held back for it"
      );
   }

   #[test]
   fn a_reading_client_receives_frames_in_order() {
      let shared = shared();
      let (server, mut client) = pair();
      shared
         .register(&server, Admission::Foreign { max: MAX_CLIENTS })
         .expect("register the reading client");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");

      let reader = thread::spawn(move || {
         let mut buffered = Vec::new();
         let mut frames = Vec::new();
         for _ in 0..2 {
            frames.push(read_response(&mut client, &mut buffered));
         }
         frames
      });

      shared.broadcast(&Response::Error {
         message: "one".to_owned(),
      });
      shared.broadcast(&Response::Error {
         message: "two".to_owned(),
      });

      let frames = reader.join().expect("reader thread");
      assert_eq!(
         frames,
         vec![
            Response::Error {
               message: "one".to_owned()
            },
            Response::Error {
               message: "two".to_owned()
            },
         ],
         "frames must arrive complete and in the order they were broadcast"
      );
      assert_eq!(
         shared.clients(),
         1,
         "a client that keeps reading stays registered"
      );
   }

   #[test]
   fn the_handle_publishes_status_rules_and_mode() {
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

      {
         let state = shared.state.lock().expect("ipc state");
         assert_eq!(state.rules, vec![rule]);
         assert_eq!(state.status, Some(status(Mode::Alert, 1)));
      }

      let (server, mut client) = pair();
      let uid = our_uid().expect("our own uid");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, policy(Some(uid))));

      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      client
         .write_all(&encode_line(&Request::SetMode { mode: Mode::Silent }).expect("set mode"))
         .expect("send");

      // A non-root peer cannot turn enforcement off (`persistence_refusal`): the answer is an Error
      // naming the root path, and the published mode is untouched. The mode is published through the
      // handle, which the assertions above and `publishing_a_status_does_not_undo_a_newer_set_mode`
      // cover.
      let mut buffered = Vec::new();
      match read_response(&mut client, &mut buffered) {
         Response::Error { message } => assert!(
            message.contains("netshieldctl set-mode"),
            "the refusal must say how root makes the change, got: {message}"
         ),
         other => panic!("expected the SetMode refusal, got {other:?}"),
      }
      assert_eq!(
         handle.mode(),
         Mode::Alert,
         "a refused SetMode must not change the published mode"
      );

      drop(client);
      reader.join().expect("reader thread");
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
      let err = match IpcServer::bind(&path, Some(1000), None) {
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
      let reader = thread::spawn(move || serve(server, shared, policy(Some(uid))));

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
      let reader = thread::spawn(move || serve(server, shared, policy(Some(uid))));

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
      let reader = thread::spawn(move || serve(server, shared, policy(Some(uid))));

      client.write_all(&encode_line(&Request::Status).expect("status")).expect("send");
      let mut buffered = Vec::new();
      match read_response(&mut client, &mut buffered) {
         Response::Error { message } => assert!(message.contains("Hello")),
         other => panic!("expected Error, got {other:?}"),
      }
      reader.join().expect("reader thread");
   }

   #[test]
   fn a_decision_is_forwarded_to_the_daemon_loop() {
      let (server, mut client) = pair();
      let shared = shared();
      let probe = Arc::clone(&shared);
      let uid = our_uid().expect("our own uid");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, policy(Some(uid))));

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
      let reader = thread::spawn(move || serve(server, shared, policy(allowed)));

      // The server (correctly) closes an unauthorised peer before its Hello lands, so a
      // failed write here means it already closed us — exactly what this test asserts.
      if let Err(err) = client.write_all(&hello(PROTOCOL_VERSION)) {
         assert!(
            matches!(
               err.kind(),
               std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ),
            "the Hello write failed for a reason other than the server closing: {err}"
         );
      }
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

   #[test]
   fn a_non_gui_peer_may_read_but_not_mutate() {
      let (server, mut client) = pair();
      let shared = shared();
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      let rule = rule();
      handle.set_rules(std::slice::from_ref(&rule));
      handle.set_status(status(Mode::Alert, 1));

      let uid = our_uid().expect("our own uid");
      let gui = GuiPolicy {
         allowed_uid: Some(uid),
         gui_path: Some(PathBuf::from("/bin/definitely-not-the-gui")),
      };
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, gui));

      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      client
         .write_all(&encode_line(&Request::ListRules).expect("list rules"))
         .expect("send");
      client
         .write_all(&encode_line(&Request::SetMode { mode: Mode::Silent }).expect("set mode"))
         .expect("send");

      let mut buffered = Vec::new();
      assert_eq!(
         read_response(&mut client, &mut buffered),
         Response::Rules { rules: vec![rule] },
         "reads stay available to a non-GUI peer of the allowed uid"
      );
      match read_response(&mut client, &mut buffered) {
         Response::Error { message } => assert!(
            message.contains("GUI"),
            "the refusal must name the requirement, got: {message}"
         ),
         other => panic!("expected Error, got {other:?}"),
      }

      // A refusal closes the connection: a clean EOF or the RST the kernel sends when the
      // server closes a socket that still holds the client's unread bytes.
      let mut rest = Vec::new();
      match client.read_to_end(&mut rest) {
         Ok(0) => {}
         Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
         other => panic!("expected the peer to be closed, got {other:?}"),
      }
      assert_eq!(
         handle.mode(),
         Mode::Alert,
         "the refused SetMode must not reach the server state"
      );
      reader.join().expect("reader thread");
   }

   #[test]
   fn the_configured_gui_may_change_state() {
      let (server, mut client) = pair();
      let shared = shared();
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      let uid = our_uid().expect("our own uid");
      let gui = GuiPolicy {
         allowed_uid: Some(uid),
         gui_path: Some(self_exe()),
      };
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, gui));

      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      // A session-scoped rule is what a click may still make; the mode switch and a permanent rule
      // are root actions (`persistence_refusal`) and have their own tests.
      // A narrow Session rule: `rule()` is Any/Any, which `socket_rule_refusal` refuses, and a
      // permanent one is a root action. This is the shape a click may still produce.
      let session = Request::UpsertRule {
         rule: Rule {
            app: AppMatcher::Exe(std::path::PathBuf::from("/usr/bin/git")),
            dest: DestMatcher::Port(443),
            duration: Duration::Session,
            ..rule()
         },
      };
      client.write_all(&encode_line(&session).expect("upsert")).expect("send");

      let mut forwarded = false;
      for _ in 0..100 {
         if let Some((_, Request::UpsertRule { rule })) = handle.try_recv() {
            assert_eq!(rule.duration, Duration::Session);
            forwarded = true;
            break;
         }
         thread::sleep(StdDuration::from_millis(10));
      }
      assert!(
         forwarded,
         "the configured GUI's session rule must reach the daemon loop"
      );

      // The connection stayed open and no Error frame was queued: the next request is a
      // read that the same session must be able to serve.
      client
         .write_all(&encode_line(&Request::ListRules).expect("list rules"))
         .expect("send");
      let mut buffered = Vec::new();
      assert!(matches!(
         read_response(&mut client, &mut buffered),
         Response::Rules { .. }
      ));

      drop(client);
      reader.join().expect("reader thread");
   }

   #[test]
   fn without_a_gui_path_the_uid_rule_still_applies() {
      let (server, mut client) = pair();
      let shared = shared();
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      let uid = our_uid().expect("our own uid");
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, policy(Some(uid))));

      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      // A session-scoped rule is what a click may still make; the mode switch and a permanent rule
      // are root actions (`persistence_refusal`) and have their own tests.
      // A narrow Session rule: `rule()` is Any/Any, which `socket_rule_refusal` refuses, and a
      // permanent one is a root action. This is the shape a click may still produce.
      let session = Request::UpsertRule {
         rule: Rule {
            app: AppMatcher::Exe(std::path::PathBuf::from("/usr/bin/git")),
            dest: DestMatcher::Port(443),
            duration: Duration::Session,
            ..rule()
         },
      };
      client.write_all(&encode_line(&session).expect("upsert")).expect("send");

      let mut forwarded = false;
      for _ in 0..100 {
         if let Some((_, Request::UpsertRule { rule })) = handle.try_recv() {
            assert_eq!(rule.duration, Duration::Session);
            forwarded = true;
            break;
         }
         thread::sleep(StdDuration::from_millis(10));
      }
      assert!(
         forwarded,
         "without gui_path the allowed uid keeps the old write permission"
      );

      drop(client);
      reader.join().expect("reader thread");
   }

   #[test]
   fn a_global_rule_is_refused_even_from_the_gui() {
      let (server, mut client) = pair();
      let shared = shared();
      let handle = IpcHandle {
         shared: Arc::clone(&shared),
      };
      let uid = our_uid().expect("our own uid");
      let gui = GuiPolicy {
         allowed_uid: Some(uid),
         gui_path: Some(self_exe()),
      };
      client.set_read_timeout(Some(StdDuration::from_secs(5))).expect("read timeout");
      let reader = thread::spawn(move || serve(server, shared, gui));

      client.write_all(&hello(PROTOCOL_VERSION)).expect("hello");
      let mut broad = rule();
      broad.app = AppMatcher::Any;
      broad.dest = DestMatcher::Any;
      // A permanent rule would be refused by the persistence gate before this one; this test is
      // about `socket_rule_refusal`, so the rule is session-scoped.
      broad.duration = Duration::Session;
      client
         .write_all(&encode_line(&Request::UpsertRule { rule: broad }).expect("upsert"))
         .expect("send");

      let mut buffered = Vec::new();
      match read_response(&mut client, &mut buffered) {
         Response::Error { message } => assert!(
            message.contains("every application") && message.contains("every destination"),
            "the refusal must say what the rule may not express, got: {message}"
         ),
         other => panic!("expected Error, got {other:?}"),
      }
      assert!(
         handle.try_recv().is_none(),
         "a refused rule must never reach the daemon loop"
      );

      drop(client);
      reader.join().expect("reader thread");
   }

   #[test]
   fn a_traced_peer_may_not_change_policy() {
      let message = provenance_refusal(Some(4242), Some(&[]), Some(&[]), None)
         .expect("a traced peer must be refused");
      assert!(
         message.contains("4242") && message.contains("traced"),
         "the refusal must name the tracer, got: {message}"
      );
   }

   #[test]
   fn a_preloaded_peer_is_refused() {
      let environment = [b"DISPLAY=:0".to_vec(), b"LD_PRELOAD=/tmp/x.so".to_vec()];
      let message = provenance_refusal(Some(0), Some(&environment), Some(&[]), None)
         .expect("a preloaded peer must be refused");
      assert!(
         message.contains("LD_PRELOAD"),
         "the refusal must name the variable, got: {message}"
      );
   }

   #[test]
   fn a_vulkan_loader_variable_is_refused_too() {
      let environment = [b"VK_ICD_FILENAMES=/tmp/evil.json".to_vec()];
      let message = provenance_refusal(Some(0), Some(&environment), Some(&[]), None)
         .expect("a steered Vulkan loader must be refused");
      assert!(
         message.contains("VK_ICD_FILENAMES"),
         "the refusal must name the variable, got: {message}"
      );
   }

   #[test]
   fn an_ordinary_desktop_environment_is_allowed() {
      let environment = [
         b"DISPLAY=:0".to_vec(),
         b"WAYLAND_DISPLAY=wayland-0".to_vec(),
         b"HOME=/home/user".to_vec(),
         b"PATH=/usr/bin".to_vec(),
         b"LANG=en_GB.UTF-8".to_vec(),
         b"XDG_RUNTIME_DIR=/run/user/1000".to_vec(),
         b"LD_LIBRARY_PATH=/usr/lib".to_vec(),
      ];
      assert_eq!(
         provenance_refusal(
            Some(0),
            Some(&environment),
            Some(&[]),
            Some(Path::new("/usr/local/bin/netshield-gui")),
         ),
         None,
         "LD_LIBRARY_PATH is ordinary build tooling, not a loader injection"
      );
   }

   #[test]
   fn a_code_mapping_from_a_writable_directory_is_refused() {
      let mappings = [ExecutableMapping {
         path: "/tmp/evil/libX11.so.6".into(),
         writable_directory: true,
      }];
      let message = provenance_refusal(
         Some(0),
         Some(&[]),
         Some(&mappings),
         Some(Path::new("/usr/local/bin/netshield-gui")),
      )
      .expect("code from a plantable directory must be refused");
      assert!(
         message.contains("/tmp/evil/libX11.so.6"),
         "the refusal must name the mapping, got: {message}"
      );
   }

   #[test]
   fn the_peer_s_own_executable_may_come_from_a_writable_directory() {
      let mappings = [ExecutableMapping {
         path: "/home/u/netshield/target/debug/netshield-gui".into(),
         writable_directory: true,
      }];
      assert_eq!(
         provenance_refusal(
            Some(0),
            Some(&[]),
            Some(&mappings),
            Some(Path::new(
               "/home/u/netshield/target/debug/netshield-gui"
            )),
         ),
         None,
         "a development build under target/ is the peer's own executable"
      );
   }

   #[test]
   fn the_mode_switch_needs_root() {
      let refusal = persistence_refusal(
         1000,
         &Request::SetMode { mode: Mode::Silent },
         &[],
      )
      .expect("a desktop peer must not turn enforcement off");
      assert!(
         refusal.contains("netshieldctl set-mode"),
         "the refusal must name the command, got: {refusal}"
      );
   }

   #[test]
   fn a_permanent_rule_from_a_desktop_peer_is_refused() {
      let permanent = rule();
      let refusal = persistence_refusal(
         1000,
         &Request::UpsertRule { rule: permanent },
         &[],
      )
      .expect("a desktop peer must not make a rule permanent");
      assert!(
         refusal.contains("permanent"),
         "the refusal must say the rule is permanent, got: {refusal}"
      );
   }

   #[test]
   fn a_permanent_decision_from_a_desktop_peer_is_allowed() {
      let decide = Request::Decide(DecideRequest {
         prompt_id: 9,
         action: Action::Allow,
         duration: Duration::Forever,
         scope: ScopeChoice::AnyConnection,
      });
      assert_eq!(
         persistence_refusal(1000, &decide, &[]),
         None,
         "a permanent answer at a prompt is the user's decision, not a socket client's"
      );
   }

   #[test]
   fn a_session_rule_from_a_desktop_peer_is_allowed() {
      let session = Rule {
         duration: Duration::Session,
         ..rule()
      };
      assert_eq!(
         persistence_refusal(1000, &Request::UpsertRule { rule: session }, &[]),
         None,
         "a rule that dies with the session stays clickable"
      );
   }

   #[test]
   fn an_edit_that_keeps_an_existing_permanent_rule_is_allowed() {
      let stored = rule();
      let edited = Rule {
         note: Some("edited".to_owned()),
         ..stored.clone()
      };
      assert_eq!(
         persistence_refusal(
            1000,
            &Request::UpsertRule { rule: edited },
            &[stored]
         ),
         None,
         "editing the note of a permanent rule keeps it permanent"
      );
   }

   #[test]
   fn an_edit_that_widens_an_existing_permanent_rule_needs_root() {
      let stored = Rule {
         dest: DestMatcher::Port(443),
         ..rule()
      };
      let widened = Rule {
         dest: DestMatcher::Any,
         ..stored.clone()
      };
      assert!(
         persistence_refusal(
            1000,
            &Request::UpsertRule { rule: widened },
            &[stored]
         )
         .is_some(),
         "widening a permanent rule changes what outlives the session"
      );
   }

   #[test]
   fn deleting_a_rule_the_snapshot_does_not_carry_is_refused() {
      let refusal = persistence_refusal(
         1000,
         &Request::DeleteRule {
            id: RuleId::new_unique(),
         },
         &[],
      )
      .expect("a delete the snapshot cannot judge must be refused, not applied ungated");
      assert!(
         refusal.contains("published rule set"),
         "the refusal must say the snapshot is behind, got: {refusal}"
      );
   }

   #[test]
   fn switching_a_rule_the_snapshot_does_not_carry_is_refused() {
      let refusal = persistence_refusal(
         1000,
         &Request::SetRuleEnabled {
            id: RuleId::new_unique(),
            enabled: false,
         },
         &[],
      )
      .expect("a switch the snapshot cannot judge must be refused, not applied ungated");
      assert!(
         refusal.contains("published rule set"),
         "the refusal must say the snapshot is behind, got: {refusal}"
      );
   }

   #[test]
   fn re_enabling_a_disabled_permanent_rule_by_editing_it_needs_root() {
      let stored = Rule {
         enabled: false,
         ..rule()
      };
      let re_enabled = Rule {
         enabled: true,
         ..stored.clone()
      };
      let refusal = persistence_refusal(
         1000,
         &Request::UpsertRule { rule: re_enabled },
         std::slice::from_ref(&stored),
      )
      .expect("switching a disabled permanent rule on by editing it is the same grant");
      assert!(
         refusal.contains("permanent"),
         "the refusal must say the rule is permanent, got: {refusal}"
      );
      assert_eq!(
         persistence_refusal(
            1000,
            &Request::UpsertRule {
               rule: stored.clone()
            },
            std::slice::from_ref(&stored)
         ),
         None,
         "an edit that leaves a disabled permanent rule off is not a grant"
      );
   }

   #[test]
   fn deleting_a_deny_rule_needs_root() {
      let deny = Rule {
         action: Action::Deny,
         ..rule()
      };
      let refusal = persistence_refusal(
         1000,
         &Request::DeleteRule {
            id: deny.id.clone(),
         },
         &[deny],
      )
      .expect("a desktop peer must not withdraw a denial");
      assert!(
         refusal.contains("withdrawing a denial"),
         "the refusal must say what is being withdrawn, got: {refusal}"
      );
   }

   #[test]
   fn deleting_an_allow_rule_is_not_a_grant() {
      let allow = Rule {
         action: Action::Allow,
         ..rule()
      };
      assert_eq!(
         persistence_refusal(
            1000,
            &Request::DeleteRule {
               id: allow.id.clone()
            },
            &[allow],
         ),
         None,
         "deleting an allow only narrows what is permitted"
      );
   }

   #[test]
   fn withdrawing_a_denial_by_switching_it_off_needs_root() {
      let deny = Rule {
         action: Action::Deny,
         enabled: true,
         ..rule()
      };
      let refusal = persistence_refusal(
         1000,
         &Request::SetRuleEnabled {
            id: deny.id.clone(),
            enabled: false,
         },
         &[deny],
      )
      .expect("a desktop peer must not withdraw a denial by switching it off");
      assert!(
         refusal.contains("netshieldctl disable"),
         "the refusal must name the command, got: {refusal}"
      );
   }

   #[test]
   fn switching_an_allow_off_only_narrows() {
      let allow = Rule {
         action: Action::Allow,
         enabled: true,
         ..rule()
      };
      assert_eq!(
         persistence_refusal(
            1000,
            &Request::SetRuleEnabled {
               id: allow.id.clone(),
               enabled: false,
            },
            &[allow],
         ),
         None,
         "switching an allow off only narrows what is permitted"
      );
   }

   #[test]
   fn switching_an_allow_back_on_needs_root() {
      let allow = Rule {
         action: Action::Allow,
         enabled: false,
         ..rule()
      };
      let refusal = persistence_refusal(
         1000,
         &Request::SetRuleEnabled {
            id: allow.id.clone(),
            enabled: true,
         },
         &[allow],
      )
      .expect("a desktop peer must not re-grant an allow by switching it back on");
      assert!(
         refusal.contains("netshieldctl enable"),
         "the refusal must name the command, got: {refusal}"
      );
   }

   #[test]
   fn root_may_do_all_of_it() {
      let stored = Rule {
         action: Action::Deny,
         ..rule()
      };
      let permanent = Rule {
         duration: Duration::Forever,
         ..stored.clone()
      };
      assert_eq!(
         persistence_refusal(0, &Request::SetMode { mode: Mode::Silent }, &[]),
         None,
         "root may switch the mode"
      );
      assert_eq!(
         persistence_refusal(0, &Request::UpsertRule { rule: permanent }, &[]),
         None,
         "root may make a rule permanent"
      );
      assert_eq!(
         persistence_refusal(
            0,
            &Request::DeleteRule {
               id: stored.id.clone()
            },
            &[stored],
         ),
         None,
         "root may withdraw a denial"
      );
   }
}
