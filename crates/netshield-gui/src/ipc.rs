//! The GUI's half of the daemon protocol: one socket thread, a queue and a drain.
//!
//! `send` writes a frame straight to the socket, from whichever thread produced it, and
//! `poll` only drains. All reading sits on a connection thread that retries a missing daemon
//! instead of handing the UI an error to handle.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use netshield_core::ipc::{
   ClientKind, ConnectionEvent, MAX_FRAME_LEN, PROTOCOL_VERSION, PromptRequest, Request, Response,
   decode_line, encode_line,
};

/// How long one request write may block. Only a daemon that stopped reading fills the socket
/// buffer; a frame that cannot be written in this long is dropped and logged.
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);

/// How many frames wait for a socket that is not connected yet. The app's startup burst is
/// three (`subscribe`, `status`, `listrules`); anything older is dropped once this is full,
/// because a request that lost its connection is worth less than the newest one.
const PENDING_CAP: usize = 64;

/// How long to wait before redialling a daemon that is not running.
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Wakes the UI thread after an event has been queued.
///
/// A minimised window paints no frames and gets no input, so queueing alone leaves the
/// event unread until the user restores it; the wake is what schedules the frame that
/// drains the queue. A callback rather than an `egui::Context` keeps this module free of
/// the UI toolkit, and lets a test observe the wake with a counter.
pub type Waker = Arc<dyn Fn() + Send + Sync>;

/// Called from the socket thread as soon as a prompt is decoded, before the UI is woken.
pub type PromptHook = Arc<dyn Fn(&PromptRequest) + Send + Sync>;

/// Called from the socket thread for every decided flow, attended or not.
///
/// The app applies these to the shared connection log here instead of queueing them for a
/// frame. A window nobody is looking at paints nothing, and a queue would let one chatty
/// process evict a quiet one's history before the window came back: the log's per-application
/// rings are the retention policy, so they have to see every event.
pub type ConnectionSink = Arc<dyn Fn(&ConnectionEvent) + Send + Sync>;

/// What the connection thread tells the UI.
#[derive(Debug)]
pub enum IpcEvent {
   /// The connection opened or dropped; while false the thread keeps retrying.
   Connected(bool),
   /// One decoded daemon frame.
   Message(Box<Response>),
}

/// How many events the socket thread keeps for a window nobody is looking at.
///
/// Only prompt closures pile up here, one per prompt id, and a snapshot of one kind replaces its
/// predecessor. Connections are not queued at all: they go straight into the shared log, whose
/// per-application rings are what keep or drop them (`ConnectionSink`).
const HIDDEN_BACKLOG: usize = 512;

/// What a kept event collapses on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
   /// Rows also pile up: only the id matters, and each is a different prompt.
   PromptClosed,
   Status,
   Rules,
   Connected,
   /// Must reach the UI at once; never kept.
   Prompt,
   Other,
}

/// The identity of one event, for the backlog's replace-or-queue decision.
fn kind(event: &IpcEvent) -> Kind {
   match event {
      IpcEvent::Connected(_) => Kind::Connected,
      IpcEvent::Message(response) => match &**response {
         Response::PromptClosed { .. } => Kind::PromptClosed,
         Response::Status(_) => Kind::Status,
         Response::Rules { .. } => Kind::Rules,
         Response::Prompt(_) => Kind::Prompt,
         _ => Kind::Other,
      },
   }
}

/// Whether the root window is on screen, and what arrived while it was not.
///
/// eframe 0.37 runs a full ui pass and paints on every repaint request even for an
/// iconified or withdrawn window, so a wake while nobody is looking costs a whole frame
/// (~0.4 ms measured). The socket thread therefore keeps routine events here instead of
/// waking the UI, and the app installs them the moment the window is back. A prompt
/// never waits: the alert is its own window and has to be raised at once.
struct Attend {
   attended: AtomicBool,
   backlog: Mutex<VecDeque<IpcEvent>>,
   dropped: AtomicU64,
}

impl Attend {
   /// A window that starts attended: the first frame is always painted.
   fn new() -> Self {
      Self {
         attended: AtomicBool::new(true),
         backlog: Mutex::new(VecDeque::new()),
         dropped: AtomicU64::new(0),
      }
   }

   fn is_attended(&self) -> bool {
      self.attended.load(Ordering::Relaxed)
   }

   fn set(&self, attended: bool) {
      self.attended.store(attended, Ordering::Relaxed);
   }

   /// Keeps one event for later. A poisoned lock is recovered: the queue stays sound.
   fn stash(&self, event: IpcEvent) {
      let mut backlog = self.backlog.lock().unwrap_or_else(PoisonError::into_inner);
      let new_kind = kind(&event);
      if new_kind == Kind::PromptClosed {
         if backlog.len() >= HIDDEN_BACKLOG && backlog.pop_front().is_some() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
         }
      } else {
         backlog.retain(|queued| kind(queued) != new_kind);
      }
      backlog.push_back(event);
   }

   /// Everything kept so far, oldest first, plus how many older events the cap dropped.
   fn take(&self) -> (Vec<IpcEvent>, u64) {
      let mut backlog = self.backlog.lock().unwrap_or_else(PoisonError::into_inner);
      let events = backlog.drain(..).collect();
      (events, self.dropped.swap(0, Ordering::Relaxed))
   }
}

/// Delivers one event to the UI, or keeps it while nobody is looking.
///
/// `false` means the UI dropped the client; the thread then stops.
fn deliver(events: &Sender<IpcEvent>, waker: &Waker, attend: &Attend, event: IpcEvent) -> bool {
   if attend.is_attended() || kind(&event) == Kind::Prompt {
      return send_event(events, waker, event);
   }
   attend.stash(event);
   true
}

/// A non-blocking handle to the daemon socket.
pub struct IpcClient {
   writer: Writer,
   events: Receiver<IpcEvent>,
   on_prompt: PromptHook,
   /// Shared with the socket thread: whether the root window is on screen.
   attend: Arc<Attend>,
}

/// Frames written to the daemon socket, from any thread.
///
/// The socket thread publishes its connected socket here after the handshake, so a request
/// goes out the moment it is sent instead of waiting for a read to time out and forward it.
/// A frame sent while there is no socket -- the app's startup burst, or anything sent while
/// the daemon is being redialled -- waits in `pending` and is flushed as soon as the thread
/// has one.
#[derive(Clone)]
pub struct Writer {
   shared: Arc<Mutex<WriterState>>,
}

struct WriterState {
   /// The connected socket, cloned from the connection thread's.
   socket: Option<UnixStream>,
   /// Frames accepted while there was no socket to write them to.
   pending: VecDeque<String>,
}

impl Writer {
   /// A writer with no socket: frames queue and are dropped once the cap is reached.
   ///
   /// This is `--mock`'s sink. `send` must keep succeeding there -- a prompt answer with no
   /// daemon is discarded by design, not because the transport died.
   pub fn silent() -> Self {
      Self::new()
   }

   fn new() -> Self {
      Self {
         shared: Arc::new(Mutex::new(WriterState {
            socket: None,
            pending: VecDeque::new(),
         })),
      }
   }

   /// Encodes one request and writes it, or queues it until there is a socket.
   ///
   /// `false` means the request never left: it could not be encoded, or the socket rejected
   /// the write. A frame that merely queues returns `true`, exactly as the channel-backed
   /// queue did.
   pub fn send(&self, request: &Request) -> bool {
      let Some(line) = frame(request) else {
         log::debug!("cannot encode an ipc request");
         return false;
      };
      let mut state = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
      match state.socket.as_mut() {
         Some(socket) => match socket.write_all(line.as_bytes()) {
            Ok(()) => true,
            Err(err) => {
               log::debug!("cannot send an ipc request: {err}");
               // The reader hits the same dead socket; frames queue until it reconnects.
               state.socket = None;
               false
            }
         },
         None => {
            if state.pending.len() >= PENDING_CAP && state.pending.pop_front().is_some() {
               log::debug!("dropping an ipc request queued while the daemon was away");
            }
            state.pending.push_back(line);
            true
         }
      }
   }

   /// Publishes a connected socket and flushes everything queued while there was none.
   ///
   /// The hello is already on the wire when this is called: the daemon refuses a client that
   /// does not announce itself first, and every flushed frame has to follow it.
   fn attach(&self, mut socket: UnixStream) {
      let mut state = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
      while let Some(line) = state.pending.pop_front() {
         if let Err(err) = socket.write_all(line.as_bytes()) {
            log::debug!("cannot send a queued ipc request: {err}");
            return;
         }
      }
      state.socket = Some(socket);
   }

   /// Forgets the socket, so later frames queue instead of failing against a dead fd.
   fn detach(&self) {
      self.shared.lock().unwrap_or_else(PoisonError::into_inner).socket = None;
   }
}

/// A send handle for code that runs outside the main window's frames (the alert viewport's
/// own callback, which keeps painting while the main window is minimised).
pub type Decider = Writer;

impl IpcClient {
   /// Spawns the connection thread. Never blocks and never fails: connection errors
   /// surface as [`IpcEvent::Connected(false)`] and the thread keeps retrying.
   ///
   /// Every queued event is followed by a `waker` call, because a hidden or minimised
   /// root window schedules no frame on its own and would otherwise not drain the queue.
   pub fn spawn(
      socket_path: PathBuf,
      waker: Waker,
      on_prompt: PromptHook,
      on_connection: ConnectionSink,
   ) -> Self {
      let writer = Writer::new();
      let (events, events_rx) = mpsc::channel();
      let attend = Arc::new(Attend::new());
      let thread_events = events.clone();
      let thread_waker = Arc::clone(&waker);
      let thread_prompt = Arc::clone(&on_prompt);
      let thread_connection = Arc::clone(&on_connection);
      let thread_attend = Arc::clone(&attend);
      let thread_writer = writer.clone();
      let spawned = thread::Builder::new().name("netshield-ipc".to_owned()).spawn(move || {
         run(
            &socket_path,
            &thread_writer,
            &thread_events,
            &thread_waker,
            &thread_prompt,
            &thread_connection,
            &thread_attend,
         )
      });
      if let Err(err) = spawned {
         log::warn!("cannot start the ipc thread: {err}");
         waker();
         let _ = events.send(IpcEvent::Connected(false));
      }
      Self {
         writer,
         events: events_rx,
         on_prompt,
         attend,
      }
   }

   /// Tells the socket thread whether the root window is on screen.
   pub fn attend(&self, attended: bool) {
      self.attend.set(attended);
   }

   /// Everything the daemon sent while the window was not on screen, oldest first, with
   /// the number of older events the backlog's cap dropped.
   pub fn take_backlog(&self) -> (Vec<IpcEvent>, u64) {
      self.attend.take()
   }

   /// Encodes and writes a request. Returns false if it could not leave the process.
   pub fn send(&self, request: &Request) -> bool {
      self.writer.send(request)
   }

   /// Non-blocking drain for the UI: returns None when there is nothing new.
   pub fn poll(&self) -> Option<IpcEvent> {
      self.events.try_recv().ok()
   }

   /// A cloneable send handle for callbacks that outlive one `App::update` call.
   pub fn decider(&self) -> Decider {
      self.writer.clone()
   }
}

/// What the connection thread does next after one step of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
   Continue,
   /// The socket is unusable; report the drop and dial again.
   Reconnect,
   /// The UI dropped the client; stop the thread.
   Stop,
}

/// Encodes one request into the single line the protocol expects.
fn frame(request: &Request) -> Option<String> {
   String::from_utf8(encode_line(request).ok()?).ok()
}

/// Queues one event and then wakes the UI; false means the UI dropped the client.
///
/// The wake follows the send so the frame it schedules can already see the event; a wake
/// before the send would race a UI that drains the empty channel and then sleeps again.
fn send_event(events: &Sender<IpcEvent>, waker: &Waker, event: IpcEvent) -> bool {
   if events.send(event).is_err() {
      return false;
   }
   waker();
   true
}

/// Owns the socket: dial, handshake, serve one connection, then retry forever.
fn run(
   path: &Path,
   writer: &Writer,
   events: &Sender<IpcEvent>,
   waker: &Waker,
   on_prompt: &PromptHook,
   on_connection: &ConnectionSink,
   attend: &Attend,
) {
   // A missing daemon is normal, so the path is named on the first failure only.
   let mut reported_path = false;
   loop {
      match UnixStream::connect(path) {
         Ok(stream) => {
            if !deliver(events, waker, attend, IpcEvent::Connected(true)) {
               return;
            }
            let flow = converse(
               stream,
               writer,
               events,
               waker,
               on_prompt,
               on_connection,
               attend,
            );
            writer.detach();
            if flow == Flow::Stop {
               return;
            }
         }
         Err(err) if reported_path => log::debug!("cannot connect to the daemon: {err}"),
         Err(err) => {
            log::debug!(
               "cannot connect to the daemon at {}: {err}",
               path.display()
            );
            reported_path = true;
         }
      }
      if !deliver(events, waker, attend, IpcEvent::Connected(false)) {
         return;
      }
      thread::sleep(RETRY_DELAY);
   }
}

/// Serves one connection until it drops or the UI goes away.
///
/// The read blocks without a timeout: requests are written by [`Writer::send`] on the thread
/// that produced them, so nothing has to wake this loop to forward a queue.
fn converse(
   stream: UnixStream,
   writer: &Writer,
   events: &Sender<IpcEvent>,
   waker: &Waker,
   on_prompt: &PromptHook,
   on_connection: &ConnectionSink,
   attend: &Attend,
) -> Flow {
   let mut out = match stream.try_clone() {
      Ok(out) => out,
      Err(err) => {
         log::debug!("cannot clone the ipc socket: {err}");
         return Flow::Reconnect;
      }
   };
   if let Err(err) = out.set_write_timeout(Some(WRITE_TIMEOUT)) {
      log::debug!("cannot set the ipc write timeout: {err}");
      return Flow::Reconnect;
   }
   let hello = Request::Hello {
      version: PROTOCOL_VERSION,
      client: ClientKind::Gui,
   };
   let Some(line) = frame(&hello) else {
      return Flow::Reconnect;
   };
   if let Err(err) = out.write_all(line.as_bytes()) {
      log::debug!("cannot send the ipc hello: {err}");
      return Flow::Reconnect;
   }
   // Everything queued while there was no socket follows the hello, then senders write here.
   writer.attach(out);

   let mut buf = Vec::new();
   let mut reader = BufReader::new(stream);
   loop {
      let budget = (MAX_FRAME_LEN + 1 - buf.len()) as u64;
      match reader.by_ref().take(budget).read_until(b'\n', &mut buf) {
         Ok(0) => return Flow::Reconnect,
         Ok(_) => {}
         Err(err) => {
            log::debug!("ipc read failed: {err}");
            return Flow::Reconnect;
         }
      }
      if buf.len() > MAX_FRAME_LEN {
         log::debug!("the daemon sent a frame over {MAX_FRAME_LEN} bytes; reconnecting");
         return Flow::Reconnect;
      }
      if buf.last() == Some(&b'\n') {
         let flow = dispatch(
            &buf,
            events,
            waker,
            on_prompt,
            on_connection,
            attend,
         );
         buf.clear();
         if flow != Flow::Continue {
            return flow;
         }
      }
   }
}

/// Decodes one frame and hands it to the UI; a malformed frame is dropped, not fatal.
fn dispatch(
   frame: &[u8],
   events: &Sender<IpcEvent>,
   waker: &Waker,
   on_prompt: &PromptHook,
   on_connection: &ConnectionSink,
   attend: &Attend,
) -> Flow {
   let body = frame.strip_suffix(b"\n").unwrap_or(frame);
   if body.iter().all(u8::is_ascii_whitespace) {
      return Flow::Continue;
   }
   match decode_line::<Response>(body) {
      Ok(response) => {
         match &response {
            Response::Prompt(prompt) => {
               log::info!(
                  "prompt {} received for {} -> {} ({})",
                  prompt.id,
                  prompt.connection.app_name,
                  prompt.connection.domain.as_deref().unwrap_or("?"),
                  prompt.connection.remote_ip
               );
               on_prompt(prompt);
            }
            Response::Connection(event) => {
               // Applied on this thread: the log owns the retention policy. Only a window that
               // is on screen needs the frame the wake schedules.
               on_connection(event);
               if attend.is_attended() {
                  waker();
               }
               return Flow::Continue;
            }
            _ => {}
         }
         let event = IpcEvent::Message(Box::new(response));
         if deliver(events, waker, attend, event) {
            Flow::Continue
         } else {
            Flow::Stop
         }
      }
      Err(err) => {
         log::debug!("ignoring an undecodable ipc frame: {err}");
         Flow::Continue
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::connlog::ConnectionLog;
   use netshield_core::connection::{Family, L4Proto};
   use netshield_core::ipc::{ConnectionEvent, ConnectionView, Mode, Resolution, StatusInfo};
   use std::fs;
   use std::net::{IpAddr, Ipv4Addr};
   use std::os::unix::net::UnixListener;
   use std::sync::atomic::{AtomicUsize, Ordering};
   use std::sync::{Arc, Mutex};
   use std::time::Instant;

   const WAIT: Duration = Duration::from_secs(5);

   /// A waker that counts its calls, so a test can tell a wake from a silent idle.
   fn counted() -> (Waker, Arc<AtomicUsize>) {
      let count = Arc::new(AtomicUsize::new(0));
      let woken = Arc::clone(&count);
      let waker: Waker = Arc::new(move || {
         woken.fetch_add(1, Ordering::SeqCst);
      });
      (waker, count)
   }

   /// A socket path no parallel test can collide on; the file is removed by each test.
   fn socket_path(label: &str) -> PathBuf {
      static COUNTER: AtomicUsize = AtomicUsize::new(0);
      let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
      std::env::temp_dir().join(format!(
         "netshield-gui-ipc-{}-{serial}-{label}.sock",
         std::process::id()
      ))
   }

   fn prompt(id: u64) -> Response {
      Response::Prompt(PromptRequest {
         id,
         connection: ConnectionView {
            app_name: "firefox".to_owned(),
            exe: None,
            pid: Some(4242),
            uid: Some(1000),
            family: Family::V4,
            proto: L4Proto::Tcp,
            remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            remote_port: 443,
            local_port: 51_000,
            domain: None,
            domain_candidates: Vec::new(),
         },
         timeout_secs: 30,
         dests: Vec::new(),
         domain_scope_available: false,
         pending: 0,
      })
   }

   fn hello() -> Response {
      Response::Hello {
         version: PROTOCOL_VERSION,
         daemon_pid: 7,
         mode: Mode::Alert,
         rule_count: 2,
      }
   }

   /// A connection event for one named application, on a distinct port.
   fn connection_for(app: &str, port: u16) -> Response {
      Response::Connection(ConnectionEvent {
         at: 1_700_000_000,
         connection: ConnectionView {
            app_name: app.to_owned(),
            exe: None,
            pid: Some(4242),
            uid: Some(1000),
            family: Family::V4,
            proto: L4Proto::Tcp,
            remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            remote_port: port,
            local_port: 51_000,
            domain: None,
            domain_candidates: Vec::new(),
         },
         allowed: true,
         matched_rule: None,
         via_prompt: false,
      })
   }

   /// A sink that records every event it is handed, so a test can see what the log received.
   fn recording_sink() -> (ConnectionSink, Arc<Mutex<Vec<ConnectionEvent>>>) {
      let seen: Arc<Mutex<Vec<ConnectionEvent>>> = Arc::new(Mutex::new(Vec::new()));
      let recording = Arc::clone(&seen);
      let sink: ConnectionSink = Arc::new(move |event: &ConnectionEvent| {
         recording.lock().expect("record the connection").push(event.clone());
      });
      (sink, seen)
   }

   /// The client most tests need: no prompt handling and no connection sink.
   fn spawn_plain(path: PathBuf, waker: Waker) -> IpcClient {
      IpcClient::spawn(path, waker, Arc::new(|_| {}), Arc::new(|_| {}))
   }

   /// A prompt closure event; `id` is what the backlog keeps or drops.
   fn closed(id: u64) -> Response {
      Response::PromptClosed {
         id,
         resolution: Resolution::SilentAutoAllowed,
      }
   }

   fn status(rule_count: usize) -> Response {
      Response::Status(StatusInfo {
         daemon_pid: 7,
         mode: Mode::Alert,
         rule_count,
         pending_prompts: 0,
         queue_num: 0,
         queue_drops: 0,
         table_verified: true,
         mutation_gated: true,
         started_at: 1_700_000_000,
      })
   }

   /// Polls until an event matches; the deadline keeps a wedged client from hanging a test.
   fn wait_for(client: &IpcClient, wanted: impl Fn(&IpcEvent) -> bool) -> Option<IpcEvent> {
      let deadline = Instant::now() + WAIT;
      while Instant::now() < deadline {
         if let Some(event) = client.poll()
            && wanted(&event)
         {
            return Some(event);
         }
         thread::sleep(Duration::from_millis(20));
      }
      None
   }

   fn wait_connected(client: &IpcClient, up: bool) {
      let seen = wait_for(
         client,
         |event| matches!(event, IpcEvent::Connected(state) if *state == up),
      );
      assert!(
         seen.is_some(),
         "no Connected({up}) within {WAIT:?}"
      );
   }

   /// Accepts the client and asserts its first line is the GUI handshake.
   fn accept_hello(listener: &UnixListener) -> (BufReader<UnixStream>, UnixStream) {
      let (stream, _) = listener.accept().expect("accept the client");
      let writer = stream.try_clone().expect("clone the socket");
      let mut reader = BufReader::new(stream);
      let mut line = String::new();
      reader.read_line(&mut line).expect("read the hello");
      assert_eq!(
         decode_line::<Request>(line.as_bytes()).expect("decodable hello"),
         Request::Hello {
            version: PROTOCOL_VERSION,
            client: ClientKind::Gui,
         }
      );
      (reader, writer)
   }

   /// Waits for the next daemon frame, skipping connection-state events.
   fn next_message(client: &IpcClient) -> Response {
      match wait_for(client, |event| {
         matches!(event, IpcEvent::Message(_))
      }) {
         Some(IpcEvent::Message(response)) => *response,
         other => panic!("expected a daemon message, got {other:?}"),
      }
   }

   #[test]
   fn the_handshake_and_the_outbound_queue() {
      let path = socket_path("handshake");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, _woken) = counted();
      let client = spawn_plain(path.clone(), waker);
      let (mut reader, mut writer) = accept_hello(&listener);

      let hello = hello();
      writer
         .write_all(&encode_line(&hello).expect("encode the hello"))
         .expect("write the hello");

      wait_connected(&client, true);
      assert_eq!(next_message(&client), hello);

      // A queued request reaches the daemon, encoded as the protocol's own frame.
      assert!(client.send(&Request::Status));
      let mut line = String::new();
      reader.read_line(&mut line).expect("read the status");
      assert_eq!(
         decode_line::<Request>(line.as_bytes()).expect("decodable status"),
         Request::Status
      );

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn retries_until_the_daemon_appears() {
      let path = socket_path("retry");
      let (waker, _woken) = counted();
      let client = spawn_plain(path.clone(), waker);

      wait_connected(&client, false);

      let listener = UnixListener::bind(&path).expect("bind the listener");
      wait_connected(&client, true);

      drop(listener);
      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn ignores_a_bad_frame_and_keeps_reading() {
      let path = socket_path("bad-frame");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, _woken) = counted();
      let client = spawn_plain(path.clone(), waker);
      let (_reader, mut writer) = accept_hello(&listener);

      writer.write_all(b"not json\n").expect("write the garbage");
      let hello = hello();
      writer
         .write_all(&encode_line(&hello).expect("encode the hello"))
         .expect("write the hello");

      assert_eq!(next_message(&client), hello);

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn the_waker_and_the_prompt_hook_order() {
      let path = socket_path("wake");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, woken) = counted();
      // The hook snapshots the wake count as it fires: equal to the count from before the
      // prompt means the alert model is fed before any frame can drain the queue.
      let seen = Arc::new(Mutex::new(Vec::new()));
      let at_hook = Arc::new(AtomicUsize::new(0));
      let recorded = Arc::clone(&seen);
      let when = Arc::clone(&at_hook);
      let count = Arc::clone(&woken);
      let hook: PromptHook = Arc::new(move |prompt: &PromptRequest| {
         when.store(count.load(Ordering::SeqCst), Ordering::SeqCst);
         recorded.lock().expect("lock the hook").push(prompt.id);
      });
      let client = IpcClient::spawn(path.clone(), waker, hook, Arc::new(|_| {}));
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      // Connected(true) is the only wake so far; a quiet socket must add none, or the
      // thread would spin the UI for the whole session.
      let settled = woken.load(Ordering::SeqCst);
      thread::sleep(Duration::from_millis(300));
      assert_eq!(
         woken.load(Ordering::SeqCst),
         settled,
         "an idle connection must not keep waking the ui"
      );

      let wakes = woken.load(Ordering::SeqCst);
      let frame = prompt(1);
      writer
         .write_all(&encode_line(&frame).expect("encode the prompt"))
         .expect("write the prompt");

      assert_eq!(next_message(&client), frame);
      assert_eq!(*seen.lock().expect("lock the hook"), vec![1]);
      // The hook must run before the wake that publishes the prompt: the wake must cover the
      // message itself, not only the connection event that preceded it. A minimised window
      // has no other way to learn a prompt arrived.
      assert_eq!(
         at_hook.load(Ordering::SeqCst),
         wakes,
         "the hook must run before the wake that publishes the prompt"
      );
      assert!(
         woken.load(Ordering::SeqCst) > wakes,
         "a prompt must wake the ui"
      );

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn a_connection_is_applied_while_nobody_is_looking() {
      let path = socket_path("hidden-sink");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, woken) = counted();
      let (sink, seen) = recording_sink();
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}), sink);
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      client.attend(false);
      let wakes = woken.load(Ordering::SeqCst);
      for port in 1..=3 {
         let frame = connection_for("brave-browser", port);
         writer
            .write_all(&encode_line(&frame).expect("encode the connection"))
            .expect("write the connection");
      }

      let deadline = Instant::now() + WAIT;
      while Instant::now() < deadline && seen.lock().expect("read the sink").len() < 3 {
         thread::sleep(Duration::from_millis(20));
      }

      let ports: Vec<u16> = seen
         .lock()
         .expect("read the sink")
         .iter()
         .map(|event| event.connection.remote_port)
         .collect();
      assert_eq!(
         ports,
         vec![1, 2, 3],
         "every flow must reach the log"
      );
      assert_eq!(
         woken.load(Ordering::SeqCst),
         wakes,
         "an unattended window must not be woken by routine traffic"
      );
      assert!(
         client.poll().is_none(),
         "a connection must not travel through the event queue"
      );
      let (kept, dropped) = client.take_backlog();
      assert!(
         kept.is_empty(),
         "the backlog keeps no connections: the log is the queue"
      );
      assert_eq!(dropped, 0);

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn a_prompt_wakes_an_unattended_window() {
      let path = socket_path("hidden-prompt");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, woken) = counted();
      let client = spawn_plain(path.clone(), waker);
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      client.attend(false);
      let wakes = woken.load(Ordering::SeqCst);
      let frame = prompt(9);
      writer
         .write_all(&encode_line(&frame).expect("encode the prompt"))
         .expect("write the prompt");

      let seen = wait_for(&client, |event| {
         matches!(
            event,
            IpcEvent::Message(response)
               if matches!(&**response, Response::Prompt(prompt) if prompt.id == 9)
         )
      });
      assert!(
         seen.is_some(),
         "a prompt must reach an unattended window at once"
      );
      assert!(
         woken.load(Ordering::SeqCst) > wakes,
         "a prompt must wake the ui"
      );

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn the_backlog_keeps_the_newest_and_counts_the_drops() {
      let path = socket_path("hidden-cap");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, _woken) = counted();
      let client = spawn_plain(path.clone(), waker);
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      client.attend(false);
      for port in 0..(HIDDEN_BACKLOG as u16 + 5) {
         let frame = closed(port as u64);
         writer
            .write_all(&encode_line(&frame).expect("encode the closed prompt"))
            .expect("write the closed prompt");
      }

      // Let the socket thread stash the whole burst before draining, or the drain would keep
      // the backlog below its cap and no event would ever be dropped.
      thread::sleep(Duration::from_millis(300));
      let deadline = Instant::now() + WAIT;
      let mut kept = Vec::new();
      let mut dropped = 0;
      let mut last = usize::MAX;
      let mut idle = 0;
      while Instant::now() < deadline && idle < 5 {
         let (mut events, lost) = client.take_backlog();
         kept.append(&mut events);
         dropped += lost;
         if kept.len() == last {
            idle += 1;
         } else {
            last = kept.len();
            idle = 0;
         }
         thread::sleep(Duration::from_millis(20));
      }

      assert_eq!(
         dropped, 5,
         "the five oldest events must be counted as dropped"
      );
      assert_eq!(
         kept.len(),
         HIDDEN_BACKLOG,
         "the backlog keeps its newest events"
      );
      let ids: Vec<u64> = kept
         .iter()
         .map(|event| match event {
            IpcEvent::Message(response) => match &**response {
               Response::PromptClosed { id, .. } => *id,
               other => panic!("expected a closed prompt, got {other:?}"),
            },
            other => panic!("expected a message, got {other:?}"),
         })
         .collect();
      assert_eq!(
         ids.first().copied(),
         Some(5),
         "the oldest were dropped"
      );
      assert_eq!(
         ids.last().copied(),
         Some(HIDDEN_BACKLOG as u64 + 4),
         "the newest were kept"
      );

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn a_connection_wakes_a_window_that_is_on_screen() {
      let path = socket_path("visible-sink");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, woken) = counted();
      let (sink, seen) = recording_sink();
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}), sink);
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      client.attend(true);
      let wakes = woken.load(Ordering::SeqCst);
      let frame = connection_for("brave-browser", 1);
      writer
         .write_all(&encode_line(&frame).expect("encode the connection"))
         .expect("write the connection");

      let deadline = Instant::now() + WAIT;
      while Instant::now() < deadline && seen.lock().expect("read the sink").is_empty() {
         thread::sleep(Duration::from_millis(20));
      }
      assert_eq!(
         seen.lock().expect("read the sink").len(),
         1,
         "the flow must reach the log"
      );
      assert!(
         woken.load(Ordering::SeqCst) > wakes,
         "a window on screen must be woken for the new row"
      );
      assert!(
         client.poll().is_none(),
         "the wake is the frame; the row still does not travel through the queue"
      );

      fs::remove_file(&path).expect("remove the socket");
   }

   /// The owner's report: hidden to tray, a browser's new connections never appeared because the
   /// torrent client's flood had evicted them from the shared backlog. The log's per-application
   /// rings must decide what survives, not a queue's order.
   #[test]
   fn a_flood_does_not_evict_a_quiet_app_while_hidden() {
      const PER_APP: usize = 50;
      const QUIET: usize = 6;
      let path = socket_path("hidden-flood");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, woken) = counted();
      let log = Arc::new(Mutex::new(ConnectionLog::new(PER_APP, 8)));
      let sink: ConnectionSink = {
         let log = Arc::clone(&log);
         Arc::new(move |event: &ConnectionEvent| {
            log.lock().expect("apply the flow").push(event);
         })
      };
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}), sink);
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      client.attend(false);
      let wakes = woken.load(Ordering::SeqCst);
      for n in 0..600_u16 {
         let flood = connection_for("qbittorrent", n);
         writer
            .write_all(&encode_line(&flood).expect("encode the flood"))
            .expect("write the flood");
         if n % 100 == 0 {
            let quiet = connection_for("brave", n);
            writer
               .write_all(&encode_line(&quiet).expect("encode the browser row"))
               .expect("write the browser row");
         }
      }

      let deadline = Instant::now() + WAIT;
      while Instant::now() < deadline && log.lock().expect("read the log").len() < PER_APP + QUIET {
         thread::sleep(Duration::from_millis(20));
      }

      let (quiet_rows, flood_rows) = {
         let log = log.lock().expect("read the log");
         let quiet = log.rows().filter(|row| row.app == "brave").count();
         let flood = log.rows().filter(|row| row.app == "qbittorrent").count();
         (quiet, flood)
      };
      assert_eq!(
         quiet_rows, QUIET,
         "the quiet app keeps every row it made"
      );
      assert_eq!(
         flood_rows, PER_APP,
         "the flood app keeps its own cap, and only its own"
      );
      assert_eq!(
         woken.load(Ordering::SeqCst),
         wakes,
         "600 flows must paint nothing while the window is hidden"
      );
      let (kept, dropped) = client.take_backlog();
      assert!(
         kept.is_empty(),
         "no connection may be queued for a later frame"
      );
      assert_eq!(dropped, 0);

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn a_snapshot_is_replaced_instead_of_queued() {
      let path = socket_path("hidden-snapshot");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, _woken) = counted();
      let client = spawn_plain(path.clone(), waker);
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      client.attend(false);
      for count in 1..=3 {
         let frame = status(count);
         writer
            .write_all(&encode_line(&frame).expect("encode the status"))
            .expect("write the status");
      }

      // Let all three snapshots arrive, so a replace-or-queue bug shows up as three events.
      thread::sleep(Duration::from_millis(300));
      let deadline = Instant::now() + WAIT;
      let mut kept = Vec::new();
      while Instant::now() < deadline && kept.is_empty() {
         let (mut events, _) = client.take_backlog();
         kept.append(&mut events);
         if kept.is_empty() {
            thread::sleep(Duration::from_millis(20));
         }
      }

      assert_eq!(
         kept.len(),
         1,
         "a snapshot is replaced, not queued"
      );
      match &kept[0] {
         IpcEvent::Message(response) => match &**response {
            Response::Status(status) => assert_eq!(status.rule_count, 3),
            other => panic!("expected a status, got {other:?}"),
         },
         other => panic!("expected a message, got {other:?}"),
      }

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn requests_sent_before_the_handshake_are_delivered() {
      let path = socket_path("pending-flush");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, _woken) = counted();
      let client = spawn_plain(path.clone(), waker);

      // Both are sent before the thread has a socket to write them to.
      assert!(client.send(&Request::Status));
      assert!(client.send(&Request::ListRules));

      let (mut reader, _writer) = accept_hello(&listener);
      reader.get_ref().set_read_timeout(Some(WAIT)).expect("set the read timeout");
      let mut line = String::new();
      reader.read_line(&mut line).expect("read the status");
      assert_eq!(
         decode_line::<Request>(line.as_bytes()).expect("decodable status"),
         Request::Status
      );
      line.clear();
      reader.read_line(&mut line).expect("read the listrules");
      assert_eq!(
         decode_line::<Request>(line.as_bytes()).expect("decodable listrules"),
         Request::ListRules
      );

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn a_frame_after_a_silence_is_delivered() {
      let path = socket_path("silent-read");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, _woken) = counted();
      let client = spawn_plain(path.clone(), waker);
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      // Well past the old read timeout, then the daemon speaks again.
      thread::sleep(Duration::from_millis(400));
      let hello = hello();
      writer
         .write_all(&encode_line(&hello).expect("encode the hello"))
         .expect("write the hello");

      assert_eq!(next_message(&client), hello);

      fs::remove_file(&path).expect("remove the socket");
   }
}
