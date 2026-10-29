//! The GUI's half of the daemon protocol: one socket thread, a queue and a drain.
//!
//! The UI thread must never block on a socket, so all blocking I/O sits on a connection
//! thread that retries a missing daemon instead of handing the UI an error to handle:
//! `send` only queues and `poll` only drains. The UI wires this up in a later slice.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use netshield_core::ipc::{
   ClientKind, MAX_FRAME_LEN, PROTOCOL_VERSION, PromptRequest, Request, Response, decode_line,
   encode_line,
};

/// How long a read may block before queued requests are forwarded again.
const READ_TIMEOUT: Duration = Duration::from_millis(100);

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
/// The connection history keeps 500 rows and drops the oldest, so a backlog of the same
/// order loses nothing the live log would have kept. A snapshot of one kind is replaced
/// rather than queued: only its newest copy is ever read.
const HIDDEN_BACKLOG: usize = 512;

/// What a kept event collapses on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
   /// Rows pile up: every flow is a log entry.
   Connection,
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
         Response::Connection(_) => Kind::Connection,
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
      if matches!(new_kind, Kind::Connection | Kind::PromptClosed) {
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
   out: Sender<String>,
   events: Receiver<IpcEvent>,
   on_prompt: PromptHook,
   /// Shared with the socket thread: whether the root window is on screen.
   attend: Arc<Attend>,
}

/// A send handle for code that runs outside the main window's frames (the alert viewport's own
/// callback, which keeps painting while the main window is minimised).
#[derive(Clone)]
pub struct Decider {
   out: Sender<String>,
}

impl Decider {
   /// A handle whose requests go nowhere, for `--mock` where no daemon is contacted.
   ///
   /// The receiver is drained on a thread of its own so `send` keeps succeeding: a prompt
   /// answer in `--mock` is discarded by design, not because the daemon thread died.
   pub fn silent() -> Self {
      let (out, receiver) = mpsc::channel();
      thread::spawn(move || while receiver.recv().is_ok() {});
      Self { out }
   }

   /// Encodes and queues a request. Returns false if the thread is gone.
   pub fn send(&self, request: &Request) -> bool {
      let Some(line) = frame(request) else {
         log::debug!("cannot encode an ipc request");
         return false;
      };
      self.out.send(line).is_ok()
   }
}

impl IpcClient {
   /// Spawns the connection thread. Never blocks and never fails: connection errors
   /// surface as [`IpcEvent::Connected(false)`] and the thread keeps retrying.
   ///
   /// Every queued event is followed by a `waker` call, because a hidden or minimised
   /// root window schedules no frame on its own and would otherwise not drain the queue.
   pub fn spawn(socket_path: PathBuf, waker: Waker, on_prompt: PromptHook) -> Self {
      let (out, out_rx) = mpsc::channel();
      let (events, events_rx) = mpsc::channel();
      let attend = Arc::new(Attend::new());
      let thread_events = events.clone();
      let thread_waker = Arc::clone(&waker);
      let thread_prompt = Arc::clone(&on_prompt);
      let thread_attend = Arc::clone(&attend);
      let spawned = thread::Builder::new().name("netshield-ipc".to_owned()).spawn(move || {
         run(
            &socket_path,
            &out_rx,
            &thread_events,
            &thread_waker,
            &thread_prompt,
            &thread_attend,
         )
      });
      if let Err(err) = spawned {
         log::warn!("cannot start the ipc thread: {err}");
         waker();
         let _ = events.send(IpcEvent::Connected(false));
      }
      Self {
         out,
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

   /// Encodes and queues a request. Returns false if the thread is gone.
   pub fn send(&self, request: &Request) -> bool {
      let Some(line) = frame(request) else {
         log::debug!("cannot encode an ipc request");
         return false;
      };
      self.out.send(line).is_ok()
   }

   /// Non-blocking drain for the UI: returns None when there is nothing new.
   pub fn poll(&self) -> Option<IpcEvent> {
      self.events.try_recv().ok()
   }

   /// A cloneable send handle for callbacks that outlive one `App::update` call.
   pub fn decider(&self) -> Decider {
      Decider {
         out: self.out.clone(),
      }
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
   out: &Receiver<String>,
   events: &Sender<IpcEvent>,
   waker: &Waker,
   on_prompt: &PromptHook,
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
            if converse(stream, out, events, waker, on_prompt, attend) == Flow::Stop {
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
/// The read timeout is what keeps queued requests moving while the daemon is silent: a
/// timeout is not an error, it just returns to the top of the loop and forwards again.
fn converse(
   stream: UnixStream,
   out: &Receiver<String>,
   events: &Sender<IpcEvent>,
   waker: &Waker,
   on_prompt: &PromptHook,
   attend: &Attend,
) -> Flow {
   let mut writer = match stream.try_clone() {
      Ok(writer) => writer,
      Err(err) => {
         log::debug!("cannot clone the ipc socket: {err}");
         return Flow::Reconnect;
      }
   };
   if let Err(err) = stream.set_read_timeout(Some(READ_TIMEOUT)) {
      log::debug!("cannot set the ipc read timeout: {err}");
      return Flow::Reconnect;
   }
   let hello = Request::Hello {
      version: PROTOCOL_VERSION,
      client: ClientKind::Gui,
   };
   let Some(line) = frame(&hello) else {
      return Flow::Reconnect;
   };
   if let Err(err) = writer.write_all(line.as_bytes()) {
      log::debug!("cannot send the ipc hello: {err}");
      return Flow::Reconnect;
   }

   // Partial frames survive a read timeout in `buf`, which grows only up to the bound.
   let mut buf = Vec::new();
   let mut reader = BufReader::new(stream);
   loop {
      match forward(out, &mut writer) {
         Flow::Continue => {}
         flow => return flow,
      }
      let budget = (MAX_FRAME_LEN + 1 - buf.len()) as u64;
      match reader.by_ref().take(budget).read_until(b'\n', &mut buf) {
         Ok(0) => return Flow::Reconnect,
         Ok(_) => {}
         Err(err)
            if matches!(
               err.kind(),
               ErrorKind::WouldBlock | ErrorKind::TimedOut
            ) => {}
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
         let flow = dispatch(&buf, events, waker, on_prompt, attend);
         buf.clear();
         if flow != Flow::Continue {
            return flow;
         }
      }
   }
}

/// Writes everything the UI has queued, without blocking.
fn forward(out: &Receiver<String>, writer: &mut UnixStream) -> Flow {
   loop {
      match out.try_recv() {
         Ok(line) => {
            if let Err(err) = writer.write_all(line.as_bytes()) {
               log::debug!("cannot send an ipc request: {err}");
               return Flow::Reconnect;
            }
         }
         Err(TryRecvError::Empty) => return Flow::Continue,
         Err(TryRecvError::Disconnected) => return Flow::Stop,
      }
   }
}

/// Decodes one frame and hands it to the UI; a malformed frame is dropped, not fatal.
fn dispatch(
   frame: &[u8],
   events: &Sender<IpcEvent>,
   waker: &Waker,
   on_prompt: &PromptHook,
   attend: &Attend,
) -> Flow {
   let body = frame.strip_suffix(b"\n").unwrap_or(frame);
   if body.iter().all(u8::is_ascii_whitespace) {
      return Flow::Continue;
   }
   match decode_line::<Response>(body) {
      Ok(response) => {
         if let Response::Prompt(prompt) = &response {
            log::info!(
               "prompt {} received for {} -> {} ({})",
               prompt.id,
               prompt.connection.app_name,
               prompt.connection.domain.as_deref().unwrap_or("?"),
               prompt.connection.remote_ip
            );
            on_prompt(prompt);
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
   use netshield_core::connection::{Family, L4Proto};
   use netshield_core::ipc::{ConnectionEvent, ConnectionView, Mode, StatusInfo};
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

   fn connection(port: u16) -> Response {
      Response::Connection(ConnectionEvent {
         at: 1_700_000_000,
         connection: ConnectionView {
            app_name: "brave-browser".to_owned(),
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

   fn status(rule_count: usize) -> Response {
      Response::Status(StatusInfo {
         daemon_pid: 7,
         mode: Mode::Alert,
         rule_count,
         pending_prompts: 0,
         queue_num: 0,
         queue_drops: 0,
         table_verified: true,
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
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}));
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
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}));

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
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}));
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
      let client = IpcClient::spawn(path.clone(), waker, hook);
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
   fn events_are_kept_while_nobody_is_looking() {
      let path = socket_path("hidden-backlog");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, woken) = counted();
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}));
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      client.attend(false);
      let wakes = woken.load(Ordering::SeqCst);
      for port in 1..=3 {
         let frame = connection(port);
         writer
            .write_all(&encode_line(&frame).expect("encode the connection"))
            .expect("write the connection");
      }

      let deadline = Instant::now() + WAIT;
      let mut kept = Vec::new();
      let mut dropped = 0;
      while Instant::now() < deadline && kept.len() < 3 {
         assert!(
            client.poll().is_none(),
            "an unattended window must not be woken by routine traffic"
         );
         let (mut events, lost) = client.take_backlog();
         dropped += lost;
         kept.append(&mut events);
         thread::sleep(Duration::from_millis(20));
      }

      assert_eq!(
         woken.load(Ordering::SeqCst),
         wakes,
         "routine traffic must not wake an unattended window"
      );
      assert_eq!(
         kept.len(),
         3,
         "the three connection events must be kept"
      );
      let ports: Vec<u16> = kept
         .iter()
         .map(|event| match event {
            IpcEvent::Message(response) => match &**response {
               Response::Connection(event) => event.connection.remote_port,
               other => panic!("expected a connection, got {other:?}"),
            },
            other => panic!("expected a message, got {other:?}"),
         })
         .collect();
      assert_eq!(ports, vec![1, 2, 3]);
      let (rest, more) = client.take_backlog();
      assert!(
         rest.is_empty(),
         "the backlog must be drained by the take"
      );
      assert_eq!(dropped + more, 0, "three events fit the backlog");

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn a_prompt_wakes_an_unattended_window() {
      let path = socket_path("hidden-prompt");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, woken) = counted();
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}));
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
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}));
      let (_reader, mut writer) = accept_hello(&listener);
      wait_connected(&client, true);

      client.attend(false);
      for port in 0..(HIDDEN_BACKLOG as u16 + 5) {
         let frame = connection(port);
         writer
            .write_all(&encode_line(&frame).expect("encode the connection"))
            .expect("write the connection");
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
      let ports: Vec<u16> = kept
         .iter()
         .map(|event| match event {
            IpcEvent::Message(response) => match &**response {
               Response::Connection(event) => event.connection.remote_port,
               other => panic!("expected a connection, got {other:?}"),
            },
            other => panic!("expected a message, got {other:?}"),
         })
         .collect();
      assert_eq!(
         ports.first().copied(),
         Some(5),
         "the oldest were dropped"
      );
      assert_eq!(
         ports.last().copied(),
         Some(HIDDEN_BACKLOG as u16 + 4),
         "the newest were kept"
      );

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn a_snapshot_is_replaced_instead_of_queued() {
      let path = socket_path("hidden-snapshot");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let (waker, _woken) = counted();
      let client = IpcClient::spawn(path.clone(), waker, Arc::new(|_| {}));
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
}
