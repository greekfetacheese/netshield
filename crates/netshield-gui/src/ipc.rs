//! The GUI's half of the daemon protocol: one socket thread, a queue and a drain.
//!
//! The UI thread must never block on a socket, so all blocking I/O sits on a connection
//! thread that retries a missing daemon instead of handing the UI an error to handle:
//! `send` only queues and `poll` only drains. The UI wires this up in a later slice.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::Duration;

use netshield_core::ipc::{
   ClientKind, MAX_FRAME_LEN, PROTOCOL_VERSION, Request, Response, decode_line, encode_line,
};

/// How long a read may block before queued requests are forwarded again.
const READ_TIMEOUT: Duration = Duration::from_millis(100);

/// How long to wait before redialling a daemon that is not running.
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// What the connection thread tells the UI.
#[derive(Debug)]
pub enum IpcEvent {
   /// The connection opened or dropped; while false the thread keeps retrying.
   Connected(bool),
   /// One decoded daemon frame.
   Message(Box<Response>),
}

/// A non-blocking handle to the daemon socket.
pub struct IpcClient {
   out: Sender<String>,
   events: Receiver<IpcEvent>,
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
   pub fn spawn(socket_path: PathBuf) -> Self {
      let (out, out_rx) = mpsc::channel();
      let (events, events_rx) = mpsc::channel();
      let thread_events = events.clone();
      let spawned = thread::Builder::new()
         .name("netshield-ipc".to_owned())
         .spawn(move || run(&socket_path, &out_rx, &thread_events));
      if let Err(err) = spawned {
         log::warn!("cannot start the ipc thread: {err}");
         let _ = events.send(IpcEvent::Connected(false));
      }
      Self {
         out,
         events: events_rx,
      }
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

/// Owns the socket: dial, handshake, serve one connection, then retry forever.
fn run(socket_path: &Path, out: &Receiver<String>, events: &Sender<IpcEvent>) {
   // A missing daemon is normal, so the path is named on the first failure only.
   let mut reported_path = false;
   loop {
      match UnixStream::connect(socket_path) {
         Ok(stream) => {
            if events.send(IpcEvent::Connected(true)).is_err() {
               return;
            }
            if converse(stream, out, events) == Flow::Stop {
               return;
            }
         }
         Err(err) if reported_path => log::debug!("cannot connect to the daemon: {err}"),
         Err(err) => {
            log::debug!(
               "cannot connect to the daemon at {}: {err}",
               socket_path.display()
            );
            reported_path = true;
         }
      }
      if events.send(IpcEvent::Connected(false)).is_err() {
         return;
      }
      thread::sleep(RETRY_DELAY);
   }
}

/// Serves one connection until it drops or the UI goes away.
///
/// The read timeout is what keeps queued requests moving while the daemon is silent: a
/// timeout is not an error, it just returns to the top of the loop and forwards again.
fn converse(stream: UnixStream, out: &Receiver<String>, events: &Sender<IpcEvent>) -> Flow {
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
         let flow = dispatch(&buf, events);
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
fn dispatch(frame: &[u8], events: &Sender<IpcEvent>) -> Flow {
   let body = frame.strip_suffix(b"\n").unwrap_or(frame);
   if body.iter().all(u8::is_ascii_whitespace) {
      return Flow::Continue;
   }
   match decode_line::<Response>(body) {
      Ok(response) => match events.send(IpcEvent::Message(Box::new(response))) {
         Ok(()) => Flow::Continue,
         Err(_) => Flow::Stop,
      },
      Err(err) => {
         log::debug!("ignoring an undecodable ipc frame: {err}");
         Flow::Continue
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use netshield_core::ipc::Mode;
   use std::fs;
   use std::os::unix::net::UnixListener;
   use std::sync::atomic::{AtomicUsize, Ordering};
   use std::time::Instant;

   const WAIT: Duration = Duration::from_secs(5);

   /// A socket path no parallel test can collide on; the file is removed by each test.
   fn socket_path(label: &str) -> PathBuf {
      static COUNTER: AtomicUsize = AtomicUsize::new(0);
      let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
      std::env::temp_dir().join(format!(
         "netshield-gui-ipc-{}-{serial}-{label}.sock",
         std::process::id()
      ))
   }

   fn hello() -> Response {
      Response::Hello {
         version: PROTOCOL_VERSION,
         daemon_pid: 7,
         mode: Mode::Alert,
         rule_count: 2,
      }
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
   fn handshake_sends_gui_hello_and_reports_the_daemon() {
      let path = socket_path("handshake");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let client = IpcClient::spawn(path.clone());
      let (_reader, mut writer) = accept_hello(&listener);

      let hello = hello();
      writer
         .write_all(&encode_line(&hello).expect("encode the hello"))
         .expect("write the hello");

      wait_connected(&client, true);
      assert_eq!(next_message(&client), hello);

      fs::remove_file(&path).expect("remove the socket");
   }

   #[test]
   fn forwards_queued_requests() {
      let path = socket_path("forward");
      let listener = UnixListener::bind(&path).expect("bind the listener");
      let client = IpcClient::spawn(path.clone());
      let (mut reader, _writer) = accept_hello(&listener);

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
      let client = IpcClient::spawn(path.clone());

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
      let client = IpcClient::spawn(path.clone());
      let (_reader, mut writer) = accept_hello(&listener);

      writer.write_all(b"not json\n").expect("write the garbage");
      let hello = hello();
      writer
         .write_all(&encode_line(&hello).expect("encode the hello"))
         .expect("write the hello");

      assert_eq!(next_message(&client), hello);

      fs::remove_file(&path).expect("remove the socket");
   }
}
