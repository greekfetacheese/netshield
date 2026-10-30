//! The `NETLINK_CONNECTOR` proc connector: a live feed of `exec` and `exit` events.
//!
//! `/proc` polling can only read the state that still exists when the scan runs: a process
//! that exits between opening a socket and having its descriptor resolved leaves a socket
//! inode that no longer names an identity. The kernel's proc connector reports the process
//! lifecycle as it happens, so the daemon can remember an identity at `exec` time and use
//! it after `/proc/<pid>/exe` has vanished. Finding fresh sockets remains a `/proc` scan;
//! this feed only makes the identity lookup race-free.
//!
//! The wire format is the connector's, not nfnetlink's: every field is native-endian, so
//! `u32::from_ne_bytes` is correct here while the `__be` attributes in [`super::attrs`]
//! are big-endian. A connector datagram carries `nlmsghdr` messages whose payload is a
//! `cn_msg` followed by the event, and the kernel may coalesce several events into one
//! datagram, which [`ProcConnector::recv`] drains in full.
//!
//! `CONFIG_PROC_EVENTS` is optional in the kernel, so binding or the listen request can
//! fail; the caller treats that as "fall back to `/proc`", never as a daemon failure.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, SystemTime};

use super::socket::{MessageIter, RECV_BUF_LEN};

/// The netlink protocol family for the process event connector.
const NETLINK_CONNECTOR: libc::c_int = 11;

/// The connector index/volume pair the process connector is registered under.
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;

/// The `cn_msg` multicast operation that starts and stops the event stream.
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;

/// `PROC_EVENT_EXEC`: a process called `execve`.
const PROC_EVENT_EXEC: u32 = 2;
/// `PROC_EVENT_EXIT`: a process is exiting, with its pid still recorded.
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

/// Size of `struct cn_msg`: `idx`, `val`, `seq`, `ack` (`u32` each), `len`, `flags`
/// (`u16` each), all native-endian.
const CN_MSG_LEN: usize = 20;

/// Absolute offsets into one message payload (`cn_msg` + `proc_event`).
const CN_IDX_OFFSET: usize = 0;
const CN_VAL_OFFSET: usize = 4;
const CN_LEN_OFFSET: usize = 16;
const PROC_WHAT_OFFSET: usize = 20;
/// `timestamp_ns` in `struct proc_event`: CLOCK_MONOTONIC at the moment the kernel logged the
/// event, in nanoseconds since boot. Kernels before 4.2 wrote no such field.
const PROC_TIMESTAMP_OFFSET: usize = 28;
const PROC_PID_OFFSET: usize = 36;
/// The smallest `proc_event` that carries both header and the pid pair: 16 bytes of
/// common header plus the union's first field and `process_tgid`.
const PROC_EVENT_LEN: usize = 24;

/// One process lifecycle event decoded from the connector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcEvent {
   /// `pid` called `execve`; its identity can be read now. `image_started` is the kernel's
   /// CLOCK_MONOTONIC stamp converted to wall time, or `None` when the kernel wrote none.
   Exec {
      pid: u32,
      image_started: Option<SystemTime>,
   },
   /// `pid` is exiting; any cached identity is about to refer to a recycled pid.
   Exit { pid: u32 },
}

/// An open proc connector socket plus its reused receive buffer.
pub struct ProcConnector {
   fd: OwnedFd,
   recv_buf: Vec<u8>,
}

impl ProcConnector {
   /// Opens the connector, binds it to the process group and sends the listen request.
   ///
   /// A kernel built without `CONFIG_PROC_EVENTS` fails here with a bind or send error;
   /// the caller logs it and keeps attributing through `/proc`.
   pub fn open() -> io::Result<Self> {
      // SAFETY: `socket` is called with the constant arguments the kernel expects; the
      // returned descriptor is the only resource it creates, and it is checked for -1
      // before being adopted below.
      let raw = unsafe {
         libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW,
            NETLINK_CONNECTOR,
         )
      };
      if raw < 0 {
         return Err(io::Error::last_os_error());
      }
      // SAFETY: `raw` is a fresh descriptor owned by this function (the check above
      // rejected -1), so transferring it into `OwnedFd` gives it exactly one owner, which
      // closes it on every later error path and on drop.
      let fd = unsafe { OwnedFd::from_raw_fd(raw) };

      // The connector multicast group is `CN_IDX_PROC`; `nl_pid` names this process so the
      // kernel does not hand the port to another listener.
      // SAFETY: `sockaddr_nl` is a plain C struct whose only invalid state is an
      // uninitialised padding field; all-zero bytes are the documented `nl_pad`, and the
      // family/pid/groups fields are assigned below.
      let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
      addr.nl_family = libc::AF_NETLINK as u16;
      addr.nl_pid = std::process::id();
      addr.nl_groups = CN_IDX_PROC;
      // SAFETY: `addr` is a fully initialised `sockaddr_nl` and the size passed is its
      // own; the pointer stays valid for the duration of the call, and the kernel only
      // reads it.
      let bound = unsafe {
         libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
         )
      };
      if bound < 0 {
         return Err(io::Error::last_os_error());
      }

      send_multicast(fd.as_raw_fd(), PROC_CN_MCAST_LISTEN)?;

      Ok(Self {
         fd,
         recv_buf: vec![0u8; RECV_BUF_LEN],
      })
   }

   /// Blocks until at least one event is available; multiple events per datagram are all
   /// returned. `IO` errors are the caller's to log and retry.
   pub fn recv(&mut self, out: &mut Vec<ProcEvent>) -> io::Result<usize> {
      let n = recv_datagram(self.fd.as_raw_fd(), &mut self.recv_buf)?;
      Ok(drain_events(&self.recv_buf[..n], out))
   }

   /// Bounds every later receive with `SO_RCVTIMEO`.
   ///
   /// The daemon thread must notice the shutdown flag, and a proc connector is quiet on an
   /// idle system; a timeout surfaces as `EAGAIN`/`EWOULDBLOCK` from [`recv`], which the
   /// caller treats as "nothing happened, check the flag". A zero duration disables it.
   ///
   /// [`recv`]: ProcConnector::recv
   pub fn set_recv_timeout(&self, timeout: Duration) -> io::Result<()> {
      let tv = libc::timeval {
         tv_sec: timeout.as_secs().try_into().unwrap_or(libc::time_t::MAX),
         tv_usec: libc::suseconds_t::from(timeout.subsec_micros()),
      };
      // SAFETY: the descriptor is owned by `self` and open, and `tv` is a fully
      // initialised `timeval` whose size is passed with the pointer; the kernel only
      // reads it for the duration of the call.
      let set = unsafe {
         libc::setsockopt(
            self.fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
         )
      };
      if set < 0 {
         return Err(io::Error::last_os_error());
      }
      Ok(())
   }
}

impl Drop for ProcConnector {
   /// Stops the stream on the way out, so the kernel stops queueing events for a socket
   /// that is about to close. Failure is irrelevant here; the descriptor is closing anyway.
   fn drop(&mut self) {
      let _ = send_multicast(self.fd.as_raw_fd(), PROC_CN_MCAST_IGNORE);
   }
}

/// Sends one `cn_msg` multicast operation (`LISTEN` or `IGNORE`) to the kernel.
fn send_multicast(fd: libc::c_int, operation: u32) -> io::Result<()> {
   // `cn_msg` header plus the 4-byte multicast op; the kernel ignores `seq`/`ack` for this
   // request, but the struct still carries them.
   let mut payload = Vec::with_capacity(CN_MSG_LEN + 4);
   payload.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
   payload.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
   payload.extend_from_slice(&0u32.to_ne_bytes()); // seq
   payload.extend_from_slice(&0u32.to_ne_bytes()); // ack
   payload.extend_from_slice(&4u16.to_ne_bytes()); // len: one u32 op follows the header
   payload.extend_from_slice(&0u16.to_ne_bytes()); // flags
   payload.extend_from_slice(&operation.to_ne_bytes());

   let datagram = super::socket::frame(
      NLMSG_CONNECTOR,
      super::socket::NLM_F_REQUEST,
      0,
      &payload,
   );
   send_raw(fd, &datagram)
}

/// The `nlmsghdr.nlmsg_type` connector events use.
const NLMSG_CONNECTOR: u16 = 0;

/// Sends one datagram to the kernel (`nl_pid = 0`).
fn send_raw(fd: libc::c_int, datagram: &[u8]) -> io::Result<()> {
   // Netlink requires either a connected socket or an explicit destination; without one
   // `send` fails with EDESTADDRREQ.
   // SAFETY: `sockaddr_nl` is a plain C struct; all-zero bytes are its valid `nl_pad`,
   // and the kernel destination is `nl_pid = 0` with no multicast groups.
   let mut dest: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
   dest.nl_family = libc::AF_NETLINK as u16;
   dest.nl_pid = 0;
   dest.nl_groups = 0;
   loop {
      // SAFETY: the descriptor is owned by the caller and open; `datagram` is a live slice
      // read only for the duration of the call, and `dest` is a fully initialised
      // `sockaddr_nl` whose length is passed with it.
      let sent = unsafe {
         libc::sendto(
            fd,
            datagram.as_ptr().cast(),
            datagram.len(),
            0,
            (&dest as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
         )
      };
      if sent < 0 {
         let err = io::Error::last_os_error();
         if err.kind() == io::ErrorKind::Interrupted {
            continue;
         }
         return Err(err);
      }
      if sent as usize != datagram.len() {
         return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "proc connector datagram was only partially sent",
         ));
      }
      return Ok(());
   }
}

/// One blocking receive into `buf`; retries `EINTR`.
fn recv_datagram(fd: libc::c_int, buf: &mut [u8]) -> io::Result<usize> {
   loop {
      // SAFETY: the descriptor is owned by the caller and open, and `buf` is a live slice
      // whose pointer and length are handed to the kernel for writing only.
      let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
      if n < 0 {
         let err = io::Error::last_os_error();
         if err.kind() == io::ErrorKind::Interrupted {
            continue;
         }
         return Err(err);
      }
      return Ok(n as usize);
   }
}

/// Appends every `proc_event` framed in one received datagram to `out`.
///
/// Split out of [`ProcConnector::recv`] so the coalescing case is unit-tested against a
/// hand-built datagram with no socket: the kernel may pack several process events into one
/// datagram, and a receive that kept only the first would silently lose an exit.
fn drain_events(datagram: &[u8], out: &mut Vec<ProcEvent>) -> usize {
   let mut appended = 0;
   for msg in MessageIter::new(datagram) {
      let Ok(msg) = msg else {
         // A malformed message ends the datagram; there is no trustworthy next header.
         break;
      };
      if let Some(event) = parse_message(msg.payload) {
         out.push(event);
         appended += 1;
      }
   }
   appended
}

/// Decodes one `cn_msg` + `proc_event` message payload.
///
/// Returns `None` for a short buffer, a message for another connector, or an event this
/// module does not track. Every offset is checked before it is read, so hostile kernel data
/// becomes `None` rather than a panic.
fn parse_message(payload: &[u8]) -> Option<ProcEvent> {
   if payload.len() < CN_MSG_LEN {
      return None;
   }
   let idx = read_u32(payload, CN_IDX_OFFSET)?;
   let val = read_u32(payload, CN_VAL_OFFSET)?;
   if idx != CN_IDX_PROC || val != CN_VAL_PROC {
      return None;
   }
   let len_bytes = payload.get(CN_LEN_OFFSET..CN_LEN_OFFSET + 2)?;
   let len = u16::from_ne_bytes(len_bytes.try_into().ok()?);
   let event = payload.get(CN_MSG_LEN..)?;
   // `len` is the kernel's claim about the event; trust the smaller of it and the bytes
   // actually present so a lying length can never reach past the buffer.
   let available = event.len().min(usize::from(len));
   if available < PROC_EVENT_LEN {
      return None;
   }
   // The event union puts `process_pid` and `process_tgid` at these offsets for both
   // `EXEC` and `EXIT`; the pid is the one the cache is keyed by.
   let what = read_u32(payload, PROC_WHAT_OFFSET)?;
   let pid = read_u32(payload, PROC_PID_OFFSET)?;
   // A short message (an older kernel's event, or a lying length) simply has no stamp; the
   // caller then falls back to its own clock, and `SLACK` covers that case.
   let stamped = read_u64(payload, PROC_TIMESTAMP_OFFSET)
      .filter(|nanos| *nanos != 0)
      .map(monotonic_to_wall);
   match what {
      PROC_EVENT_EXEC => Some(ProcEvent::Exec {
         pid,
         image_started: stamped,
      }),
      PROC_EVENT_EXIT => Some(ProcEvent::Exit { pid }),
      _ => None,
   }
}

/// Reads a native-endian `u32` at `offset`, or `None` when the buffer ends before it.
fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
   let bytes = buf.get(offset..offset + 4)?;
   Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

/// Reads a native-endian `u64` at `offset`, or `None` when the buffer ends before it.
fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
   let bytes = buf.get(offset..offset + 8)?;
   Some(u64::from_ne_bytes(bytes.try_into().ok()?))
}

/// Converts a boot-relative CLOCK_MONOTONIC stamp to wall time.
///
/// The two clocks are read as a pair, so the conversion costs one `clock_gettime` and inherits only
/// the microseconds between the reads — which is what `SLACK` budgets for. A failure to read
/// CLOCK_MONOTONIC is not worth an error path: the caller keeps its own receipt time.
fn monotonic_to_wall(event_ns: u64) -> SystemTime {
   let Some(now_mono) = monotonic_ns() else {
      return SystemTime::now();
   };
   wall_from_monotonic(event_ns, now_mono, SystemTime::now())
}

/// The pure half of [`monotonic_to_wall`], so the arithmetic is testable without a clock.
fn wall_from_monotonic(event_ns: u64, now_mono_ns: u64, now_wall: SystemTime) -> SystemTime {
   let lag = now_mono_ns.saturating_sub(event_ns);
   now_wall.checked_sub(Duration::from_nanos(lag)).unwrap_or(now_wall)
}

/// CLOCK_MONOTONIC in nanoseconds, the clock the connector stamps its events with.
///
/// This is the one place in the crate that reads a clock through `libc`, and it stays here because
/// `unsafe` is only allowed under `netlink/`. `proc.rs` uses it for `image_started_at`, because
/// `/proc/uptime` is CLOCK_BOOTTIME while `starttime` counts CLOCK_MONOTONIC ticks.
pub(crate) fn monotonic_ns() -> Option<u64> {
   let mut now = libc::timespec {
      tv_sec: 0,
      tv_nsec: 0,
   };
   // SAFETY: `now` is a valid, writable `timespec` for the duration of the call, and
   // CLOCK_MONOTONIC is one of the two clock ids `clock_gettime` requires.
   let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
   if rc != 0 || now.tv_sec < 0 || now.tv_nsec < 0 {
      return None;
   }
   Some(
      (now.tv_sec as u64)
         .saturating_mul(1_000_000_000)
         .saturating_add(now.tv_nsec as u64),
   )
}

#[cfg(test)]
mod tests {
   use super::*;

   /// Builds one literal-sized `cn_msg` + `proc_event` message.
   ///
   /// The bytes are assembled from explicit field offsets rather than from the parsing
   /// constants, so a wrong constant breaks the parser test instead of moving both sides
   /// together.
   fn message(idx: u32, val: u32, what: u32, pid: u32, stamp: u64) -> Vec<u8> {
      let mut msg = vec![0u8; 20 + 24];
      msg[0..4].copy_from_slice(&idx.to_ne_bytes());
      msg[4..8].copy_from_slice(&val.to_ne_bytes());
      msg[16..18].copy_from_slice(&24u16.to_ne_bytes());
      msg[20..24].copy_from_slice(&what.to_ne_bytes());
      msg[24..28].copy_from_slice(&3u32.to_ne_bytes()); // cpu
      msg[28..36].copy_from_slice(&stamp.to_ne_bytes());
      msg[36..40].copy_from_slice(&pid.to_ne_bytes());
      msg[40..44].copy_from_slice(&pid.to_ne_bytes());
      msg
   }

   /// Wraps message payloads in `nlmsghdr` frames, back to back as the kernel sends them.
   fn datagram(payloads: &[Vec<u8>]) -> Vec<u8> {
      let mut bytes = Vec::new();
      for payload in payloads {
         bytes.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
         bytes.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_type
         bytes.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
         bytes.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
         bytes.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
         bytes.extend_from_slice(payload);
      }
      bytes
   }

   #[test]
   fn exec_and_exit_frames_decode_to_their_pid() {
      let bytes = message(1, 1, 2, 4242, 0);
      assert_eq!(
         parse_message(&bytes),
         Some(ProcEvent::Exec {
            pid: 4242,
            image_started: None,
         })
      );

      let mut events = Vec::new();
      assert_eq!(drain_events(&datagram(&[bytes]), &mut events), 1);
      assert_eq!(
         events,
         vec![ProcEvent::Exec {
            pid: 4242,
            image_started: None,
         }]
      );

      // `PROC_EVENT_EXIT` is bit 31 set; a signed or truncated comparison would read it
      // as an unknown event.
      let bytes = message(1, 1, 0x8000_0000, 777, 0);
      assert_eq!(
         parse_message(&bytes),
         Some(ProcEvent::Exit { pid: 777 })
      );

      let mut events = Vec::new();
      assert_eq!(drain_events(&datagram(&[bytes]), &mut events), 1);
      assert_eq!(events, vec![ProcEvent::Exit { pid: 777 }]);
   }

   #[test]
   fn truncated_frames_are_rejected_without_panicking() {
      let full = message(1, 1, 2, 9001, 0);
      for cut in [0, 1, 19, 20, 21, 35, 36, 39, 43] {
         assert_eq!(
            parse_message(&full[..cut]),
            None,
            "a {cut}-byte frame is short of the event"
         );
      }
      // A `cn_msg` whose `len` claims fewer bytes than the event header needs.
      let mut lying = full.clone();
      lying[16..18].copy_from_slice(&4u16.to_ne_bytes());
      assert_eq!(parse_message(&lying), None);

      // A header that announces more bytes than were received ends the datagram.
      let mut short = datagram(&[message(1, 1, 2, 1, 0)]);
      short[0..4].copy_from_slice(&80u32.to_ne_bytes());
      let mut events = Vec::new();
      assert_eq!(drain_events(&short, &mut events), 0);
      assert!(events.is_empty());
   }

   #[test]
   fn unrelated_messages_are_ignored() {
      // Another connector's index or val pair is not a proc event.
      assert_eq!(parse_message(&message(2, 1, 2, 1, 0)), None);
      assert_eq!(parse_message(&message(1, 2, 2, 1, 0)), None);
      assert_eq!(
         parse_message(&message(0, 0, 2, 1, 0)),
         None,
         "an unrelated connector index/val pair is not a proc event"
      );

      // `PROC_EVENT_FORK` is 1; this module only tracks exec and exit.
      assert_eq!(parse_message(&message(1, 1, 1, 1, 0)), None);
      assert_eq!(parse_message(&message(1, 1, 0, 1, 0)), None);

      // A datagram mixing one tracked event with an unknown one yields only the tracked
      // event, and both frames are still walked.
      let mut events = Vec::new();
      let bytes = datagram(&[
         message(1, 1, 2, 10, 0),
         message(1, 1, 1, 11, 0),
         message(1, 1, 0x8000_0000, 12, 0),
      ]);
      assert_eq!(drain_events(&bytes, &mut events), 2);
      assert_eq!(
         events,
         vec![
            ProcEvent::Exec {
               pid: 10,
               image_started: None,
            },
            ProcEvent::Exit { pid: 12 },
         ]
      );
   }

   #[test]
   fn several_events_in_one_datagram_are_all_returned() {
      // The kernel coalesces; keeping only the first would lose the exec that followed an
      // exit and leave its process identity unreadable.
      let bytes = datagram(&[
         message(1, 1, 2, 100, 0),
         message(1, 1, 0x8000_0000, 200, 0),
         message(1, 1, 2, 300, 0),
      ]);
      let mut events = Vec::new();
      assert_eq!(drain_events(&bytes, &mut events), 3);
      assert_eq!(
         events,
         vec![
            ProcEvent::Exec {
               pid: 100,
               image_started: None,
            },
            ProcEvent::Exit { pid: 200 },
            ProcEvent::Exec {
               pid: 300,
               image_started: None,
            },
         ]
      );
   }

   #[test]
   fn an_event_stamped_five_millis_ago_is_converted_to_five_millis_ago() {
      let now_wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
      let now_mono = 12_345_000_000_u64; // arbitrary boot-relative nanoseconds
      let event = now_mono - 5_000_000;
      assert_eq!(
         wall_from_monotonic(event, now_mono, now_wall),
         now_wall - Duration::from_millis(5)
      );
      assert_eq!(
         wall_from_monotonic(now_mono, now_mono, now_wall),
         now_wall,
         "an event stamped now is now"
      );
      assert_eq!(
         wall_from_monotonic(now_mono + 1, now_mono, now_wall),
         now_wall,
         "a stamp in the future cannot move the time forward"
      );
   }

   #[test]
   fn an_exec_message_carries_its_kernel_timestamp() {
      let bytes = message(1, 1, 2, 42, 12_345_000_000);
      let Some(ProcEvent::Exec { pid, image_started }) = parse_message(&bytes) else {
         panic!("an exec message must decode");
      };
      assert_eq!(pid, 42);
      assert!(
         image_started.is_some(),
         "a nonzero stamp is converted, not dropped"
      );

      // A zero stamp is the kernel's "no timestamp" value; attribution falls back to its
      // own receipt clock.
      assert_eq!(
         parse_message(&message(1, 1, 2, 42, 0)),
         Some(ProcEvent::Exec {
            pid: 42,
            image_started: None,
         })
      );

      // Truncated before the stamp ends, the message cannot decode at all: no event may
      // reach the cache without the pid, and no stamp may be invented for one.
      let full = message(1, 1, 2, 42, 12_345_000_000);
      assert_eq!(parse_message(&full[..35]), None);
      assert_eq!(
         read_u64(&full, PROC_TIMESTAMP_OFFSET),
         Some(12_345_000_000)
      );
      assert_eq!(read_u64(&full[..35], PROC_TIMESTAMP_OFFSET), None);
   }
}
