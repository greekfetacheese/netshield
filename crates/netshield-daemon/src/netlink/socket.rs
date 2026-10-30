//! The netlink socket and message framing.
//!
//! One `SOCK_RAW` socket per queue, bound with `nl_pid = 0` so the kernel assigns the port
//! id. Messages are framed here — every netlink message starts with a 16-byte `nlmsghdr`
//! whose length includes the header — because the sequence number in that header is what
//! ties an ACK to the request that produced it.
//!
//! Unlike the `nfgenmsg` and attribute payloads, the `nlmsghdr` fields are host byte order,
//! as the kernel reads and writes them; only the fields described as `__be` in the wire
//! protocol are big-endian.
//!
//! Configuration requests wait for their `NLMSG_ERROR` ACK, so a failed `bind` or a
//! missing `CAP_NET_ADMIN` becomes an error at the call site instead of a queue that
//! silently never sees traffic. Verdicts are fire-and-forget: they are on the packet hot
//! path, and the kernel does not ACK them.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use log::{debug, info};

/// Size of `struct nlmsghdr`, included in `nlmsg_len`.
pub(crate) const NLMSG_HDRLEN: usize = 16;

/// Receive buffer size: 128 KiB, comfortably above a 64 KiB datagram plus its metadata,
/// so a queued packet that arrives mid-handshake is not truncated and lost.
pub(crate) const RECV_BUF_LEN: usize = 128 * 1024;

/// Receive buffer requested for a queue's netlink socket.
///
/// The kernel caps this at `net.core.rmem_max` (4 MiB on a stock box) and `getsockopt` reports the
/// value it was given, not the double it actually allocates. A queued packet costs ~768 bytes of socket
/// memory, so the kernel's 208 KiB default is a few hundred packets of headroom.
pub(crate) const RECV_BUFFER_BYTES: i32 = 4 * 1024 * 1024;

/// The kernel reports success and failure of a request through this message type.
pub(crate) const NLMSG_ERROR: u16 = 2;

/// `NLM_F_REQUEST`: the message is a request to the kernel.
pub(crate) const NLM_F_REQUEST: u16 = 1;

/// `NLM_F_ACK`: ask the kernel to answer with an `NLMSG_ERROR` carrying the result.
pub(crate) const NLM_F_ACK: u16 = 4;

/// A bound netlink socket plus its outgoing sequence counter.
pub struct NetlinkSocket {
   fd: OwnedFd,
   next_seq: u32,
   /// Datagrams received while waiting for an ACK that were not that ACK. A bound queue
   /// can deliver a packet before the ACK for a later config step arrives; dropping such
   /// a datagram would leave its packet id unverdicted in the kernel queue forever.
   deferred: VecDeque<Vec<u8>>,
}

impl NetlinkSocket {
   /// Opens a netlink socket for the netfilter subsystem and binds it to a kernel-chosen
   /// port id.
   pub fn open() -> io::Result<Self> {
      // SAFETY: `socket` is called with the constant arguments the kernel expects; the
      // returned descriptor is the only resource it creates, and it is checked for -1
      // before being adopted below.
      let raw = unsafe {
         libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW,
            libc::NETLINK_NETFILTER,
         )
      };
      if raw < 0 {
         return Err(io::Error::last_os_error());
      }
      // SAFETY: `raw` is a fresh descriptor owned by this function (the check above
      // rejected -1), so transferring it into `OwnedFd` gives it exactly one owner, which
      // closes it on every later error path and on drop.
      let fd = unsafe { OwnedFd::from_raw_fd(raw) };

      // SAFETY: `sockaddr_nl` is a plain C struct whose only invalid state is an
      // uninitialised padding field; all-zero bytes are the documented `nl_pad`, and
      // `nl_pid = 0`, `nl_groups = 0` ask the kernel for a port id and no multicast
      // groups.
      let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
      addr.nl_family = libc::AF_NETLINK as u16;
      addr.nl_pid = 0;
      addr.nl_groups = 0;
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
      // A packet that will not fit in the socket's receive buffer is dropped and reported as
      // `ENOBUFS` on the next receive — that is the "No buffer space available" line a torrent client's
      // peer burst produces. The kernel's default buffer holds a few hundred packets; ask for what the
      // machine allows and log what was actually granted, because a kernel capped below the request is
      // the case where this silently does nothing. Not fatal: an unsized buffer is the behaviour this
      // replaces, and refusing to start a firewall over a socket-tuning hint would be worse.
      match set_receive_buffer(fd.as_raw_fd()) {
         Ok(effective) => info!(
            "netlink receive buffer: asked for {RECV_BUFFER_BYTES} bytes, kernel granted {effective}"
         ),
         Err(err) => debug!("could not size the netlink receive buffer: {err}"),
      }
      Ok(Self {
         fd,
         next_seq: 1,
         deferred: VecDeque::new(),
      })
   }

   /// Sends one message with `NLM_F_REQUEST | NLM_F_ACK` and blocks for its ACK.
   ///
   /// Returns the kernel's `-errno` as an [`io::Error`], so a missing capability surfaces
   /// as `EPERM` at the caller rather than as a queue that silently carries no traffic.
   pub fn request(&mut self, msg_type: u16, payload: &[u8]) -> io::Result<()> {
      let seq = self.next_seq;
      self.next_seq = self.next_seq.wrapping_add(1);
      let datagram = frame(msg_type, NLM_F_REQUEST | NLM_F_ACK, seq, payload);
      self.send_raw(&datagram)?;

      let mut buf = vec![0u8; RECV_BUF_LEN];
      loop {
         let n = self.recv_datagram(&mut buf)?;
         let mut carries_packet = false;
         for msg in MessageIter::new(&buf[..n]) {
            let msg = msg.map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            if msg.msg_type == NLMSG_ERROR {
               if msg.seq == seq {
                  return ack_status(msg.payload);
               }
               debug!(
                  "ignoring NLMSG_ERROR for sequence {}, expected {seq}",
                  msg.seq
               );
               continue;
            }
            // Anything else is a queued packet that arrived while the handshake was
            // still running; dropping it would leave its packet id unverdicted in the
            // kernel queue forever, so hand it to `NfQueue::recv`.
            carries_packet = true;
         }
         if carries_packet {
            self.deferred.push_back(buf[..n].to_vec());
         }
      }
   }

   /// Fire-and-forget send, with no ACK awaited (used for verdicts, which are on the hot
   /// path).
   pub fn send(&mut self, msg_type: u16, payload: &[u8]) -> io::Result<()> {
      let seq = self.next_seq;
      self.next_seq = self.next_seq.wrapping_add(1);
      let datagram = frame(msg_type, NLM_F_REQUEST, seq, payload);
      self.send_raw(&datagram)
   }

   /// One blocking recv into `buf`; returns the datagram length. Retries `EINTR`.
   pub fn recv_datagram(&self, buf: &mut [u8]) -> io::Result<usize> {
      loop {
         // SAFETY: the descriptor is owned by `self` and open, and `buf` is a live slice
         // whose pointer and length are handed to the kernel for writing only.
         let n = unsafe {
            libc::recv(
               self.fd.as_raw_fd(),
               buf.as_mut_ptr().cast(),
               buf.len(),
               0,
            )
         };
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

   /// Returns a datagram that was received while waiting for an ACK.
   pub(crate) fn take_deferred(&mut self) -> Option<Vec<u8>> {
      self.deferred.pop_front()
   }

   /// Bounds every later receive with `SO_RCVTIMEO`.
   ///
   /// The daemon loop is otherwise blocked in `recv` indefinitely, which would make it
   /// miss prompt deadlines, IPC requests and the SIGTERM flag. A timeout surfaces as
   /// `EAGAIN`/`EWOULDBLOCK` from `recv_datagram`, which the caller treats as "nothing
   /// happened, go around the loop". Passing a zero duration disables the timeout.
   pub fn set_recv_timeout(&self, timeout: std::time::Duration) -> io::Result<()> {
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

   fn send_raw(&self, datagram: &[u8]) -> io::Result<()> {
      // Netlink requires either a connected socket or an explicit destination; without
      // one `send` fails with EDESTADDRREQ. `nl_pid = 0` addresses the kernel.
      // SAFETY: `sockaddr_nl` is a plain C struct; all-zero bytes are its valid `nl_pad`,
      // and the kernel destination is `nl_pid = 0` with no multicast groups.
      let mut dest: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
      dest.nl_family = libc::AF_NETLINK as u16;
      dest.nl_pid = 0;
      dest.nl_groups = 0;
      loop {
         // SAFETY: the descriptor is owned by `self` and open; `datagram` is a live slice
         // read only for the duration of the call, and `dest` is a fully initialised
         // `sockaddr_nl` whose length is passed with it.
         let sent = unsafe {
            libc::sendto(
               self.fd.as_raw_fd(),
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
               "netlink datagram was only partially sent",
            ));
         }
         return Ok(());
      }
   }
}

/// The credentials the kernel recorded for a connected Unix socket's peer.
///
/// The pid is what lets the control socket check *which executable* is on the other end
/// (`/proc/<pid>/exe`), not merely which user: every process of the desktop user shares a
/// UID, so the uid alone cannot tell the configured GUI from any other program that user
/// happens to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
   /// The peer's process id when it connected; `0` when the kernel did not report one.
   pub pid: u32,
   /// The peer's user id when it connected.
   pub uid: u32,
}

/// Reads the peer's credentials from a connected Unix socket.
///
/// This lives beside the netlink transport because it is a raw `getsockopt` call and
/// `unsafe` is confined to this module tree; `std`'s `UnixStream::peer_cred` is still
/// unstable, so the daemon's control socket cannot authenticate peers without it.
///
/// `SO_PEERCRED` reports the credentials the peer held when it connected, not at the time
/// of the call, so a later setuid cannot launder an unauthorised connection.
pub fn peer_creds(fd: std::os::fd::RawFd) -> io::Result<PeerCred> {
   // SAFETY: `ucred` is a plain C struct with no invalid bit patterns; all-zero bytes are
   // a valid initial value that `getsockopt` overwrites.
   let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
   let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
   // SAFETY: the caller passes an open socket descriptor; `cred` is a live, correctly
   // sized `ucred` and `len` its length, both handed to the kernel for writing only.
   let got = unsafe {
      libc::getsockopt(
         fd,
         libc::SOL_SOCKET,
         libc::SO_PEERCRED,
         (&mut cred as *mut libc::ucred).cast(),
         &mut len,
      )
   };
   if got < 0 {
      return Err(io::Error::last_os_error());
   }
   if len as usize != std::mem::size_of::<libc::ucred>() {
      return Err(io::Error::new(
         io::ErrorKind::InvalidData,
         "SO_PEERCRED returned a credential of the wrong size",
      ));
   }
   Ok(PeerCred {
      pid: cred.pid as u32,
      uid: cred.uid,
   })
}

/// Reads only the peer's UID; a thin wrapper over [`peer_creds`] for callers that do not
/// need the pid.
pub fn peer_uid(fd: std::os::fd::RawFd) -> io::Result<u32> {
   Ok(peer_creds(fd)?.uid)
}

/// Asks for the largest receive buffer the kernel will grant, returning the effective size.
///
/// Split from [`NetlinkSocket::open`] and given a raw descriptor so a test can prove the option took
/// effect on a socket of its own, without a privileged queue.
fn set_receive_buffer(raw: libc::c_int) -> io::Result<i32> {
   let size = RECV_BUFFER_BYTES;
   // SAFETY: `raw` is a descriptor the caller owns and keeps open for the call; the option value is a
   // live `c_int` whose address is valid for the call, and the kernel only reads it.
   let set = unsafe {
      libc::setsockopt(
         raw,
         libc::SOL_SOCKET,
         libc::SO_RCVBUF,
         (&size as *const libc::c_int).cast(),
         std::mem::size_of::<libc::c_int>() as libc::socklen_t,
      )
   };
   if set < 0 {
      return Err(io::Error::last_os_error());
   }
   let mut effective: libc::c_int = 0;
   let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
   // SAFETY: `raw` is the same live descriptor, and `effective`/`len` are a `c_int` and its size that
   // the kernel writes into; both outlive the call.
   let got = unsafe {
      libc::getsockopt(
         raw,
         libc::SOL_SOCKET,
         libc::SO_RCVBUF,
         (&mut effective as *mut libc::c_int).cast(),
         &mut len,
      )
   };
   if got < 0 {
      return Err(io::Error::last_os_error());
   }
   Ok(effective)
}

/// Builds one netlink datagram: header, then the caller's payload.
pub(crate) fn frame(msg_type: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
   let len = NLMSG_HDRLEN + payload.len();
   let mut datagram = Vec::with_capacity(len);
   datagram.extend_from_slice(&(len as u32).to_ne_bytes());
   datagram.extend_from_slice(&msg_type.to_ne_bytes());
   datagram.extend_from_slice(&flags.to_ne_bytes());
   datagram.extend_from_slice(&seq.to_ne_bytes());
   datagram.extend_from_slice(&0u32.to_ne_bytes()); // nl_pid: the kernel fills in the sender
   datagram.extend_from_slice(payload);
   datagram
}

/// Decodes the `NLMSG_ERROR` body into the kernel's answer.
///
/// A zero error means the request succeeded; a negative one is `-errno` and is returned as
/// that OS error, which is how `EPERM` reaches the caller.
pub(crate) fn ack_status(payload: &[u8]) -> io::Result<()> {
   if payload.len() < 4 {
      return Err(io::Error::new(
         io::ErrorKind::InvalidData,
         "NLMSG_ERROR is shorter than its error field",
      ));
   }
   let error = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
   if error == 0 {
      return Ok(());
   }
   if error < 0 {
      return Err(io::Error::from_raw_os_error(-error));
   }
   Err(io::Error::new(
      io::ErrorKind::InvalidData,
      format!("NLMSG_ERROR carried a positive error code {error}"),
   ))
}

/// Why one netlink message inside a datagram could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgError {
   /// The datagram ends before the message it announces.
   Truncated,
   /// `nlmsg_len` is smaller than the 16-byte header, so it cannot be advanced past.
   BadLength,
}

impl std::fmt::Display for MsgError {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self {
         Self::Truncated => f.write_str("truncated netlink message"),
         Self::BadLength => f.write_str("netlink message length below its 16-byte header"),
      }
   }
}

impl std::error::Error for MsgError {}

/// One message borrowed from a received datagram.
#[derive(Debug)]
pub struct Message<'a> {
   pub msg_type: u16,
   pub flags: u16,
   pub payload: &'a [u8],
   /// The sequence number in the header; an ACK echoes the request's.
   pub(crate) seq: u32,
}

/// Splits the `nlmsghdrs` packed into one received datagram.
///
/// A malformed message ends the iteration: after a bad length there is no trustworthy
/// place for the next header to begin.
pub struct MessageIter<'a> {
   datagram: &'a [u8],
   offset: usize,
   done: bool,
}

impl<'a> MessageIter<'a> {
   pub fn new(datagram: &'a [u8]) -> Self {
      Self {
         datagram,
         offset: 0,
         done: false,
      }
   }
}

impl<'a> Iterator for MessageIter<'a> {
   type Item = Result<Message<'a>, MsgError>;

   fn next(&mut self) -> Option<Self::Item> {
      if self.done || self.offset >= self.datagram.len() {
         return None;
      }
      let rest = &self.datagram[self.offset..];
      if rest.len() < NLMSG_HDRLEN {
         self.done = true;
         return Some(Err(MsgError::Truncated));
      }
      let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
      if len < NLMSG_HDRLEN {
         self.done = true;
         return Some(Err(MsgError::BadLength));
      }
      if len > rest.len() {
         self.done = true;
         return Some(Err(MsgError::Truncated));
      }
      let msg_type = u16::from_ne_bytes([rest[4], rest[5]]);
      let flags = u16::from_ne_bytes([rest[6], rest[7]]);
      let seq = u32::from_ne_bytes([rest[8], rest[9], rest[10], rest[11]]);
      let payload = &rest[NLMSG_HDRLEN..len];
      // Inter-message padding is outside `nlmsg_len`; the final message may omit it.
      self.offset += (len + 3) & !3;
      Some(Ok(Message {
         msg_type,
         flags,
         payload,
         seq,
      }))
   }
}

/// The kernel's `nfgenmsg`, which prefixes every nfnetlink payload.
pub(crate) const NFGENMSG_LEN: usize = 4;

/// Builds an `nfgenmsg` for `family` and `res_id` (the queue number for queue messages).
pub(crate) fn nfgenmsg(family: u8, res_id: u16) -> [u8; NFGENMSG_LEN] {
   let id = res_id.to_be_bytes();
   [family, 0, id[0], id[1]]
}

#[cfg(test)]
mod tests {
   use super::*;

   fn header(len: usize, msg_type: u16, flags: u16, seq: u32) -> [u8; NLMSG_HDRLEN] {
      let mut hdr = [0u8; NLMSG_HDRLEN];
      hdr[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
      hdr[4..6].copy_from_slice(&msg_type.to_ne_bytes());
      hdr[6..8].copy_from_slice(&flags.to_ne_bytes());
      hdr[8..12].copy_from_slice(&seq.to_ne_bytes());
      hdr
   }

   #[test]
   fn splits_a_two_message_datagram() {
      let mut datagram = Vec::new();
      datagram.extend_from_slice(&header(20, 0x0300, 0, 7));
      datagram.extend_from_slice(b"abcd");
      datagram.extend_from_slice(&header(19, 0x0301, 1, 8));
      datagram.extend_from_slice(b"xyz");
      datagram.push(0); // the final message's padding is allowed to be present

      let msgs = MessageIter::new(&datagram).collect::<Result<Vec<_>, _>>().unwrap();
      assert_eq!(msgs.len(), 2);
      assert_eq!((msgs[0].msg_type, msgs[0].flags), (0x0300, 0));
      assert_eq!(msgs[0].payload, b"abcd");
      assert_eq!(msgs[0].seq, 7);
      assert_eq!((msgs[1].msg_type, msgs[1].flags), (0x0301, 1));
      assert_eq!(msgs[1].payload, b"xyz");
      assert_eq!(msgs[1].seq, 8);
   }

   #[test]
   fn a_malformed_datagram_is_an_error() {
      // A length past the end of the buffer is `Truncated`.
      let datagram = header(64, 0x0300, 0, 1);
      let result: Vec<_> = MessageIter::new(&datagram).collect();
      assert_eq!(result.len(), 1);
      assert_eq!(
         result[0].as_ref().unwrap_err(),
         &MsgError::Truncated
      );

      // A zero length is `BadLength`.
      let datagram = header(0, 0x0300, 0, 1);
      let result: Vec<_> = MessageIter::new(&datagram).collect();
      assert_eq!(result.len(), 1);
      assert_eq!(
         result[0].as_ref().unwrap_err(),
         &MsgError::BadLength
      );

      // An empty datagram holds no message at all.
      assert_eq!(MessageIter::new(&[]).count(), 0);
   }

   #[test]
   fn an_ack_reports_success_and_eperm() {
      let payload = (-1i32).to_ne_bytes();
      let err = ack_status(&payload).unwrap_err();
      assert_eq!(err.raw_os_error(), Some(libc::EPERM));
      assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

      // The same error is reachable through the message iterator, matching the seq.
      let datagram = frame(NLMSG_ERROR, 0, 5, &(-1i32).to_ne_bytes());
      let msg = MessageIter::new(&datagram).next().unwrap().unwrap();
      assert_eq!(msg.msg_type, NLMSG_ERROR);
      assert_eq!(msg.seq, 5);
      assert_eq!(
         ack_status(msg.payload).unwrap_err().raw_os_error(),
         Some(libc::EPERM)
      );

      // Zero is success.
      assert!(ack_status(&0i32.to_ne_bytes()).is_ok());
   }

   #[test]
   fn frame_carries_the_documented_header() {
      let datagram = frame(0x0302, NLM_F_REQUEST | NLM_F_ACK, 9, &[1, 2, 3]);
      assert_eq!(datagram.len(), NLMSG_HDRLEN + 3);
      assert_eq!(
         u32::from_ne_bytes(datagram[0..4].try_into().unwrap()),
         19
      );
      assert_eq!(
         u16::from_ne_bytes(datagram[4..6].try_into().unwrap()),
         0x0302
      );
      assert_eq!(
         u16::from_ne_bytes(datagram[6..8].try_into().unwrap()),
         5
      );
      assert_eq!(
         u32::from_ne_bytes(datagram[8..12].try_into().unwrap()),
         9
      );
      assert_eq!(
         u32::from_ne_bytes(datagram[12..16].try_into().unwrap()),
         0
      );
      assert_eq!(&datagram[16..], &[1, 2, 3]);
   }

   /// The receive buffer a queue's socket ends up with must be the one the box can grant, not the
   /// kernel default — the default holds a few hundred queued packets and a peer burst overflows it.
   #[test]
   fn the_netlink_receive_buffer_is_raised_above_the_default() {
      // A bare netlink socket: `setsockopt` needs no privilege and this never joins a queue.
      // SAFETY: constant arguments; the descriptor is the only resource created and is checked.
      let raw = unsafe {
         libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW,
            libc::NETLINK_NETFILTER,
         )
      };
      assert!(
         raw >= 0,
         "a netlink socket must open unprivileged"
      );
      // SAFETY: `raw` is the live descriptor above; the kernel only writes the two out-parameters.
      let mut default_size: libc::c_int = 0;
      let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
      let read = unsafe {
         libc::getsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&mut default_size as *mut libc::c_int).cast(),
            &mut len,
         )
      };
      assert_eq!(
         read, 0,
         "reading the default receive buffer must succeed"
      );

      let effective = set_receive_buffer(raw).expect("the option must be applied");
      assert!(
         effective > default_size,
         "asked for {RECV_BUFFER_BYTES}, the default was {default_size}, got {effective}"
      );

      // SAFETY: `raw` is still owned here and closed exactly once.
      unsafe { libc::close(raw) };
   }
}
