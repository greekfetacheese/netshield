//! Deleting the conntrack entries of an app, so its next packet is a new flow again.
//!
//! The nftables output hook only queues a *new* flow; once the kernel has a conntrack
//! entry for a connection, later packets never reach the daemon, so a policy change cannot
//! touch traffic that is already running. The fix is to stamp every entry with its owner
//! (see [`crate::firewall::ruleset_text`]) and delete the stamped entries when the owner's
//! policy changes. This module speaks ctnetlink directly: the delete is one `nfgenmsg`
//! plus two attributes per address family, which needs no C library.
//!
//! The tag in [`OWNER_TAG`] is what makes a flush safe. Docker and Kubernetes write their
//! own conntrack marks, so a flush of "everything" would delete their flows; every mark
//! NetShield writes has the top bits set to `01`, and the flush masks exactly those bits.
//!
//! The netlink header and acknowledgement handling are shared with the queue transport in
//! [`crate::netlink::socket`]; the raw syscalls this module makes itself are the four that
//! create, bind, send on and receive from the socket, each with the invariant that makes
//! it sound.

use std::cell::Cell;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::firewall::{OWNER_TAG, OWNER_TAG_MASK};
use crate::netlink::socket::{
   MessageIter, NLM_F_ACK, NLM_F_REQUEST, NLMSG_ERROR, ack_status, frame,
};

/// The netfilter netlink protocol, as passed to `socket(2)`.
const NETLINK_NETFILTER: i32 = 12;
/// The ctnetlink subsystem, in the high byte of `nlmsghdr.nlmsg_type`.
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
/// The delete message of that subsystem.
const IPCTNL_MSG_CT_DELETE: u16 = 2;
/// The conntrack mark attribute.
const CTA_MARK: u16 = 8;
/// The mask applied to that mark when matching entries.
const CTA_MARK_MASK: u16 = 19;

/// `(NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE`.
const DELETE_MSG_TYPE: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE;

/// Size of `struct nfgenmsg`, which prefixes every nfnetlink payload.
const NFGENMSG_LEN: usize = 4;
/// Size of `struct nlattr`'s header, which the attribute length includes.
const ATTR_HDR_LEN: usize = 4;
/// A `u32` attribute: the 4-byte header plus its 4-byte payload.
const ATTR_U32_LEN: usize = ATTR_HDR_LEN + 4;
/// Enough for an `NLMSG_ERROR` acknowledgement and its echoed header.
const ACK_BUF_LEN: usize = 4096;

/// The kernel's `nfgenmsg`, which starts every nfnetlink payload.
#[repr(C)]
struct NfGenMsg {
   family: u8,
   version: u8,
   res_id: u16,
}

impl NfGenMsg {
   /// Serialises the struct: family and version are bytes, `res_id` is network order.
   fn bytes(family: u8) -> [u8; NFGENMSG_LEN] {
      let message = Self {
         family,
         version: 0,
         res_id: 0,
      };
      let mut bytes = [0u8; NFGENMSG_LEN];
      bytes[0] = message.family;
      bytes[1] = message.version;
      bytes[2..].copy_from_slice(&message.res_id.to_be_bytes());
      bytes
   }
}

/// The header of an `nlattr`; the length includes this header and its payload.
#[repr(C)]
struct NlAttrHeader {
   length: u16,
   kind: u16,
}

/// The address family of one flush, reported back so the caller can log it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
   Ipv4,
   Ipv6,
}

impl Family {
   /// Both families, in the order the daemon flushes them.
   const ALL: [Self; 2] = [Self::Ipv4, Self::Ipv6];

   /// The `nfgenmsg.family` / `AF_*` value this family is sent with.
   fn interface(self) -> u8 {
      match self {
         Self::Ipv4 => libc::AF_INET as u8,
         Self::Ipv6 => libc::AF_INET6 as u8,
      }
   }
}

impl fmt::Display for Family {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(match self {
         Self::Ipv4 => "ipv4",
         Self::Ipv6 => "ipv6",
      })
   }
}

/// Why a conntrack flush failed.
#[derive(Debug)]
pub enum ConntrackError {
   /// The ctnetlink socket could not be created or bound.
   Socket(io::Error),
   /// A delete could not be sent, or its acknowledgement could not be read.
   Netlink { family: Family, source: io::Error },
   /// The kernel answered the delete with a non-zero error; `errno` is its positive form.
   Kernel { family: Family, errno: i32 },
   /// The uid cannot be tagged without colliding with another owner's mark.
   UidOutOfRange(u32),
}

impl fmt::Display for ConntrackError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Socket(err) => write!(f, "could not open the ctnetlink socket: {err}"),
         Self::Netlink { family, source } => {
            write!(
               f,
               "the {family} conntrack delete failed: {source}"
            )
         }
         Self::Kernel { family, errno } => write!(
            f,
            "the kernel rejected the {family} conntrack delete: {}",
            io::Error::from_raw_os_error(*errno)
         ),
         Self::UidOutOfRange(uid) => write!(
            f,
            "uid {uid} sets one of the two top bits NetShield reserves for its conntrack tag"
         ),
      }
   }
}

impl std::error::Error for ConntrackError {
   fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
      match self {
         Self::Socket(err) => Some(err),
         Self::Netlink { source, .. } => Some(source),
         Self::Kernel { .. } | Self::UidOutOfRange(_) => None,
      }
   }
}

/// Deletes the conntrack entries of an app, so its next packet is a new flow again.
pub struct Conntrack {
   socket: OwnedFd,
   sequence: Cell<u32>,
}

impl Conntrack {
   /// Opens a bound ctnetlink socket. The first request will fail with `EPERM` when the
   /// caller lacks `CAP_NET_ADMIN`; opening the socket itself does not need it.
   pub fn open() -> Result<Self, ConntrackError> {
      // SAFETY: `socket` is called with the constant arguments the netfilter protocol
      // expects; the returned descriptor is the only resource it creates, and it is
      // checked for -1 before being adopted below.
      let raw = unsafe {
         libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW,
            NETLINK_NETFILTER,
         )
      };
      if raw < 0 {
         return Err(ConntrackError::Socket(io::Error::last_os_error()));
      }
      // SAFETY: `raw` is a fresh descriptor owned by this function (the check above
      // rejected -1), so transferring it into `OwnedFd` gives it exactly one owner, which
      // closes it on every later error path and on drop.
      let socket = unsafe { OwnedFd::from_raw_fd(raw) };

      // SAFETY: `sockaddr_nl` is a plain C struct whose only invalid state is an
      // uninitialised padding field; all-zero bytes are the documented `nl_pad`, and
      // `nl_pid = 0`, `nl_groups = 0` ask the kernel for a port id and no multicast.
      let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
      address.nl_family = libc::AF_NETLINK as u16;
      address.nl_pid = 0;
      address.nl_groups = 0;
      // SAFETY: the descriptor is owned by `self` and open; `address` is a fully
      // initialised `sockaddr_nl` and its own size is passed with it, and the kernel only
      // reads it for the duration of the call.
      let bound = unsafe {
         libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
         )
      };
      if bound < 0 {
         return Err(ConntrackError::Socket(io::Error::last_os_error()));
      }
      Ok(Self {
         socket,
         sequence: Cell::new(1),
      })
   }

   /// Deletes every entry owned by `uid`. Returns the families that were flushed, for the
   /// log line.
   pub fn revoke_uid(&mut self, uid: u32) -> Result<Vec<Family>, ConntrackError> {
      let mark = owner_mark(uid)?;
      self.delete(mark, u32::MAX)
   }

   /// Deletes every entry this daemon stamped, whoever owns it. Used at startup: the daemon
   /// has no knowledge of flows that were established while it was not running, and
   /// leaving them alive would be a permanent hole.
   pub fn revoke_all(&mut self) -> Result<Vec<Family>, ConntrackError> {
      self.delete(OWNER_TAG, OWNER_TAG_MASK)
   }

   /// Sends one delete per family and waits for each acknowledgement.
   fn delete(&mut self, mark: u32, mask: u32) -> Result<Vec<Family>, ConntrackError> {
      let mut flushed = Vec::with_capacity(Family::ALL.len());
      for family in Family::ALL {
         let sequence = self.next_sequence();
         let message = delete_message(family.interface(), mark, mask, sequence);
         self
            .send(&message)
            .map_err(|source| ConntrackError::Netlink { family, source })?;
         self.await_ack(family, sequence)?;
         flushed.push(family);
      }
      Ok(flushed)
   }

   /// The sequence number of the next request, wrapping rather than overflowing.
   fn next_sequence(&self) -> u32 {
      let sequence = self.sequence.get();
      self.sequence.set(sequence.wrapping_add(1));
      sequence
   }

   /// Sends one datagram to the kernel.
   fn send(&self, message: &[u8]) -> io::Result<()> {
      // Netlink requires either a connected socket or an explicit destination; without
      // one `send` fails with EDESTADDRREQ. `nl_pid = 0` addresses the kernel.
      // SAFETY: `sockaddr_nl` is a plain C struct; all-zero bytes are its valid `nl_pad`,
      // and the kernel destination is `nl_pid = 0` with no multicast groups.
      let mut destination: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
      destination.nl_family = libc::AF_NETLINK as u16;
      destination.nl_pid = 0;
      destination.nl_groups = 0;
      loop {
         // SAFETY: the descriptor is owned by `self` and open; `message` is a live slice
         // read only for the duration of the call, and `destination` is a fully
         // initialised `sockaddr_nl` whose size is passed with it.
         let sent = unsafe {
            libc::sendto(
               self.socket.as_raw_fd(),
               message.as_ptr().cast(),
               message.len(),
               0,
               (&destination as *const libc::sockaddr_nl).cast(),
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
         if sent as usize != message.len() {
            return Err(io::Error::new(
               io::ErrorKind::WriteZero,
               "ctnetlink datagram was only partially sent",
            ));
         }
         return Ok(());
      }
   }

   /// Blocks until the `NLMSG_ERROR` carrying `sequence` arrives.
   ///
   /// A non-zero `error` field is a failure with that errno, never a silent success: a
   /// flush that the kernel refused must reach the caller.
   fn await_ack(&self, family: Family, sequence: u32) -> Result<(), ConntrackError> {
      let mut buffer = [0u8; ACK_BUF_LEN];
      loop {
         // SAFETY: the descriptor is owned by `self` and open, and `buffer` is a live
         // array whose pointer and length are handed to the kernel for writing only.
         let received = unsafe {
            libc::recv(
               self.socket.as_raw_fd(),
               buffer.as_mut_ptr().cast(),
               buffer.len(),
               0,
            )
         };
         if received < 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
               continue;
            }
            return Err(ConntrackError::Netlink { family, source });
         }
         for message in MessageIter::new(&buffer[..received as usize]) {
            let message = message.map_err(|err| ConntrackError::Netlink {
               family,
               source: io::Error::new(io::ErrorKind::InvalidData, err),
            })?;
            if message.msg_type != NLMSG_ERROR || message.seq != sequence {
               continue;
            }
            return match ack_status(message.payload) {
               Ok(()) => Ok(()),
               Err(source) => Err(match source.raw_os_error() {
                  Some(errno) => ConntrackError::Kernel { family, errno },
                  None => ConntrackError::Netlink { family, source },
               }),
            };
         }
      }
   }
}

/// The mark NetShield writes for `uid`, or an error when the uid would escape the tag.
///
/// A uid with either of the tag's two top bits set cannot be encoded: OR-ing the tag would
/// leave a value that alias a smaller uid (uid `0x4000_0001` would be indistinguishable
/// from uid 1) or fall outside the tag space entirely. Refusing keeps a flush from ever
/// deleting another owner's flows; Linux uids that large do not occur in practice.
fn owner_mark(uid: u32) -> Result<u32, ConntrackError> {
   if uid & OWNER_TAG_MASK != 0 {
      return Err(ConntrackError::UidOutOfRange(uid));
   }
   Ok(OWNER_TAG | uid)
}

/// Builds one ctnetlink delete: `nlmsghdr`, `nfgenmsg`, `CTA_MARK`, `CTA_MARK_MASK`.
///
/// Split out from the socket so the exact wire bytes are unit-tested without
/// `CAP_NET_ADMIN`. `mark` and `mask` are network order, since the kernel declares them
/// `__be32`; the header fields are host order, like every other `nlmsghdr`.
fn delete_message(family: u8, mark: u32, mask: u32, sequence: u32) -> Vec<u8> {
   let mut payload = Vec::with_capacity(NFGENMSG_LEN + 2 * ATTR_U32_LEN);
   payload.extend_from_slice(&NfGenMsg::bytes(family));
   push_u32_attr(&mut payload, CTA_MARK, mark);
   push_u32_attr(&mut payload, CTA_MARK_MASK, mask);
   frame(
      DELETE_MSG_TYPE,
      NLM_F_REQUEST | NLM_F_ACK,
      sequence,
      &payload,
   )
}

/// Appends one `u32` attribute, network order, with no padding needed for a 4-byte payload.
fn push_u32_attr(buffer: &mut Vec<u8>, kind: u16, value: u32) {
   let header = NlAttrHeader {
      length: ATTR_U32_LEN as u16,
      kind,
   };
   buffer.extend_from_slice(&header.length.to_ne_bytes());
   buffer.extend_from_slice(&header.kind.to_ne_bytes());
   buffer.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
   use std::os::unix::process::CommandExt;
   use std::path::Path;
   use std::process::{Child, Command};
   use std::time::{Duration, Instant};

   use super::*;

   #[test]
   fn the_delete_message_carries_the_owner() {
      let message = delete_message(libc::AF_INET as u8, OWNER_TAG | 1000, u32::MAX, 7);
      assert_eq!(message.len(), 36);
      assert_eq!(
         u32::from_ne_bytes(message[0..4].try_into().unwrap()),
         36
      );
      assert_eq!(
         u16::from_ne_bytes(message[4..6].try_into().unwrap()),
         (1 << 8) | 2
      );
      assert_eq!(
         u16::from_ne_bytes(message[6..8].try_into().unwrap()),
         1 | 4
      );
      assert_eq!(
         u32::from_ne_bytes(message[8..12].try_into().unwrap()),
         7
      );
      assert_eq!(message[16], libc::AF_INET as u8);
      assert_eq!(message[17], 0);
      assert_eq!(&message[18..20], &[0, 0]);
      assert_eq!(
         u16::from_ne_bytes(message[20..22].try_into().unwrap()),
         8
      );
      assert_eq!(
         u16::from_ne_bytes(message[22..24].try_into().unwrap()),
         CTA_MARK
      );
      assert_eq!(&message[24..28], &0x4000_03e8u32.to_be_bytes());
      assert_eq!(
         u16::from_ne_bytes(message[28..30].try_into().unwrap()),
         8
      );
      assert_eq!(
         u16::from_ne_bytes(message[30..32].try_into().unwrap()),
         CTA_MARK_MASK
      );
      assert_eq!(&message[32..36], &u32::MAX.to_be_bytes());
   }

   #[test]
   fn the_tag_keeps_another_tools_mark_out() {
      fn matches((mark, mask): (u32, u32), candidate: u32) -> bool {
         candidate & mask == mark
      }

      let revoke_all = (OWNER_TAG, OWNER_TAG_MASK);
      assert_eq!(revoke_all, (0x4000_0000, 0xc000_0000));
      for foreign in [0x0000_0000, 0x1000_0000] {
         assert!(
            !matches(revoke_all, foreign),
            "revoke_all must not match another tool's mark {foreign:#010x}"
         );
      }

      let uid_1000 = (
         owner_mark(1000).expect("uid 1000 is encodable"),
         u32::MAX,
      );
      let uid_1001 = (
         owner_mark(1001).expect("uid 1001 is encodable"),
         u32::MAX,
      );
      assert_eq!(uid_1000.0, 0x4000_03e8);
      assert_eq!(uid_1001.0, 0x4000_03e9);
      assert!(matches(revoke_all, uid_1000.0));
      assert!(
         !matches(uid_1001, uid_1000.0),
         "revoking uid 1001 must not match uid 1000's entry"
      );
      assert!(!matches(uid_1000, uid_1001.0));
   }

   #[test]
   fn a_uid_that_would_collide_with_the_tag_is_handled() {
      // A uid may set either of the tag's two top bits. OR-ing the tag would then alias a
      // smaller uid (`0x4000_0001` looks exactly like uid 1) or leave the tag space, so
      // the encoder refuses rather than deleting another owner's flows. Linux uids that
      // large do not exist in practice; refusing is the fail-loud behaviour.
      assert!(matches!(
         owner_mark(0x4000_0000),
         Err(ConntrackError::UidOutOfRange(0x4000_0000))
      ));
      assert!(matches!(
         owner_mark(u32::MAX),
         Err(ConntrackError::UidOutOfRange(u32::MAX))
      ));
      assert_eq!(
         owner_mark(0x3fff_ffff).expect("the largest encodable uid"),
         0x7fff_ffff
      );
      assert_eq!(
         owner_mark(1000).expect("uid 1000 is encodable"),
         0x4000_03e8
      );
   }

   /// The live test below needs root, the installed nft rule and a loaded nf_conntrack.
   #[test]
   #[ignore = "needs root, CAP_NET_ADMIN, the installed nft rule and /proc/net/nf_conntrack"]
   fn an_established_flow_is_flushed() {
      if !is_root() {
         eprintln!("skipping: must run as root (CAP_NET_ADMIN is required)");
         return;
      }
      if !Path::new("/proc/net/nf_conntrack").exists() {
         eprintln!("skipping: /proc/net/nf_conntrack is unavailable; is nf_conntrack loaded?");
         return;
      }
      let Some(chain) = nft_output_chain() else {
         eprintln!("skipping: table inet netshield is not installed; run netshieldd first");
         return;
      };
      if !chain.contains("record the owner") && !add_stamp_rule() {
         eprintln!("skipping: the owner-stamping rule is neither installed nor addable");
         return;
      }

      // uid 1000, because the flush is per owner and root's own flow would be marked as
      // uid 0. `sleep` keeps the connection's descriptor open while the entry is checked.
      let _client = ChildGuard(
         Command::new("bash")
            .args(["-c", "exec 3<>/dev/tcp/1.1.1.1/443; sleep 10"])
            .uid(1000)
            .spawn()
            .expect("spawn a uid-1000 client"),
      );

      let expected = OWNER_TAG | 1000;
      let deadline = Instant::now() + Duration::from_secs(10);
      while Instant::now() < deadline && !conntrack_marks().contains(&expected) {
         std::thread::sleep(Duration::from_millis(100));
      }
      assert!(
         conntrack_marks().contains(&expected),
         "the established flow must appear in /proc/net/nf_conntrack with mark {expected:#010x}"
      );

      let mut conntrack = Conntrack::open().expect("open ctnetlink");
      assert_eq!(
         conntrack.revoke_uid(1000).expect("flush uid 1000"),
         [Family::Ipv4, Family::Ipv6]
      );
      let deadline = Instant::now() + Duration::from_secs(5);
      while Instant::now() < deadline && conntrack_marks().contains(&expected) {
         std::thread::sleep(Duration::from_millis(100));
      }
      assert!(
         !conntrack_marks().contains(&expected),
         "the flushed flow must be gone from /proc/net/nf_conntrack"
      );

      // The second call has nothing left to delete and must still succeed.
      assert_eq!(
         conntrack.revoke_uid(1000).expect("a second flush is a no-op"),
         [Family::Ipv4, Family::Ipv6]
      );
      assert!(!conntrack_marks().contains(&expected));
   }

   /// The effective uid from `/proc/self/status`, so the live test need not call `geteuid`.
   fn is_root() -> bool {
      std::fs::read_to_string("/proc/self/status").ok().and_then(|status| {
         status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|fields| fields.split_whitespace().nth(1))
            .and_then(|uid| uid.parse::<u32>().ok())
      }) == Some(0)
   }

   /// `nft list chain inet netshield output`, or `None` when the table is not installed.
   fn nft_output_chain() -> Option<String> {
      let output = Command::new("nft")
         .args(["list", "chain", "inet", "netshield", "output"])
         .output()
         .ok()?;
      output
         .status
         .success()
         .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
   }

   /// Adds the stamping rule to an already-installed table, so the test can run without a
   /// daemon restart. The quoting is nft's, not the shell's: no shell is involved.
   fn add_stamp_rule() -> bool {
      Command::new("nft")
         .args([
            "add",
            "rule",
            "inet",
            "netshield",
            "output",
            "ct",
            "state",
            "new",
            "ct",
            "mark",
            "set",
            "meta",
            "skuid",
            "|",
            "0x40000000",
            "comment",
            "\"netshield: record the owner\"",
         ])
         .status()
         .map(|status| status.success())
         .unwrap_or(false)
   }

   /// Every conntrack mark in `/proc/net/nf_conntrack`, in either radix the kernel uses.
   fn conntrack_marks() -> Vec<u32> {
      let Ok(text) = std::fs::read_to_string("/proc/net/nf_conntrack") else {
         return Vec::new();
      };
      text
         .lines()
         .flat_map(|line| line.split_whitespace())
         .filter_map(|token| token.strip_prefix("mark="))
         .filter_map(|value| match value.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16).ok(),
            None => value.parse().ok(),
         })
         .collect()
   }

   /// Kills the test's client on every exit path, including a failed assertion.
   struct ChildGuard(Child);

   impl Drop for ChildGuard {
      fn drop(&mut self) {
         let _ = self.0.kill();
         let _ = self.0.wait();
      }
   }
}
