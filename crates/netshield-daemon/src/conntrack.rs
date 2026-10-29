//! Listing and killing the conntrack flows of an app, so an already-running connection
//! can be revoked.
//!
//! The nftables output hook only queues a *new* flow; once the kernel has a conntrack
//! entry for a connection, later packets never reach the daemon, so a policy change cannot
//! touch traffic that is already running. Deleting the entry is not enough: measured, the
//! connection keeps working, because both endpoints still hold their sockets and the next
//! packet makes a fresh entry. What ends the connection is rejecting its exact tuple in
//! the firewall for as long as the policy requires; [`Conntrack::established_flows`] is
//! what enumerates the tuples to reject.
//!
//! The tag in [`OWNER_TAG`] is what makes a flush safe. Docker and Kubernetes write their
//! own conntrack marks, so a flush of "everything" would delete their flows; every mark
//! NetShield writes has the top bits set to `01`, and the flush masks exactly those bits.
//! The dump uses the same mark filter, so it lists only this daemon's entries.
//!
//! The netlink header and acknowledgement handling are shared with the queue transport in
//! [`crate::netlink::socket`]; the raw syscalls this module makes itself are the four that
//! create, bind, send on and receive from the socket, each with the invariant that makes
//! it sound.

use std::cell::Cell;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use log::debug;

use crate::firewall::{OWNER_TAG, OWNER_TAG_MASK};
use crate::netlink::attrs::AttrReader;
use crate::netlink::socket::{
   MessageIter, NLM_F_ACK, NLM_F_REQUEST, NLMSG_ERROR, RECV_BUF_LEN, ack_status, frame,
};

/// The netfilter netlink protocol, as passed to `socket(2)`.
const NETLINK_NETFILTER: i32 = 12;
/// The ctnetlink subsystem, in the high byte of `nlmsghdr.nlmsg_type`.
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
/// The delete message of that subsystem.
const IPCTNL_MSG_CT_DELETE: u16 = 2;
/// The dump request of that subsystem.
const IPCTNL_MSG_CT_GET: u16 = 1;
/// A conntrack entry inside a dump reply.
const IPCTNL_MSG_CT_NEW: u16 = 0;
/// The conntrack mark attribute.
const CTA_MARK: u16 = 8;
/// The mask applied to that mark when matching entries.
const CTA_MARK_MASK: u16 = 19;

/// `(NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE`.
const DELETE_MSG_TYPE: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE;
/// `(NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET`.
const DUMP_MSG_TYPE: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
/// `(NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW`.
const ENTRY_MSG_TYPE: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;

/// `NLM_F_ROOT`: the dump starts at the first entry.
const NLM_F_ROOT: u16 = 0x100;
/// `NLM_F_MATCH`: the kernel returns every matching entry.
const NLM_F_MATCH: u16 = 0x200;
/// `NLM_F_ROOT | NLM_F_MATCH`, the flag pair a dump request carries.
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
/// The last message of a multipart dump reply.
const NLMSG_DONE: u16 = 3;

/// The original-direction tuple of a conntrack entry.
const CTA_TUPLE_ORIG: u16 = 1;
/// The address pair inside that tuple.
const CTA_TUPLE_IP: u16 = 1;
/// The protocol triple inside that tuple.
const CTA_TUPLE_PROTO: u16 = 2;
/// The IPv4 source address attribute.
const CTA_IP_V4_SRC: u16 = 1;
/// The IPv4 destination address attribute.
const CTA_IP_V4_DST: u16 = 2;
/// The IPv6 source address attribute.
const CTA_IP_V6_SRC: u16 = 3;
/// The IPv6 destination address attribute.
const CTA_IP_V6_DST: u16 = 4;
/// The protocol number attribute.
const CTA_PROTO_NUM: u16 = 1;
/// The source port attribute.
const CTA_PROTO_SRC_PORT: u16 = 2;
/// The destination port attribute.
const CTA_PROTO_DST_PORT: u16 = 3;
/// The bits of `nla_type` that carry flags; the attribute kind is the rest.
const NLA_TYPE_MASK: u16 = 0x3fff;

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

/// One tracked flow, in the shape the firewall's revoke sets need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
   /// Local address, local port, remote address, remote port.
   V4(Ipv4Addr, u16, Ipv4Addr, u16),
   /// Local address, local port, remote address, remote port.
   V6(Ipv6Addr, u16, Ipv6Addr, u16),
}

/// Which flows to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
   /// The flows whose conntrack mark names this uid.
   Uid(u32),
   /// Every flow this daemon ever stamped.
   All,
}

/// Why a conntrack request failed.
#[derive(Debug)]
pub enum ConntrackError {
   /// The ctnetlink socket could not be created or bound.
   Socket(io::Error),
   /// A request could not be sent, or its reply could not be read.
   Netlink { family: Family, source: io::Error },
   /// The kernel answered a request with a non-zero error; `errno` is its positive form.
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
               "the {family} conntrack request failed: {source}"
            )
         }
         Self::Kernel { family, errno } => write!(
            f,
            "the kernel rejected the {family} conntrack request: {}",
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

/// Deletes the conntrack entries of an app, and lists the flows they describe.
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

   /// The established flows of `owner`, as the tuples the revoke sets take.
   ///
   /// Both families are dumped, and an entry that does not parse is skipped rather than
   /// failing the whole dump: a partial list is still useful for killing the flows that
   /// are understood, and the count of the ones that were not is logged.
   pub fn established_flows(&mut self, owner: Owner) -> Result<Vec<Flow>, ConntrackError> {
      let (mark, mask) = match owner {
         Owner::Uid(uid) => (owner_mark(uid)?, u32::MAX),
         Owner::All => (OWNER_TAG, OWNER_TAG_MASK),
      };
      let mut flows = Vec::new();
      let mut skipped = 0usize;
      for family in Family::ALL {
         let sequence = self.next_sequence();
         let message = dump_message(family.interface(), mark, mask, sequence);
         self
            .send(&message)
            .map_err(|source| ConntrackError::Netlink { family, source })?;
         self.read_dump(family, sequence, &mut flows, &mut skipped)?;
      }
      if skipped > 0 {
         debug!("skipped {skipped} conntrack entries whose tuple did not parse");
      }
      Ok(flows)
   }

   /// Reads one family's dump reply until `NLMSG_DONE`, collecting every parsed flow.
   ///
   /// A message that is not part of the dump (`NLMSG_ERROR` with a zero length, a
   /// stray packet) is ignored; a kernel error is not, so a refused dump cannot look
   /// like an empty one.
   fn read_dump(
      &mut self,
      family: Family,
      sequence: u32,
      flows: &mut Vec<Flow>,
      skipped: &mut usize,
   ) -> Result<(), ConntrackError> {
      let mut buffer = vec![0u8; RECV_BUF_LEN];
      loop {
         // SAFETY: the descriptor is owned by `self` and open, and `buffer` is a live
         // allocation whose pointer and length are handed to the kernel for writing only.
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
            if message.seq != sequence {
               continue;
            }
            match message.msg_type {
               NLMSG_DONE => return Ok(()),
               NLMSG_ERROR => match ack_status(message.payload) {
                  // A dump acknowledges the request before it streams the entries;
                  // only a real error ends it.
                  Ok(()) => continue,
                  Err(source) => {
                     return Err(match source.raw_os_error() {
                        Some(errno) => ConntrackError::Kernel { family, errno },
                        None => ConntrackError::Netlink { family, source },
                     });
                  }
               },
               ENTRY_MSG_TYPE => match parse_entry(message.payload) {
                  Some(flow) => flows.push(flow),
                  None => *skipped += 1,
               },
               _ => {}
            }
         }
      }
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

/// Builds one ctnetlink dump request: `nlmsghdr`, `nfgenmsg`, `CTA_MARK`,
/// `CTA_MARK_MASK`, with `NLM_F_DUMP` so the kernel streams every matching entry.
///
/// Split out from the socket so the exact wire bytes are unit-tested without
/// `CAP_NET_ADMIN`. The flags are `NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH`, the pair
/// the kernel documents as `NLM_F_DUMP`.
fn dump_message(family: u8, mark: u32, mask: u32, sequence: u32) -> Vec<u8> {
   let mut payload = Vec::with_capacity(NFGENMSG_LEN + 2 * ATTR_U32_LEN);
   payload.extend_from_slice(&NfGenMsg::bytes(family));
   push_u32_attr(&mut payload, CTA_MARK, mark);
   push_u32_attr(&mut payload, CTA_MARK_MASK, mask);
   frame(
      DUMP_MSG_TYPE,
      NLM_F_REQUEST | NLM_F_DUMP,
      sequence,
      &payload,
   )
}

/// Parses one dumped conntrack entry into the tuple the revoke sets key on.
///
/// `None` means the entry is well-formed netlink but carries no usable original tuple:
/// a protocol other than TCP or UDP, a family that does not match the addresses, or a
/// missing attribute. The caller skips it; one odd entry must not discard the rest.
fn parse_entry(payload: &[u8]) -> Option<Flow> {
   let (family, attributes) = split_nfgenmsg(payload)?;
   let tuple = payload_of(attributes, CTA_TUPLE_ORIG)?;
   let ip = payload_of(tuple, CTA_TUPLE_IP)?;
   let proto = payload_of(tuple, CTA_TUPLE_PROTO)?;
   let protocol = be_protocol(payload_of(proto, CTA_PROTO_NUM)?)?;
   if protocol != libc::IPPROTO_TCP as u8 && protocol != libc::IPPROTO_UDP as u8 {
      return None;
   }
   let source_port = be_u16(payload_of(proto, CTA_PROTO_SRC_PORT)?)?;
   let destination_port = be_u16(payload_of(proto, CTA_PROTO_DST_PORT)?)?;
   if family == libc::AF_INET as u8 {
      let source = Ipv4Addr::from(<[u8; 4]>::try_from(payload_of(ip, CTA_IP_V4_SRC)?).ok()?);
      let destination = Ipv4Addr::from(<[u8; 4]>::try_from(payload_of(ip, CTA_IP_V4_DST)?).ok()?);
      Some(Flow::V4(
         source,
         source_port,
         destination,
         destination_port,
      ))
   } else if family == libc::AF_INET6 as u8 {
      let source = Ipv6Addr::from(<[u8; 16]>::try_from(payload_of(ip, CTA_IP_V6_SRC)?).ok()?);
      let destination = Ipv6Addr::from(<[u8; 16]>::try_from(payload_of(ip, CTA_IP_V6_DST)?).ok()?);
      Some(Flow::V6(
         source,
         source_port,
         destination,
         destination_port,
      ))
   } else {
      None
   }
}

/// Splits a dump entry into its `nfgenmsg` family and its attribute stream.
fn split_nfgenmsg(payload: &[u8]) -> Option<(u8, &[u8])> {
   let family = *payload.first()?;
   Some((family, payload.get(NFGENMSG_LEN..)?))
}

/// The payload of the attribute `kind` in `attributes`, ignoring the kernel's flag bits.
///
/// Used for nested attributes too: the inner attribute stream is just another payload.
/// A second attribute of the same kind loses to the first, which is what the kernel
/// sends: one instance per kind.
fn payload_of(attributes: &[u8], kind: u16) -> Option<&[u8]> {
   AttrReader::new(attributes)
      .filter_map(Result::ok)
      .find(|attr| attr.kind & NLA_TYPE_MASK == kind)
      .map(|attr| attr.payload)
}

/// Reads the protocol number: the kernel sends `CTA_PROTO_NUM` as one `u8`, not the
/// four-byte `__be32` the other numeric attributes use.
fn be_protocol(payload: &[u8]) -> Option<u8> {
   payload.first().copied()
}

/// Reads a big-endian `u16` payload, which is how the kernel encodes a port.
fn be_u16(payload: &[u8]) -> Option<u16> {
   Some(u16::from_be_bytes(
      <[u8; 2]>::try_from(payload).ok()?,
   ))
}
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
   use std::net::{TcpListener, TcpStream};
   use std::time::{Duration, Instant};

   use super::*;
   use crate::netlink::attrs::{push_attr, push_attr_u32};

   /// `NLA_F_NESTED`: the kernel sets it on a nested attribute's type. Only the tests
   /// *build* messages, so only they need the flag; the reader masks it off.
   const NLA_F_NESTED: u16 = 0x8000;

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
         DELETE_MSG_TYPE
      );
      assert_eq!(
         u16::from_ne_bytes(message[6..8].try_into().unwrap()),
         NLM_F_REQUEST | NLM_F_ACK
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
   fn the_dump_request_asks_for_the_owner() {
      let message = dump_message(
         libc::AF_INET6 as u8,
         OWNER_TAG | 1000,
         u32::MAX,
         9,
      );
      assert_eq!(message.len(), 36);
      assert_eq!(
         u32::from_ne_bytes(message[0..4].try_into().unwrap()),
         36
      );
      assert_eq!(
         u16::from_ne_bytes(message[4..6].try_into().unwrap()),
         DUMP_MSG_TYPE
      );
      assert_eq!(
         DUMP_MSG_TYPE,
         (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
      );
      assert_eq!(IPCTNL_MSG_CT_GET, 1);
      assert_eq!(
         u16::from_ne_bytes(message[6..8].try_into().unwrap()),
         NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH
      );
      assert_eq!(NLM_F_ROOT, 0x100);
      assert_eq!(NLM_F_MATCH, 0x200);
      assert_eq!(
         u16::from_ne_bytes(message[6..8].try_into().unwrap()),
         NLM_F_REQUEST | NLM_F_DUMP
      );
      assert_eq!(
         u32::from_ne_bytes(message[8..12].try_into().unwrap()),
         9
      );
      assert_eq!(message[16], libc::AF_INET6 as u8);
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

      // `Owner::All` filters on the tag and the tag mask, never on a single uid.
      let all = dump_message(libc::AF_INET as u8, OWNER_TAG, OWNER_TAG_MASK, 10);
      assert_eq!(
         u16::from_ne_bytes(all[4..6].try_into().unwrap()),
         DUMP_MSG_TYPE
      );
      assert_eq!(&all[24..28], &OWNER_TAG.to_be_bytes());
      assert_eq!(&all[32..36], &OWNER_TAG_MASK.to_be_bytes());
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

   /// Appends one attribute whose payload is the nested stream `inner`, the way the
   /// kernel marks a nested attribute with `NLA_F_NESTED`.
   fn push_nested(buffer: &mut Vec<u8>, kind: u16, inner: &[u8]) {
      push_attr(buffer, kind | NLA_F_NESTED, inner);
   }

   /// A conntrack entry exactly as the kernel encodes it: `nfgenmsg`, then the original
   /// tuple with its address pair and protocol triple nested one level deeper.
   fn entry(
      family: u8,
      protocol: u8,
      source: &[u8],
      destination: &[u8],
      ports: (u16, u16),
   ) -> Vec<u8> {
      let mut ip = Vec::new();
      let (source_kind, destination_kind) = if family == libc::AF_INET as u8 {
         (CTA_IP_V4_SRC, CTA_IP_V4_DST)
      } else {
         (CTA_IP_V6_SRC, CTA_IP_V6_DST)
      };
      push_attr(&mut ip, source_kind, source);
      push_attr(&mut ip, destination_kind, destination);

      let mut proto = Vec::new();
      push_attr(&mut proto, CTA_PROTO_NUM, &[protocol]);
      push_attr(
         &mut proto,
         CTA_PROTO_SRC_PORT,
         &ports.0.to_be_bytes(),
      );
      push_attr(
         &mut proto,
         CTA_PROTO_DST_PORT,
         &ports.1.to_be_bytes(),
      );

      let mut tuple = Vec::new();
      push_nested(&mut tuple, CTA_TUPLE_IP, &ip);
      push_nested(&mut tuple, CTA_TUPLE_PROTO, &proto);

      let mut payload = Vec::new();
      payload.extend_from_slice(&NfGenMsg::bytes(family));
      push_nested(&mut payload, CTA_TUPLE_ORIG, &tuple);
      payload
   }

   #[test]
   fn a_parsed_entry_becomes_a_flow() {
      let v4 = entry(
         libc::AF_INET as u8,
         libc::IPPROTO_TCP as u8,
         &[10, 0, 0, 1],
         &[93, 184, 216, 34],
         (51234, 443),
      );
      assert_eq!(
         parse_entry(&v4),
         Some(Flow::V4(
            Ipv4Addr::new(10, 0, 0, 1),
            51234,
            Ipv4Addr::new(93, 184, 216, 34),
            443
         ))
      );

      let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
      let destination = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
      let v6 = entry(
         libc::AF_INET6 as u8,
         libc::IPPROTO_UDP as u8,
         &source.octets(),
         &destination.octets(),
         (60000, 53),
      );
      assert_eq!(
         parse_entry(&v6),
         Some(Flow::V6(source, 60000, destination, 53))
      );
   }

   #[test]
   fn an_entry_without_a_tuple_is_skipped() {
      // A well-formed entry whose original tuple is not there: parse_entry must answer
      // "no flow", not an error, so one odd entry cannot discard the rest of the dump.
      let mut payload = Vec::new();
      payload.extend_from_slice(&NfGenMsg::bytes(libc::AF_INET as u8));
      push_attr_u32(&mut payload, CTA_MARK, OWNER_TAG | 1000);
      assert_eq!(parse_entry(&payload), None);

      // A non-TCP/UDP tuple is skipped too: the revoke sets are keyed on tcp/udp only.
      let icmp = entry(
         libc::AF_INET as u8,
         libc::IPPROTO_ICMP as u8,
         &[10, 0, 0, 1],
         &[10, 0, 0, 2],
         (0, 0),
      );
      assert_eq!(parse_entry(&icmp), None);

      // Truncations of a valid entry never panic and never invent a flow.
      let valid = entry(
         libc::AF_INET as u8,
         libc::IPPROTO_TCP as u8,
         &[10, 0, 0, 1],
         &[10, 0, 0, 2],
         (1, 2),
      );
      for n in 0..valid.len() {
         assert_eq!(
            parse_entry(&valid[..n]),
            None,
            "a truncated entry is skipped"
         );
      }
   }

   /// The live test needs root and `CAP_NET_ADMIN`. It installs its own table with
   /// loopback filtering on, because the daemon's default ruleset returns before the
   /// owner stamp on `lo`; the table is removed again on every exit path.
   ///
   /// It observes conntrack through the dump it is testing, never through
   /// `/proc/net/nf_conntrack`: that file does not exist on every kernel, and a test that
   /// skipped there would report a false green.
   #[test]
   #[ignore = "needs root and CAP_NET_ADMIN; installs and removes its own nft table"]
   fn an_established_flow_is_listed_and_killed() {
      if !is_root() {
         eprintln!("skipping: must run as root (CAP_NET_ADMIN is required)");
         return;
      }
      crate::firewall::install("netshielddiag", 0, 1, true, false)
         .expect("install the ruleset with loopback filtering");
      let _table = TableGuard;

      // A loopback connection, so the test needs no external network. The client's uid is
      // this process's uid, and the stamp rule marks its SYN's flow with that uid.
      let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the listener");
      let server_port = listener.local_addr().expect("listener address").port();
      let mut client =
         TcpStream::connect((Ipv4Addr::LOCALHOST, server_port)).expect("connect to the listener");
      let (accepted, _) = listener.accept().expect("accept the connection");
      client
         .set_read_timeout(Some(Duration::from_secs(2)))
         .expect("set the client read timeout");

      let uid = effective_uid().expect("read the effective uid");
      let expected = Flow::V4(
         Ipv4Addr::LOCALHOST,
         client.local_addr().expect("client address").port(),
         Ipv4Addr::LOCALHOST,
         server_port,
      );

      let mut conntrack = Conntrack::open().expect("open ctnetlink");
      let deadline = Instant::now() + Duration::from_secs(10);
      let mut flows = Vec::new();
      while Instant::now() < deadline && !flows.contains(&expected) {
         flows = conntrack.established_flows(Owner::Uid(uid)).expect("dump the owner's flows");
         std::thread::sleep(Duration::from_millis(100));
      }
      assert!(
         flows.contains(&expected),
         "the established flow {expected:?} must be listed for uid {uid}; listed {flows:?}"
      );
      println!("found established flow {expected:?} for uid {uid}");

      let killed =
         crate::firewall::kill_flows("netshielddiag", &[expected], 30).expect("kill the flow");
      assert_eq!(killed, 1);
      println!("killed {killed} flow(s) with {expected:?}");

      // The next byte on the connection hits the reject rule; the client must see the
      // reset rather than a successful write/read.
      let mut buffer = [0u8; 16];
      let outcome = loop {
         match std::io::Write::write(&mut client, b"x") {
            Err(err) => break err,
            Ok(_) => match std::io::Read::read(&mut client, &mut buffer) {
               Err(err) => break err,
               Ok(0) => break std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
               Ok(_) => continue,
            },
         }
      };
      assert_eq!(
         outcome.kind(),
         std::io::ErrorKind::ConnectionReset,
         "the killed flow must be reset, got {outcome}"
      );
      let _ = accepted.peer_addr();

      // A new connection from the same uid is not in the set and must still get through:
      // the reject is keyed by flow, so it cannot lock the app out of reconnecting.
      let fresh = TcpStream::connect((Ipv4Addr::LOCALHOST, server_port))
         .expect("a new connection must not be rejected");
      let _ = listener.accept().expect("accept the new connection");
      drop(fresh);
   }

   /// Removes the ruleset the live test installed, even when one of its assertions fails.
   struct TableGuard;

   impl Drop for TableGuard {
      fn drop(&mut self) {
         if let Err(err) = crate::firewall::remove("netshielddiag") {
            eprintln!("could not remove the test's nft table: {err}");
         }
      }
   }

   /// The effective uid from `/proc/self/status`, so the live test need not call `geteuid`.
   fn effective_uid() -> Option<u32> {
      let status = std::fs::read_to_string("/proc/self/status").ok()?;
      status
         .lines()
         .find_map(|line| line.strip_prefix("Uid:"))
         .and_then(|fields| fields.split_whitespace().nth(1))
         .and_then(|uid| uid.parse::<u32>().ok())
   }

   fn is_root() -> bool {
      effective_uid() == Some(0)
   }
}
