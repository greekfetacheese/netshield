//! The NFQUEUE implementation: handshake, packet parsing and verdicts.
//!
//! The values encoded here are the wire protocol of `nfnetlink_queue`, taken from the
//! kernel headers and fixed by the architecture document. Every message type is
//! `(NFNL_SUBSYS_QUEUE << 8) | msg` and every payload begins with a 4-byte `nfgenmsg`.
//!
//! The handshake order matters: the legacy `PF_BIND`/`PF_UNBIND` pair is a no-op on
//! kernels ≥ 3.8 (and may return an error), so those steps are attempted and logged but
//! never fatal, while `BIND`, `PARAMS`, `QUEUE_MAXLEN` and `FLAGS` are the steps whose
//! failure would leave the queue misconfigured, so they are fatal. Configuration is ACKed;
//! verdicts are not, because they sit on the packet hot path.
//!
//! One received datagram may carry several packet messages, so [`NfQueue::recv`] drains
//! every one of them: each packet id owes the kernel exactly one verdict, and a message
//! skipped here would sit unverdicted until the queue was destroyed.

use std::io;

use log::debug;

use super::attrs::{Attr, AttrReader, push_attr, push_attr_u32};
use super::socket::{self, MessageIter, NetlinkSocket, RECV_BUF_LEN, nfgenmsg};

const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;

const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_PF_UNBIND: u8 = 4;
const NFQNL_CFG_CMD_PF_BIND: u8 = 3;

const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;

const NFQA_CFG_F_CONNTRACK: u32 = 2;
const NFQA_CFG_F_UID_GID: u32 = 8;

const NFQNL_COPY_PACKET: u8 = 2;

const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;
const NFQA_TIMESTAMP: u16 = 4;
const NFQA_IFINDEX_OUTDEV: u16 = 6;
const NFQA_HWADDR: u16 = 9;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_UID: u16 = 16;
const NFQA_GID: u16 = 17;

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// `nfqnl_msg_config_cmd` is packed: `command`, `pad`, big-endian `pf`.
const CONFIG_CMD_LEN: usize = 4;
/// `nfqnl_msg_config_params` is packed: big-endian `copy_range`, `copy_mode`.
const CONFIG_PARAMS_LEN: usize = 5;
/// `nfqnl_msg_packet_hdr` is packed: big-endian `packet_id`, big-endian `hw_protocol`, hook.
const PACKET_HDR_LEN: usize = 7;
/// `nfqnl_msg_verdict_hdr` is packed: big-endian `verdict`, big-endian `packet_id`.
const VERDICT_HDR_LEN: usize = 8;

/// The maximum length of one queued packet: with `copy_range = 0xFFFF` the kernel copies
/// up to this many bytes of the datagram.
const QUEUE_MAXLEN: u32 = 4096;
const COPY_RANGE: u32 = 0xFFFF;

/// The message type for every nfnetlink queue message.
const fn queue_msg(msg: u16) -> u16 {
   (NFNL_SUBSYS_QUEUE << 8) | msg
}

/// An open NFQUEUE: the socket the kernel queues packets to, plus the queue number.
pub struct NfQueue {
   socket: NetlinkSocket,
   queue: u16,
   /// Reused receive buffer: `recv` is the packet hot path and must not allocate per
   /// datagram.
   recv_buf: Vec<u8>,
}

/// One packet dequeued from the kernel.
#[derive(Debug)]
pub struct Packet {
   pub id: u32,
   pub family: u8,
   pub hook: u8,
   /// The raw IP datagram, possibly truncated to the configured copy range.
   pub payload: Vec<u8>,
   pub mark: Option<u32>,
   pub uid: Option<u32>,
   pub gid: Option<u32>,
   pub out_ifindex: Option<u32>,
   pub hw_addr: Option<Vec<u8>>,
   /// `(seconds, microseconds)` from `NFQA_TIMESTAMP`.
   pub timestamp: Option<(u64, u64)>,
}

/// The answer owed to the kernel for a queued packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
   Accept,
   Drop,
}

/// Why a queue operation failed.
#[derive(Debug)]
pub enum NfqError {
   /// The syscall or the kernel's ACK failed; `EPERM` here means no `CAP_NET_ADMIN`.
   Io(io::Error),
   /// The kernel sent a message this implementation cannot make sense of.
   Protocol(String),
}

impl std::fmt::Display for NfqError {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self {
         Self::Io(err) => write!(f, "netlink I/O error: {err}"),
         Self::Protocol(reason) => write!(f, "malformed netlink message: {reason}"),
      }
   }
}

impl std::error::Error for NfqError {
   fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
      match self {
         Self::Io(err) => Some(err),
         Self::Protocol(_) => None,
      }
   }
}

impl From<io::Error> for NfqError {
   fn from(err: io::Error) -> Self {
      Self::Io(err)
   }
}

impl NfQueue {
   /// Opens queue `queue` and performs the configuration handshake.
   ///
   /// The legacy per-family bind steps are best effort — the kernel auto-binds since 3.8
   /// and some builds reject the explicit call — but every step whose failure would leave
   /// the queue silently misconfigured is fatal, so a bad service unit or a missing
   /// capability fails loudly here.
   pub fn open(queue: u16) -> Result<Self, NfqError> {
      let mut socket = NetlinkSocket::open()?;

      for pf in [AF_INET, AF_INET6] {
         if let Err(err) = socket.request(
            queue_msg(NFQNL_MSG_CONFIG),
            &config_cmd(queue, NFQNL_CFG_CMD_PF_UNBIND, pf),
         ) {
            debug!("nfqueue {queue}: legacy PF_UNBIND for AF {pf} failed (ignored): {err}");
         }
      }
      for pf in [AF_INET, AF_INET6] {
         if let Err(err) = socket.request(
            queue_msg(NFQNL_MSG_CONFIG),
            &config_cmd(queue, NFQNL_CFG_CMD_PF_BIND, pf),
         ) {
            debug!("nfqueue {queue}: legacy PF_BIND for AF {pf} failed (ignored): {err}");
         }
      }

      socket.request(queue_msg(NFQNL_MSG_CONFIG), &config_bind(queue))?;
      socket.request(queue_msg(NFQNL_MSG_CONFIG), &config_params(queue))?;
      socket.request(
         queue_msg(NFQNL_MSG_CONFIG),
         &config_maxlen(queue, QUEUE_MAXLEN),
      )?;
      socket.request(
         queue_msg(NFQNL_MSG_CONFIG),
         &config_flags(queue, NFQA_CFG_F_UID_GID | NFQA_CFG_F_CONNTRACK),
      )?;

      Ok(Self {
         socket,
         queue,
         recv_buf: vec![0u8; RECV_BUF_LEN],
      })
   }

   /// Appends every queued packet carried by one datagram to `out` and returns how many
   /// were appended. A datagram may carry several packet messages, so a caller must never
   /// assume one; `out` lets the caller reuse its allocation on the hot path.
   ///
   /// A datagram with no `NFQNL_MSG_PACKET` (an ACK, other nfnetlink traffic) returns
   /// `Ok(0)`: there is nothing to answer and the caller may block again. A malformed
   /// packet message is an error even when other messages were fine: answering with a
   /// guessed verdict would either drop traffic that should flow or accept traffic that
   /// should not, and the packet it describes must stay visibly unverdicted.
   pub fn recv(&mut self, out: &mut Vec<Packet>) -> Result<usize, NfqError> {
      let n = match self.socket.take_deferred() {
         Some(datagram) => {
            if datagram.len() > self.recv_buf.len() {
               return Err(NfqError::Protocol(format!(
                  "deferred datagram of {} bytes exceeds the receive buffer",
                  datagram.len()
               )));
            }
            self.recv_buf[..datagram.len()].copy_from_slice(&datagram);
            datagram.len()
         }
         None => self.socket.recv_datagram(&mut self.recv_buf)?,
      };
      drain_packets(&self.recv_buf[..n], out)
   }

   /// Answers one packet id. Fire-and-forget: a verdict is on the hot path and the kernel
   /// sends no ACK for it.
   pub fn verdict(&mut self, id: u32, verdict: Verdict) -> Result<(), NfqError> {
      let payload = verdict_payload(self.queue, id, verdict);
      self.socket.send(queue_msg(NFQNL_MSG_VERDICT), &payload)?;
      Ok(())
   }

   /// The queue number this handle is bound to.
   pub fn queue_num(&self) -> u16 {
      self.queue
   }
}

/// Appends every packet message framed in one received datagram to `out`.
///
/// Split out from [`NfQueue::recv`] so the coalescing case is unit-tested against a
/// hand-built datagram with no socket: returning on the first packet message used to
/// leave the rest of the datagram's packet ids unverdicted.
fn drain_packets(datagram: &[u8], out: &mut Vec<Packet>) -> Result<usize, NfqError> {
   let mut appended = 0;
   for msg in MessageIter::new(datagram) {
      let msg = msg.map_err(|err| NfqError::Protocol(err.to_string()))?;
      if msg.msg_type == queue_msg(NFQNL_MSG_PACKET) {
         out.push(parse_packet(msg.payload)?);
         appended += 1;
      }
      // ACKs and other nfnetlink traffic are not packets; keep draining so a packet
      // that shares the datagram with them is not lost.
   }
   Ok(appended)
}

/// `CONFIG`/`CMD` payload: `nfgenmsg` plus `nfqnl_msg_config_cmd` bytes.
fn config_cmd(queue: u16, command: u8, pf: u8) -> Vec<u8> {
   let mut payload = nfgenmsg(AF_UNSPEC, queue).to_vec();
   let mut cmd = [0u8; CONFIG_CMD_LEN];
   cmd[0] = command;
   cmd[2..4].copy_from_slice(&(pf as u16).to_be_bytes());
   push_attr(&mut payload, NFQA_CFG_CMD, &cmd);
   payload
}

/// `CONFIG`/`CMD_BIND` for this queue.
fn config_bind(queue: u16) -> Vec<u8> {
   config_cmd(queue, NFQNL_CFG_CMD_BIND, AF_UNSPEC)
}

/// `CONFIG`/`PARAMS`: copy the whole datagram in packet mode.
fn config_params(queue: u16) -> Vec<u8> {
   let mut payload = nfgenmsg(AF_UNSPEC, queue).to_vec();
   let mut params = [0u8; CONFIG_PARAMS_LEN];
   params[0..4].copy_from_slice(&COPY_RANGE.to_be_bytes());
   params[4] = NFQNL_COPY_PACKET;
   push_attr(&mut payload, NFQA_CFG_PARAMS, &params);
   payload
}

/// `CONFIG`/`QUEUE_MAXLEN`: how many packets may sit in the queue at once.
fn config_maxlen(queue: u16, maxlen: u32) -> Vec<u8> {
   let mut payload = nfgenmsg(AF_UNSPEC, queue).to_vec();
   push_attr_u32(&mut payload, NFQA_CFG_QUEUE_MAXLEN, maxlen);
   payload
}

/// `CONFIG`/`MASK` + `FLAGS`: which optional per-packet attributes the kernel should add.
fn config_flags(queue: u16, flags: u32) -> Vec<u8> {
   let mut payload = nfgenmsg(AF_UNSPEC, queue).to_vec();
   push_attr_u32(&mut payload, NFQA_CFG_MASK, flags);
   push_attr_u32(&mut payload, NFQA_CFG_FLAGS, flags);
   payload
}

/// `VERDICT` payload: `nfgenmsg` plus the packed verdict header.
fn verdict_payload(queue: u16, id: u32, verdict: Verdict) -> Vec<u8> {
   let mut payload = nfgenmsg(AF_UNSPEC, queue).to_vec();
   let mut hdr = [0u8; VERDICT_HDR_LEN];
   let verdict = match verdict {
      Verdict::Accept => NF_ACCEPT,
      Verdict::Drop => NF_DROP,
   };
   hdr[0..4].copy_from_slice(&verdict.to_be_bytes());
   hdr[4..8].copy_from_slice(&id.to_be_bytes());
   push_attr(&mut payload, NFQA_VERDICT_HDR, &hdr);
   payload
}

/// Parses one `NFQNL_MSG_PACKET` payload into a [`Packet`].
fn parse_packet(payload: &[u8]) -> Result<Packet, NfqError> {
   if payload.len() < socket::NFGENMSG_LEN {
      return Err(NfqError::Protocol(
         "NFQNL_MSG_PACKET is shorter than nfgenmsg".to_owned(),
      ));
   }
   let family = payload[0];
   let attrs = &payload[socket::NFGENMSG_LEN..];

   let mut header: Option<(u32, u8)> = None;
   let mut data: Option<Vec<u8>> = None;
   let mut mark = None;
   let mut uid = None;
   let mut gid = None;
   let mut out_ifindex = None;
   let mut hw_addr = None;
   let mut timestamp = None;

   for attr in AttrReader::new(attrs) {
      let attr = attr.map_err(|err| NfqError::Protocol(err.to_string()))?;
      match attr.kind {
         NFQA_PACKET_HDR => {
            if attr.payload.len() < PACKET_HDR_LEN {
               return Err(NfqError::Protocol(format!(
                  "NFQA_PACKET_HDR is {} bytes, expected {}",
                  attr.payload.len(),
                  PACKET_HDR_LEN
               )));
            }
            let id = be32(&attr.payload[0..4]);
            let hook = attr.payload[6];
            header = Some((id, hook));
         }
         NFQA_PAYLOAD => data = Some(attr.payload.to_vec()),
         NFQA_MARK => mark = Some(be_u32(attr)?),
         NFQA_UID => uid = Some(be_u32(attr)?),
         NFQA_GID => gid = Some(be_u32(attr)?),
         NFQA_IFINDEX_OUTDEV => out_ifindex = Some(be_u32(attr)?),
         NFQA_HWADDR => hw_addr = Some(attr.payload.to_vec()),
         NFQA_TIMESTAMP => {
            if attr.payload.len() < 16 {
               return Err(NfqError::Protocol(format!(
                  "NFQA_TIMESTAMP is {} bytes, expected 16",
                  attr.payload.len()
               )));
            }
            timestamp = Some((
               be64(&attr.payload[0..8]),
               be64(&attr.payload[8..16]),
            ));
         }
         _ => {}
      }
   }

   let (id, hook) = header
      .ok_or_else(|| NfqError::Protocol("NFQNL_MSG_PACKET has no NFQA_PACKET_HDR".to_owned()))?;
   let payload =
      data.ok_or_else(|| NfqError::Protocol("NFQNL_MSG_PACKET has no NFQA_PAYLOAD".to_owned()))?;

   Ok(Packet {
      id,
      family,
      hook,
      payload,
      mark,
      uid,
      gid,
      out_ifindex,
      hw_addr,
      timestamp,
   })
}

fn be32(bytes: &[u8]) -> u32 {
   u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn be64(bytes: &[u8]) -> u64 {
   u64::from_be_bytes([
      bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
   ])
}

fn be_u32(attr: Attr<'_>) -> Result<u32, NfqError> {
   if attr.payload.len() < 4 {
      return Err(NfqError::Protocol(format!(
         "attribute {} is {} bytes, expected 4",
         attr.kind,
         attr.payload.len()
      )));
   }
   Ok(be32(attr.payload))
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::netlink::socket::frame;
   use std::panic;

   fn packet_datagram(attrs: &[(u16, &[u8])]) -> Vec<u8> {
      let mut payload = nfgenmsg(AF_INET, 3).to_vec();
      for (kind, bytes) in attrs {
         push_attr(&mut payload, *kind, bytes);
      }
      frame(queue_msg(NFQNL_MSG_PACKET), 0, 1, &payload)
   }

   #[test]
   fn parse_synthetic_packet() {
      let mut hdr = [0u8; PACKET_HDR_LEN];
      hdr[0..4].copy_from_slice(&0x0000_00ABu32.to_be_bytes());
      hdr[4..6].copy_from_slice(&0x0800u16.to_be_bytes());
      hdr[6] = 2; // hook: local out
      let mut ts = [0u8; 16];
      ts[0..8].copy_from_slice(&1_700_000_000u64.to_be_bytes());
      ts[8..16].copy_from_slice(&123_456u64.to_be_bytes());
      let datagram = packet_datagram(&[
         (NFQA_PACKET_HDR, &hdr),
         (NFQA_PAYLOAD, b"IP datagram"),
         (NFQA_MARK, &0x10u32.to_be_bytes()),
         (NFQA_UID, &1000u32.to_be_bytes()),
         (NFQA_GID, &1001u32.to_be_bytes()),
         (NFQA_IFINDEX_OUTDEV, &2u32.to_be_bytes()),
         (NFQA_HWADDR, &[0xDE, 0xAD, 0xBE, 0xEF, 0, 1]),
         (NFQA_TIMESTAMP, &ts),
      ]);

      let msg = MessageIter::new(&datagram).next().unwrap().unwrap();
      assert_eq!(msg.msg_type, 0x0300);
      let packet = parse_packet(msg.payload).unwrap();
      assert_eq!(packet.id, 0xAB);
      assert_eq!(packet.family, AF_INET);
      assert_eq!(packet.hook, 2);
      assert_eq!(packet.payload, b"IP datagram");
      assert_eq!(packet.mark, Some(0x10));
      assert_eq!(packet.uid, Some(1000));
      assert_eq!(packet.gid, Some(1001));
      assert_eq!(packet.out_ifindex, Some(2));
      assert_eq!(
         packet.hw_addr.as_deref(),
         Some(&[0xDE, 0xAD, 0xBE, 0xEF, 0, 1][..])
      );
      assert_eq!(packet.timestamp, Some((1_700_000_000, 123_456)));
   }

   #[test]
   fn packet_without_header_is_a_protocol_error() {
      let datagram = packet_datagram(&[(NFQA_PAYLOAD, b"IP datagram")]);
      let msg = MessageIter::new(&datagram).next().unwrap().unwrap();
      match parse_packet(msg.payload) {
         Err(NfqError::Protocol(reason)) => assert!(reason.contains("NFQA_PACKET_HDR")),
         other => panic!("expected a protocol error, got {other:?}"),
      }
   }

   #[test]
   fn missing_payload_is_a_protocol_error() {
      let mut hdr = [0u8; PACKET_HDR_LEN];
      hdr[0..4].copy_from_slice(&7u32.to_be_bytes());
      hdr[6] = 2;
      let datagram = packet_datagram(&[(NFQA_PACKET_HDR, &hdr)]);
      let msg = MessageIter::new(&datagram).next().unwrap().unwrap();
      match parse_packet(msg.payload) {
         Err(NfqError::Protocol(reason)) => assert!(reason.contains("NFQA_PAYLOAD")),
         other => panic!("expected a protocol error, got {other:?}"),
      }
   }

   #[test]
   fn truncated_mid_attribute_is_a_protocol_error() {
      let mut hdr = [0u8; PACKET_HDR_LEN];
      hdr[0..4].copy_from_slice(&7u32.to_be_bytes());
      let mut payload = nfgenmsg(AF_INET, 3).to_vec();
      push_attr(&mut payload, NFQA_PACKET_HDR, &hdr);
      push_attr(&mut payload, NFQA_PAYLOAD, b"abcdef");
      // Drop three bytes from the payload attribute while leaving `nlmsg_len` honest,
      // so the message framing is sound and the attribute reader is the one that sees
      // the cut.
      payload.truncate(payload.len() - 3);
      let datagram = frame(queue_msg(NFQNL_MSG_PACKET), 0, 1, &payload);
      let msg = MessageIter::new(&datagram).next().unwrap().unwrap();
      match parse_packet(msg.payload) {
         Err(NfqError::Protocol(reason)) => assert!(reason.contains("truncated")),
         other => panic!("expected a protocol error, got {other:?}"),
      }
   }

   #[test]
   fn large_payload_is_parsed_intact() {
      let data: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
      let mut hdr = [0u8; PACKET_HDR_LEN];
      hdr[0..4].copy_from_slice(&9u32.to_be_bytes());
      let datagram = packet_datagram(&[(NFQA_PACKET_HDR, &hdr), (NFQA_PAYLOAD, &data)]);
      let msg = MessageIter::new(&datagram).next().unwrap().unwrap();
      let packet = parse_packet(msg.payload).unwrap();
      assert_eq!(packet.payload, data);
   }

   #[test]
   fn parse_is_panic_free_on_every_truncation() {
      let mut hdr = [0u8; PACKET_HDR_LEN];
      hdr[0..4].copy_from_slice(&1u32.to_be_bytes());
      let datagram = packet_datagram(&[
         (NFQA_PACKET_HDR, &hdr),
         (NFQA_PAYLOAD, b"payload"),
         (NFQA_UID, &7u32.to_be_bytes()),
      ]);
      for n in 0..=datagram.len() {
         let _ = panic::catch_unwind(|| parse_packet(&datagram[..n]));
      }
   }

   #[test]
   fn config_messages_have_the_documented_bytes() {
      // CONFIG/CMD_BIND: 16 (nlmsghdr) + 4 (nfgenmsg) + 4 (nlattr hdr) + 4 (cmd) = 28.
      let bind = config_bind(3);
      let msg = frame(queue_msg(NFQNL_MSG_CONFIG), 5, 1, &bind);
      assert_eq!(msg.len(), 28);
      assert_eq!(&msg[0..4], &28u32.to_ne_bytes());
      assert_eq!(&msg[4..6], &0x0302u16.to_ne_bytes());
      assert_eq!(&msg[6..8], &5u16.to_ne_bytes());
      assert_eq!(
         &msg[16..20],
         &[0, 0, 0, 3],
         "nfgenmsg: AF_UNSPEC, v0, queue 3"
      );
      assert_eq!(
         &msg[20..24],
         &[8, 0, 1, 0],
         "attr: len 8, type NFQA_CFG_CMD"
      );
      assert_eq!(
         &msg[24..28],
         &[NFQNL_CFG_CMD_BIND, 0, 0, 0],
         "bind, AF_UNSPEC"
      );

      // CONFIG/PARAMS: 5-byte packed payload padded to 12 -> 32 bytes.
      let msg = frame(
         queue_msg(NFQNL_MSG_CONFIG),
         5,
         2,
         &config_params(3),
      );
      assert_eq!(msg.len(), 32);
      assert_eq!(
         &msg[20..24],
         &[9, 0, 2, 0],
         "attr: len 9, type NFQA_CFG_PARAMS"
      );
      assert_eq!(
         &msg[24..29],
         &[0, 0, 0xFF, 0xFF, NFQNL_COPY_PACKET]
      );
      assert_eq!(
         &msg[29..32],
         &[0, 0, 0],
         "padding is outside the length"
      );

      // CONFIG/QUEUE_MAXLEN: 28 bytes.
      let msg = frame(
         queue_msg(NFQNL_MSG_CONFIG),
         5,
         3,
         &config_maxlen(3, QUEUE_MAXLEN),
      );
      assert_eq!(msg.len(), 28);
      assert_eq!(
         &msg[20..24],
         &[8, 0, 3, 0],
         "attr: len 8, type QUEUE_MAXLEN"
      );
      assert_eq!(&msg[24..28], &4096u32.to_be_bytes());

      // CONFIG/FLAGS: two attributes -> 36 bytes, value UID_GID | CONNTRACK.
      let msg = frame(
         queue_msg(NFQNL_MSG_CONFIG),
         5,
         4,
         &config_flags(3, 10),
      );
      assert_eq!(msg.len(), 36);
      assert_eq!(
         &msg[20..24],
         &[8, 0, 4, 0],
         "attr: len 8, type NFQA_CFG_MASK"
      );
      assert_eq!(&msg[24..28], &10u32.to_be_bytes());
      assert_eq!(
         &msg[28..32],
         &[8, 0, 5, 0],
         "attr: len 8, type NFQA_CFG_FLAGS"
      );
      assert_eq!(&msg[32..36], &10u32.to_be_bytes());

      let flags = NFQA_CFG_F_UID_GID | NFQA_CFG_F_CONNTRACK;
      assert_eq!(flags, 10);
      assert_eq!(flags & 1, 0, "FAIL_OPEN must not be set");
   }

   #[test]
   fn pf_bind_carries_the_family() {
      let msg = frame(
         queue_msg(NFQNL_MSG_CONFIG),
         5,
         1,
         &config_cmd(3, NFQNL_CFG_CMD_PF_BIND, AF_INET6),
      );
      assert_eq!(msg.len(), 28);
      assert_eq!(
         &msg[24..28],
         &[NFQNL_CFG_CMD_PF_BIND, 0, 0, AF_INET6]
      );
   }

   #[test]
   fn pf_unbind_is_command_four_for_both_families() {
      for pf in [AF_INET, AF_INET6] {
         let msg = frame(
            queue_msg(NFQNL_MSG_CONFIG),
            5,
            1,
            &config_cmd(3, NFQNL_CFG_CMD_PF_UNBIND, pf),
         );
         assert_eq!(msg.len(), 28);
         assert_eq!(
            &msg[20..24],
            &[8, 0, 1, 0],
            "attr: len 8, type NFQA_CFG_CMD"
         );
         assert_eq!(
            &msg[24..28],
            &[4, 0, 0, pf],
            "unbind command 4, family {pf}"
         );
      }
   }

   #[test]
   fn one_datagram_drains_every_packet() {
      let mut first = [0u8; PACKET_HDR_LEN];
      first[0..4].copy_from_slice(&0x11u32.to_be_bytes());
      first[6] = 3;
      let mut second = [0u8; PACKET_HDR_LEN];
      second[0..4].copy_from_slice(&0x22u32.to_be_bytes());
      second[6] = 3;
      let mut datagram =
         packet_datagram(&[(NFQA_PACKET_HDR, &first), (NFQA_PAYLOAD, b"first packet")]);
      datagram.extend_from_slice(&packet_datagram(&[
         (NFQA_PACKET_HDR, &second),
         (NFQA_PAYLOAD, b"second packet"),
      ]));
      assert_eq!(
         MessageIter::new(&datagram).count(),
         2,
         "the datagram must hold two framed messages"
      );

      // The drain is exercised directly: it is the part that used to return on the first
      // packet and silently drop the rest of the datagram.
      let mut out = Vec::new();
      let count = drain_packets(&datagram, &mut out).unwrap();
      assert_eq!(count, 2);
      assert_eq!(out.len(), 2);
      assert_eq!(
         (out[0].id, out[0].payload.as_slice()),
         (0x11, &b"first packet"[..])
      );
      assert_eq!(
         (out[1].id, out[1].payload.as_slice()),
         (0x22, &b"second packet"[..])
      );

      // An ACK-only datagram carries no packet, and the caller gets `Ok(0)`.
      let mut out = Vec::new();
      let ack = frame(socket::NLMSG_ERROR, 0, 1, &0i32.to_ne_bytes());
      assert_eq!(drain_packets(&ack, &mut out).unwrap(), 0);
      assert!(out.is_empty());
   }

   #[test]
   fn verdict_message_has_the_documented_bytes() {
      let payload = verdict_payload(3, 0x0000_0102, Verdict::Accept);
      let msg = frame(queue_msg(NFQNL_MSG_VERDICT), 1, 1, &payload);
      assert_eq!(msg.len(), 32, "16 + 4 + 4 + 8");
      assert_eq!(&msg[0..4], &32u32.to_ne_bytes());
      assert_eq!(&msg[4..6], &0x0301u16.to_ne_bytes());
      assert_eq!(&msg[8..12], &1u32.to_ne_bytes());
      assert_eq!(
         &msg[16..20],
         &[0, 0, 0, 3],
         "nfgenmsg: AF_UNSPEC, v0, queue 3"
      );
      assert_eq!(
         &msg[20..24],
         &[12, 0, 2, 0],
         "attr: len 12, type NFQA_VERDICT_HDR"
      );
      assert_eq!(&msg[24..28], &NF_ACCEPT.to_be_bytes());
      assert_eq!(&msg[28..32], &0x0000_0102u32.to_be_bytes());
      assert_eq!(&msg[24..32], &[0, 0, 0, 1, 0, 0, 1, 2]);

      let payload = verdict_payload(3, 0x0000_0102, Verdict::Drop);
      let msg = frame(queue_msg(NFQNL_MSG_VERDICT), 1, 1, &payload);
      assert_eq!(&msg[24..28], &NF_DROP.to_be_bytes());
   }
}
