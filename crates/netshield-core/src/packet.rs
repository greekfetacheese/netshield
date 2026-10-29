//! Bounds-checked IPv4/IPv6 packet parsing.
//!
//! The daemon receives raw bytes from the kernel queue and from the network, so every
//! offset in this module is checked before it is used. A hostile or truncated packet is
//! an [`Err`], never an index panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::connection::Family;

/// Why a packet could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
   /// The buffer is shorter than the fixed header it claims to carry.
   TooShort,
   /// The version nibble is neither 4 nor 6, or does not match the intended parser.
   BadVersion,
   /// The IPv4 IHL is below the minimum of five 32-bit words.
   BadIhl,
   /// A length field points past the bytes that were actually captured.
   Truncated,
   /// An IPv6 extension header is malformed or the chain is longer than eight.
   BadExtensionHeader,
   /// The IPv6 next header is not a transport this parser understands.
   UnsupportedTransport,
}

/// The TCP control bits of one segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl TcpFlags {
   pub const FIN: u8 = 0x01;
   pub const SYN: u8 = 0x02;
   pub const RST: u8 = 0x04;
   pub const PSH: u8 = 0x08;
   pub const ACK: u8 = 0x10;
   pub const URG: u8 = 0x20;

   /// The raw flag byte, as it appeared on the wire.
   pub fn bits(self) -> u8 {
      self.0
   }

   pub fn syn(self) -> bool {
      self.0 & Self::SYN != 0
   }

   pub fn ack(self) -> bool {
      self.0 & Self::ACK != 0
   }

   pub fn fin(self) -> bool {
      self.0 & Self::FIN != 0
   }

   pub fn rst(self) -> bool {
      self.0 & Self::RST != 0
   }

   pub fn psh(self) -> bool {
      self.0 & Self::PSH != 0
   }

   pub fn urg(self) -> bool {
      self.0 & Self::URG != 0
   }
}

/// The transport information attribution needs from a packet.
///
/// A fragment, an ESP payload or an unknown protocol keeps the addresses but carries no
/// usable ports, which is why `Other` exists rather than a fabricated port pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4Payload {
   Tcp {
      src_port: u16,
      dst_port: u16,
      flags: TcpFlags,
   },
   Udp {
      src_port: u16,
      dst_port: u16,
   },
   Icmp {
      icmp_type: u8,
      icmp_code: u8,
   },
   Other,
}

/// An IP packet reduced to what the flow table and DNS cache need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedPacket {
   pub family: Family,
   pub src: IpAddr,
   pub dst: IpAddr,
   pub l4: L4Payload,
}

/// Reads one byte at `offset`, or `None` when the slice is too short.
fn byte(buf: &[u8], offset: usize) -> Option<u8> {
   buf.get(offset).copied()
}

/// Reads a big-endian `u16` at `offset`, or `None` when the slice is too short.
fn be16(buf: &[u8], offset: usize) -> Option<u16> {
   let bytes = buf.get(offset..offset.checked_add(2)?)?;
   Some(u16::from_be_bytes([
      *bytes.first()?,
      *bytes.get(1)?,
   ]))
}

/// Enters the transport header at `start`, bounded by the IP length field.
fn parse_transport(
   payload: &[u8],
   start: usize,
   end: usize,
   proto: u8,
) -> Result<L4Payload, ParseError> {
   let transport = payload.get(start..end).ok_or(ParseError::Truncated)?;

   match proto {
      6 => {
         let src_port = be16(transport, 0).ok_or(ParseError::Truncated)?;
         let dst_port = be16(transport, 2).ok_or(ParseError::Truncated)?;
         let flags = byte(transport, 13).ok_or(ParseError::Truncated)?;
         Ok(L4Payload::Tcp {
            src_port,
            dst_port,
            flags: TcpFlags(flags),
         })
      }
      17 => {
         let src_port = be16(transport, 0).ok_or(ParseError::Truncated)?;
         let dst_port = be16(transport, 2).ok_or(ParseError::Truncated)?;
         Ok(L4Payload::Udp { src_port, dst_port })
      }
      1 | 58 => {
         let icmp_type = byte(transport, 0).ok_or(ParseError::Truncated)?;
         let icmp_code = byte(transport, 1).ok_or(ParseError::Truncated)?;
         Ok(L4Payload::Icmp {
            icmp_type,
            icmp_code,
         })
      }
      _ => Ok(L4Payload::Other),
   }
}

fn parse_v4(payload: &[u8]) -> Result<ParsedPacket, ParseError> {
   if payload.len() < 20 {
      return Err(ParseError::TooShort);
   }

   let first = byte(payload, 0).ok_or(ParseError::TooShort)?;
   if first >> 4 != 4 {
      return Err(ParseError::BadVersion);
   }

   let ihl = usize::from(first & 0x0f);
   if ihl < 5 {
      return Err(ParseError::BadIhl);
   }

   let header_len = ihl * 4;
   if header_len > payload.len() {
      return Err(ParseError::Truncated);
   }

   let total_len = usize::from(be16(payload, 2).ok_or(ParseError::TooShort)?);
   if total_len > payload.len() || total_len < header_len {
      return Err(ParseError::Truncated);
   }

   let frag_off = be16(payload, 6).ok_or(ParseError::TooShort)?;
   let proto = byte(payload, 9).ok_or(ParseError::TooShort)?;
   let src = IpAddr::V4(Ipv4Addr::from([
      byte(payload, 12).ok_or(ParseError::TooShort)?,
      byte(payload, 13).ok_or(ParseError::TooShort)?,
      byte(payload, 14).ok_or(ParseError::TooShort)?,
      byte(payload, 15).ok_or(ParseError::TooShort)?,
   ]));
   let dst = IpAddr::V4(Ipv4Addr::from([
      byte(payload, 16).ok_or(ParseError::TooShort)?,
      byte(payload, 17).ok_or(ParseError::TooShort)?,
      byte(payload, 18).ok_or(ParseError::TooShort)?,
      byte(payload, 19).ok_or(ParseError::TooShort)?,
   ]));

   // A non-zero fragment offset means the ports, if any, were carried by an earlier
   // fragment; this packet only has payload bytes.
   let l4 = if frag_off & 0x1fff != 0 {
      L4Payload::Other
   } else {
      parse_transport(payload, header_len, total_len, proto)?
   };

   Ok(ParsedPacket {
      family: Family::V4,
      src,
      dst,
      l4,
   })
}

fn parse_v6(payload: &[u8]) -> Result<ParsedPacket, ParseError> {
   if payload.len() < 40 {
      return Err(ParseError::TooShort);
   }

   let first = byte(payload, 0).ok_or(ParseError::TooShort)?;
   if first >> 4 != 6 {
      return Err(ParseError::BadVersion);
   }

   let declared = usize::from(be16(payload, 4).ok_or(ParseError::TooShort)?);
   // Zero means a jumbogram: the payload runs to the end of the captured buffer.
   let end = if declared == 0 {
      payload.len()
   } else {
      40usize.checked_add(declared).ok_or(ParseError::Truncated)?
   };
   if end > payload.len() {
      return Err(ParseError::Truncated);
   }

   let src = Ipv6Addr::from(
      <[u8; 16]>::try_from(payload.get(8..24).ok_or(ParseError::TooShort)?)
         .map_err(|_| ParseError::TooShort)?,
   );
   let dst = Ipv6Addr::from(
      <[u8; 16]>::try_from(payload.get(24..40).ok_or(ParseError::TooShort)?)
         .map_err(|_| ParseError::TooShort)?,
   );

   let mut next = byte(payload, 6).ok_or(ParseError::TooShort)?;
   let mut offset = 40;
   let mut extensions = 0u8;

   loop {
      match next {
         6 | 17 | 58 => {
            let l4 = parse_transport(payload, offset, end, next)?;
            return Ok(ParsedPacket {
               family: Family::V6,
               src: IpAddr::V6(src),
               dst: IpAddr::V6(dst),
               l4,
            });
         }
         // No next header or an encrypted ESP payload: addresses remain useful, ports do
         // not exist at this layer.
         59 | 50 => {
            return Ok(ParsedPacket {
               family: Family::V6,
               src: IpAddr::V6(src),
               dst: IpAddr::V6(dst),
               l4: L4Payload::Other,
            });
         }
         0 | 43 | 60 | 51 | 44 => {
            extensions += 1;
            if extensions > 8 {
               return Err(ParseError::BadExtensionHeader);
            }

            let header_next = byte(payload, offset).ok_or(ParseError::BadExtensionHeader)?;
            let (units, unit_len) = match next {
               // Hop-by-hop, routing, destination options: (len + 1) * 8 bytes.
               0 | 43 | 60 => {
                  let len = byte(payload, offset + 1).ok_or(ParseError::BadExtensionHeader)?;
                  (usize::from(len) + 1, 8)
               }
               // Authentication header: (len + 2) * 4 bytes.
               51 => {
                  let len = byte(payload, offset + 1).ok_or(ParseError::BadExtensionHeader)?;
                  (usize::from(len) + 2, 4)
               }
               // Fragment header: a fixed eight bytes, next header in byte 0.
               _ => (1, 8),
            };
            let extra = units.checked_mul(unit_len).ok_or(ParseError::BadExtensionHeader)?;

            match offset.checked_add(extra) {
               Some(next_offset) if next_offset <= end => {
                  offset = next_offset;
                  next = header_next;
               }
               _ => return Err(ParseError::BadExtensionHeader),
            }
         }
         _ => return Err(ParseError::UnsupportedTransport),
      }
   }
}

/// Parses one captured IP packet.
///
/// The caller supplies exactly the bytes `copy_range` returned; the IP length fields are
/// treated as an upper bound on those bytes and a mismatch is reported rather than
/// silently clamped.
pub fn parse(payload: &[u8]) -> Result<ParsedPacket, ParseError> {
   match payload.first() {
      None => Err(ParseError::TooShort),
      Some(first) => match first >> 4 {
         4 => parse_v4(payload),
         6 => parse_v6(payload),
         _ => Err(ParseError::BadVersion),
      },
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   fn ipv4(proto: u8, transport: &[u8], options: &[u8], total_len: Option<u16>) -> Vec<u8> {
      let ihl = 5 + options.len() / 4;
      let header_len = ihl * 4;
      let total = total_len.unwrap_or((header_len + transport.len()) as u16);
      let mut bytes = vec![0u8; header_len];
      bytes[0] = 0x40 | ihl as u8;
      bytes[2..4].copy_from_slice(&total.to_be_bytes());
      bytes[8] = 64;
      bytes[9] = proto;
      bytes[12..16].copy_from_slice(&[192, 0, 2, 10]);
      bytes[16..20].copy_from_slice(&[198, 51, 100, 20]);
      if header_len > 20 {
         bytes[20..header_len].copy_from_slice(options);
      }
      bytes.extend_from_slice(transport);
      bytes
   }

   fn tcp(src: u16, dst: u16, flags: u8) -> Vec<u8> {
      let mut bytes = vec![0u8; 20];
      bytes[0..2].copy_from_slice(&src.to_be_bytes());
      bytes[2..4].copy_from_slice(&dst.to_be_bytes());
      bytes[12] = 0x50;
      bytes[13] = flags;
      bytes
   }

   fn udp(src: u16, dst: u16) -> Vec<u8> {
      let mut bytes = vec![0u8; 8];
      bytes[0..2].copy_from_slice(&src.to_be_bytes());
      bytes[2..4].copy_from_slice(&dst.to_be_bytes());
      bytes[4..6].copy_from_slice(&8u16.to_be_bytes());
      bytes
   }

   fn icmp(kind: u8, code: u8) -> Vec<u8> {
      vec![kind, code, 0, 0, 0, 0, 0, 0]
   }

   fn ipv6(next: u8, transport: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
      let mut payload = Vec::new();
      for extension in extensions {
         payload.extend_from_slice(extension);
      }
      payload.extend_from_slice(transport);
      let mut bytes = vec![0u8; 40];
      bytes[0] = 0x60;
      bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
      bytes[6] = next;
      bytes[7] = 64;
      bytes[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
      bytes[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
      bytes.extend_from_slice(&payload);
      bytes
   }

   fn ext(next: u8, len_units: u8) -> Vec<u8> {
      let mut bytes = vec![0u8; (usize::from(len_units) + 1) * 8];
      bytes[0] = next;
      bytes[1] = len_units;
      bytes
   }

   /// Every truncation of a valid packet must yield `Ok` or `Err`, never a panic.
   fn assert_no_panic_on_truncation(bytes: &[u8]) {
      for n in 0..=bytes.len() {
         let _ = parse(&bytes[..n]);
      }
   }

   #[test]
   fn ipv4_tcp_syn_is_parsed_field_by_field() {
      let bytes = ipv4(6, &tcp(51_234, 443, 0x02), &[], None);
      let packet = parse(&bytes).expect("valid packet");
      assert_eq!(packet.family, Family::V4);
      assert_eq!(
         packet.src,
         IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
      );
      assert_eq!(
         packet.dst,
         IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20))
      );
      match packet.l4 {
         L4Payload::Tcp {
            src_port,
            dst_port,
            flags,
         } => {
            assert_eq!(src_port, 51_234);
            assert_eq!(dst_port, 443);
            assert_eq!(flags.bits(), TcpFlags::SYN);
            assert!(flags.syn());
            assert!(!flags.ack());
            assert!(!flags.fin());
            assert!(!flags.rst());
            assert!(!flags.psh());
            assert!(!flags.urg());
         }
         other => panic!("expected TCP, got {other:?}"),
      }
      assert_no_panic_on_truncation(&bytes);
   }

   #[test]
   fn ipv4_udp_and_icmp_are_parsed() {
      let cases = [
         (
            "UDP ports",
            ipv4(17, &udp(53_000, 53), &[], None),
            L4Payload::Udp {
               src_port: 53_000,
               dst_port: 53,
            },
         ),
         (
            "ICMP type and code",
            ipv4(1, &icmp(8, 0), &[], None),
            L4Payload::Icmp {
               icmp_type: 8,
               icmp_code: 0,
            },
         ),
      ];
      for (case, bytes, expected) in cases {
         let packet = parse(&bytes).expect("valid packet");
         assert_eq!(packet.l4, expected, "{case}");
         assert_no_panic_on_truncation(&bytes);
      }
   }

   #[test]
   fn ipv4_options_still_find_the_transport_header() {
      let options = [1u8, 1, 1, 1];
      let bytes = ipv4(6, &tcp(1000, 8080, 0x10), &options, None);
      assert_eq!(bytes[0] & 0x0f, 6);
      let packet = parse(&bytes).expect("valid packet");
      match packet.l4 {
         L4Payload::Tcp {
            src_port, dst_port, ..
         } => {
            assert_eq!(src_port, 1000);
            assert_eq!(dst_port, 8080);
         }
         other => panic!("expected TCP, got {other:?}"),
      }
      assert_no_panic_on_truncation(&bytes);
   }

   #[test]
   fn ipv4_bad_lengths_and_versions_are_rejected() {
      let past_the_buffer = ipv4(6, &tcp(1, 2, 0x02), &[], Some(200));
      let below_the_header = ipv4(6, &tcp(1, 2, 0x02), &[1, 1, 1, 1], Some(20));
      let mut version_five = ipv4(6, &tcp(1, 2, 0x02), &[], None);
      version_five[0] = 0x50;

      let cases = [
         (
            "total length past the buffer",
            past_the_buffer,
            ParseError::Truncated,
         ),
         (
            "total length below the header",
            below_the_header,
            ParseError::Truncated,
         ),
         (
            "version five",
            version_five,
            ParseError::BadVersion,
         ),
      ];
      for (case, bytes, expected) in cases {
         assert_eq!(parse(&bytes), Err(expected), "{case}");
      }
   }

   #[test]
   fn ipv4_fragment_offset_yields_other() {
      let mut bytes = ipv4(6, &tcp(1, 2, 0x02), &[], None);
      bytes[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
      assert_eq!(
         parse(&bytes).map(|packet| packet.l4),
         Ok(L4Payload::Other)
      );
   }

   #[test]
   fn ipv6_tcp_is_parsed() {
      let bytes = ipv6(6, &tcp(44_444, 443, 0x12), &[]);
      let packet = parse(&bytes).expect("valid packet");
      assert_eq!(packet.family, Family::V6);
      assert_eq!(
         packet.src,
         IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
      );
      match packet.l4 {
         L4Payload::Tcp {
            src_port,
            dst_port,
            flags,
         } => {
            assert_eq!(src_port, 44_444);
            assert_eq!(dst_port, 443);
            assert!(flags.syn());
            assert!(flags.ack());
         }
         other => panic!("expected TCP, got {other:?}"),
      }
      assert_no_panic_on_truncation(&bytes);
   }

   #[test]
   fn ipv6_hop_by_hop_extension_still_finds_ports() {
      let bytes = ipv6(0, &tcp(5555, 80, 0x02), &[ext(6, 0)]);
      let packet = parse(&bytes).expect("valid packet");
      assert_eq!(
         packet.l4,
         L4Payload::Tcp {
            src_port: 5555,
            dst_port: 80,
            flags: TcpFlags(0x02),
         }
      );
      assert_no_panic_on_truncation(&bytes);
   }

   #[test]
   fn ipv6_extension_chain_longer_than_eight_is_rejected() {
      let extensions: Vec<u8> = (0..9).flat_map(|_| ext(0, 0)).collect();
      let mut payload = extensions;
      payload.extend_from_slice(&tcp(1, 2, 0x02));
      let bytes = ipv6(0, &payload, &[]);
      assert_eq!(parse(&bytes), Err(ParseError::BadExtensionHeader));
   }

   #[test]
   fn ipv6_esp_and_icmp_are_parsed() {
      let cases = [
         (
            "ESP is other",
            ipv6(50, &[0u8; 8], &[]),
            L4Payload::Other,
         ),
         (
            "ICMP type and code",
            ipv6(58, &icmp(128, 0), &[]),
            L4Payload::Icmp {
               icmp_type: 128,
               icmp_code: 0,
            },
         ),
      ];
      for (case, bytes, expected) in cases {
         assert_eq!(
            parse(&bytes).map(|packet| packet.l4),
            Ok(expected),
            "{case}"
         );
      }
   }
}
