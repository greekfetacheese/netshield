//! Bounds-checked DNS answer parsing.
//!
//! Only the record types the attribution cache can use are decoded: an `A`, `AAAA` or
//! `CNAME` answer. Everything else is skipped by its `rdlength`, because decoding MX or
//! TXT into a type nothing reads would be dead code. Every offset is checked so a
//! malformed or hostile response is an [`Err`], never an index panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The record types this parser can use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
   A,
   Aaaa,
   Cname,
}

/// What an answer points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
   /// The address an `A` or `AAAA` record carries.
   Address(IpAddr),
   /// The canonical name a `CNAME` record carries, lowercased and without a trailing dot.
   Name(String),
}

/// One answer that the attribution cache can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
   pub name: String,
   pub kind: RecordKind,
   pub ttl: u32,
   pub target: Target,
}

/// Why a DNS message could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
   /// The buffer is shorter than the twelve-byte header.
   TooShort,
   /// The message is a query, not a response (`QR` clear).
   NotResponse,
   /// A length field points past the bytes that were captured.
   Truncated,
   /// A label or the decoded name is longer than the DNS limits allow.
   BadName,
   /// A compression pointer does not point at an earlier offset.
   PointerLoop,
   /// A name uses more than eight compression pointers.
   TooManyPointers,
}

/// DNS names may not exceed 255 bytes once decoded.
const MAX_NAME_LEN: usize = 255;

/// A compression pointer costs a jump; eight is far beyond any legitimate encoding.
const MAX_POINTERS: u8 = 8;

fn byte(buf: &[u8], offset: usize) -> Option<u8> {
   buf.get(offset).copied()
}

fn be16(buf: &[u8], offset: usize) -> Option<u16> {
   let bytes = buf.get(offset..offset.checked_add(2)?)?;
   Some(u16::from_be_bytes([
      *bytes.first()?,
      *bytes.get(1)?,
   ]))
}

fn be32(buf: &[u8], offset: usize) -> Option<u32> {
   let bytes = buf.get(offset..offset.checked_add(4)?)?;
   let mut raw = [0u8; 4];
   raw.copy_from_slice(bytes);
   Some(u32::from_be_bytes(raw))
}

/// Decodes one name starting at `start`.
///
/// Returns the lowercased name without its trailing dot plus the offset just past the
/// name's encoding in the record that contained it. Compression pointers must point
/// strictly backwards, which makes an infinite pointer chain impossible even before the
/// jump cap is applied.
fn read_name(msg: &[u8], start: usize) -> Result<(String, usize), DnsError> {
   let mut name = String::new();
   let mut cursor = start;
   let mut resume: Option<usize> = None;
   let mut jumps = 0u8;
   let mut decoded_len = 0usize;

   loop {
      let len_byte = byte(msg, cursor).ok_or(DnsError::Truncated)?;
      match len_byte & 0xc0 {
         0xc0 => {
            let low = byte(
               msg,
               cursor.checked_add(1).ok_or(DnsError::Truncated)?,
            )
            .ok_or(DnsError::Truncated)?;
            let target = (usize::from(len_byte & 0x3f) << 8) | usize::from(low);
            if target >= cursor {
               return Err(DnsError::PointerLoop);
            }
            jumps += 1;
            if jumps > MAX_POINTERS {
               return Err(DnsError::TooManyPointers);
            }
            if resume.is_none() {
               resume = Some(cursor.checked_add(2).ok_or(DnsError::Truncated)?);
            }
            cursor = target;
         }
         0x00 => {
            let len = usize::from(len_byte);
            if len == 0 {
               let after = cursor.checked_add(1).ok_or(DnsError::Truncated)?;
               return Ok((name, resume.unwrap_or(after)));
            }
            let start = cursor.checked_add(1).ok_or(DnsError::Truncated)?;
            let end = start.checked_add(len).ok_or(DnsError::Truncated)?;
            let label = msg.get(start..end).ok_or(DnsError::Truncated)?;
            decoded_len += len + usize::from(!name.is_empty());
            if decoded_len > MAX_NAME_LEN {
               return Err(DnsError::BadName);
            }
            if !name.is_empty() {
               name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
            cursor = end;
         }
         // A length of 64..=191 is not a valid label, and 192..=255 is the pointer case.
         _ => return Err(DnsError::BadName),
      }
   }
}

/// Parses the answers of one DNS response message.
///
/// Only `A`, `AAAA` and `CNAME` answers are returned; the other answers are skipped by
/// length after their bounds have been validated.
pub fn parse_response(msg: &[u8]) -> Result<Vec<DnsRecord>, DnsError> {
   if msg.len() < 12 {
      return Err(DnsError::TooShort);
   }
   let flags = byte(msg, 2).ok_or(DnsError::TooShort)?;
   if flags & 0x80 == 0 {
      return Err(DnsError::NotResponse);
   }

   let qdcount = be16(msg, 4).ok_or(DnsError::TooShort)?;
   let ancount = be16(msg, 6).ok_or(DnsError::TooShort)?;

   let mut offset = 12;
   for _ in 0..qdcount {
      let (_, next) = read_name(msg, offset)?;
      offset = next.checked_add(4).ok_or(DnsError::Truncated)?;
      if offset > msg.len() {
         return Err(DnsError::Truncated);
      }
   }

   let mut records = Vec::new();
   for _ in 0..ancount {
      let (name, next) = read_name(msg, offset)?;
      let rtype = be16(msg, next).ok_or(DnsError::Truncated)?;
      let ttl_at = next.checked_add(4).ok_or(DnsError::Truncated)?;
      let ttl = be32(msg, ttl_at).ok_or(DnsError::Truncated)?;
      let length_at = next.checked_add(8).ok_or(DnsError::Truncated)?;
      let rdlength = usize::from(be16(msg, length_at).ok_or(DnsError::Truncated)?);
      let rdata_start = next.checked_add(10).ok_or(DnsError::Truncated)?;
      let rdata_end = rdata_start.checked_add(rdlength).ok_or(DnsError::Truncated)?;
      if rdata_end > msg.len() {
         return Err(DnsError::Truncated);
      }
      let rdata = msg.get(rdata_start..rdata_end).ok_or(DnsError::Truncated)?;

      let record = match rtype {
         1 => {
            if rdata.len() != 4 {
               return Err(DnsError::Truncated);
            }
            let octets: [u8; 4] = rdata.try_into().map_err(|_| DnsError::Truncated)?;
            Some(DnsRecord {
               name: name.clone(),
               kind: RecordKind::A,
               ttl,
               target: Target::Address(IpAddr::V4(Ipv4Addr::from(octets))),
            })
         }
         28 => {
            if rdata.len() != 16 {
               return Err(DnsError::Truncated);
            }
            let octets: [u8; 16] = rdata.try_into().map_err(|_| DnsError::Truncated)?;
            Some(DnsRecord {
               name: name.clone(),
               kind: RecordKind::Aaaa,
               ttl,
               target: Target::Address(IpAddr::V6(Ipv6Addr::from(octets))),
            })
         }
         5 => {
            let (target, target_next) = read_name(msg, rdata_start)?;
            if target_next > rdata_end {
               return Err(DnsError::Truncated);
            }
            Some(DnsRecord {
               name: name.clone(),
               kind: RecordKind::Cname,
               ttl,
               target: Target::Name(target),
            })
         }
         _ => None,
      };

      if let Some(record) = record {
         records.push(record);
      }
      offset = rdata_end;
   }

   Ok(records)
}

/// Parses a DNS response carried by TCP, whose two-byte length prefix is not part of the
/// DNS message itself.
pub fn parse_tcp_response(msg: &[u8]) -> Result<Vec<DnsRecord>, DnsError> {
   let declared = usize::from(be16(msg, 0).ok_or(DnsError::TooShort)?);
   let end = 2usize.checked_add(declared).ok_or(DnsError::Truncated)?;
   let body = msg.get(2..end).ok_or(DnsError::Truncated)?;
   parse_response(body)
}

#[cfg(test)]
mod tests {
   use super::*;

   const HEADER_LEN: usize = 12;

   fn header(flags: u8, qdcount: u16, ancount: u16) -> Vec<u8> {
      let mut bytes = vec![0u8; HEADER_LEN];
      bytes[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
      bytes[2] = flags;
      bytes[3] = 0x80;
      bytes[4..6].copy_from_slice(&qdcount.to_be_bytes());
      bytes[6..8].copy_from_slice(&ancount.to_be_bytes());
      bytes
   }

   fn labels(name: &str) -> Vec<u8> {
      let mut bytes = Vec::new();
      for label in name.split('.') {
         bytes.push(label.len() as u8);
         bytes.extend_from_slice(label.as_bytes());
      }
      bytes.push(0);
      bytes
   }

   fn question(name: &str, rtype: u16) -> Vec<u8> {
      let mut bytes = labels(name);
      bytes.extend_from_slice(&rtype.to_be_bytes());
      bytes.extend_from_slice(&1u16.to_be_bytes());
      bytes
   }

   fn answer(name: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
      let mut bytes = name.to_vec();
      bytes.extend_from_slice(&rtype.to_be_bytes());
      bytes.extend_from_slice(&1u16.to_be_bytes());
      bytes.extend_from_slice(&ttl.to_be_bytes());
      bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
      bytes.extend_from_slice(rdata);
      bytes
   }

   fn pointer(offset: u16) -> Vec<u8> {
      (0xc000u16 | offset).to_be_bytes().to_vec()
   }

   fn response(answers: &[Vec<u8>]) -> Vec<u8> {
      let mut bytes = header(0x80, 1, answers.len() as u16);
      bytes.extend_from_slice(&question("Example.COM", 1));
      for answer in answers {
         bytes.extend_from_slice(answer);
      }
      bytes
   }

   fn a_record(ttl: u32) -> Vec<u8> {
      answer(&pointer(12), 1, ttl, &[93, 184, 216, 34])
   }

   fn assert_no_panic_on_truncation(msg: &[u8]) {
      for n in 0..=msg.len() {
         let _ = parse_response(&msg[..n]);
      }
   }

   #[test]
   fn a_answer_is_parsed_with_name_address_and_ttl() {
      let msg = response(&[a_record(300)]);
      let records = parse_response(&msg).expect("valid response");
      assert_eq!(
         records,
         vec![DnsRecord {
            name: "example.com".to_owned(),
            kind: RecordKind::A,
            ttl: 300,
            target: Target::Address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
         }]
      );
      assert_no_panic_on_truncation(&msg);
   }

   #[test]
   fn aaaa_answer_is_parsed() {
      let rdata = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
      let msg = response(&[answer(&pointer(12), 28, 60, &rdata)]);
      let records = parse_response(&msg).expect("valid response");
      assert_eq!(records.len(), 1);
      assert_eq!(records[0].kind, RecordKind::Aaaa);
      assert_eq!(
         records[0].target,
         Target::Address(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
         )))
      );
      assert_no_panic_on_truncation(&msg);
   }

   #[test]
   fn compressed_answer_name_points_back_to_the_question() {
      let msg = response(&[a_record(120)]);
      // The answer name is a two-byte pointer to offset 12, the question's first label.
      let records = parse_response(&msg).expect("valid response");
      assert_eq!(records[0].name, "example.com");
      assert_no_panic_on_truncation(&msg);
   }

   #[test]
   fn cname_target_may_be_compressed() {
      // An answer named by a pointer to the question, whose rdata is a pointer to the
      // canonical name embedded in a second answer's data.
      let cname = answer(&pointer(12), 5, 60, &pointer(12));
      let msg = response(&[cname]);
      let records = parse_response(&msg).expect("valid response");
      assert_eq!(
         records,
         vec![DnsRecord {
            name: "example.com".to_owned(),
            kind: RecordKind::Cname,
            ttl: 60,
            target: Target::Name("example.com".to_owned()),
         }]
      );
      assert_no_panic_on_truncation(&msg);
   }

   #[test]
   fn unrelated_record_between_two_a_answers_is_skipped() {
      let txt = answer(&pointer(12), 16, 60, b"v=spf1 -all");
      let msg = response(&[a_record(10), txt, a_record(20)]);
      let records = parse_response(&msg).expect("valid response");
      assert_eq!(records.len(), 2);
      assert_eq!(records[0].ttl, 10);
      assert_eq!(records[1].ttl, 20);
      assert_eq!(records[0].kind, RecordKind::A);
      assert_eq!(records[1].kind, RecordKind::A);
      assert_no_panic_on_truncation(&msg);
   }

   #[test]
   fn query_is_not_a_response() {
      let mut msg = response(&[]);
      msg[2] = 0x00;
      assert_eq!(parse_response(&msg), Err(DnsError::NotResponse));
   }

   #[test]
   fn forward_pointer_is_a_pointer_loop() {
      let mut msg = response(&[]);
      // Answer name at the end of the question points forward, past itself.
      let at = msg.len();
      msg.extend_from_slice(&pointer((at + 2) as u16));
      msg[6..8].copy_from_slice(&1u16.to_be_bytes());
      assert_eq!(parse_response(&msg), Err(DnsError::PointerLoop));
   }

   #[test]
   fn nine_pointer_chain_is_too_many_pointers() {
      // Ten questions: the first name is the root, and every later name points at the
      // previous one, so decoding the last name takes nine backwards jumps.
      let mut msg = header(0x80, 10, 0);
      msg.push(0);
      msg.extend_from_slice(&1u16.to_be_bytes());
      msg.extend_from_slice(&1u16.to_be_bytes());
      let mut previous = HEADER_LEN as u16;
      for _ in 1..10 {
         let at = msg.len() as u16;
         msg.extend_from_slice(&pointer(previous));
         msg.extend_from_slice(&1u16.to_be_bytes());
         msg.extend_from_slice(&1u16.to_be_bytes());
         previous = at;
      }
      assert_eq!(
         parse_response(&msg),
         Err(DnsError::TooManyPointers)
      );
   }

   #[test]
   fn label_longer_than_63_is_a_bad_name() {
      let mut msg = header(0x80, 0, 1);
      msg.push(64);
      msg.extend_from_slice(&[b'a'; 64]);
      msg.push(0);
      assert_eq!(parse_response(&msg), Err(DnsError::BadName));
   }

   #[test]
   fn name_longer_than_255_is_a_bad_name() {
      let mut msg = header(0x80, 0, 1);
      for _ in 0..5 {
         msg.push(63);
         msg.extend_from_slice(&[b'a'; 63]);
      }
      msg.push(0);
      assert_eq!(parse_response(&msg), Err(DnsError::BadName));
   }

   #[test]
   fn rdlength_past_the_end_is_truncated() {
      let mut msg = response(&[]);
      msg[6..8].copy_from_slice(&1u16.to_be_bytes());
      msg.extend_from_slice(&pointer(12));
      msg.extend_from_slice(&1u16.to_be_bytes()); // A
      msg.extend_from_slice(&1u16.to_be_bytes()); // IN
      msg.extend_from_slice(&60u32.to_be_bytes());
      msg.extend_from_slice(&8u16.to_be_bytes()); // claims 8 bytes of rdata
      msg.extend_from_slice(&[93, 184, 216, 34]); // only 4 present
      assert_eq!(parse_response(&msg), Err(DnsError::Truncated));
   }

   #[test]
   fn a_record_with_sixteen_bytes_of_rdata_is_truncated() {
      let rdata = [0u8; 16];
      let msg = response(&[answer(&pointer(12), 1, 60, &rdata)]);
      assert_eq!(parse_response(&msg), Err(DnsError::Truncated));
   }

   #[test]
   fn tcp_response_skips_the_length_prefix() {
      let body = response(&[a_record(60)]);
      let mut framed = (body.len() as u16).to_be_bytes().to_vec();
      framed.extend_from_slice(&body);
      assert_eq!(parse_tcp_response(&framed), parse_response(&body));

      let mut overstated = (framed.len() as u16).to_be_bytes().to_vec();
      overstated.extend_from_slice(&body);
      assert_eq!(
         parse_tcp_response(&overstated),
         Err(DnsError::Truncated)
      );
   }
}
