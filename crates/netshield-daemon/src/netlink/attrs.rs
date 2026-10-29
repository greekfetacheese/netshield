//! `nlattr` encoding and decoding.
//!
//! Every netlink payload after `nfgenmsg` is a sequence of TLVs: a 16-bit length that
//! includes the 4-byte header, a 16-bit type, the payload, and padding up to a 4-byte
//! boundary that is *not* counted in the length. Payload bytes are big-endian wherever the
//! kernel declares a `__be` field; the length and type fields themselves are host order,
//! like the rest of the netlink header.
//!
//! The reader is the boundary between hostile kernel data and the rest of the daemon: it
//! never indexes past the buffer it was given, and a short or impossible length ends the
//! iteration with an error instead of wrapping into a loop.

use std::error::Error;
use std::fmt;

/// Smallest possible `nlattr`: the 4-byte header with an empty payload.
const ATTR_HDR_LEN: usize = 4;

/// One decoded attribute borrowed from the datagram it arrived in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr<'a> {
   /// The attribute type, e.g. `NFQA_PAYLOAD`.
   pub kind: u16,
   /// The payload, with the header and the trailing padding excluded.
   pub payload: &'a [u8],
}

/// Why a `nlattr` stream could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrError {
   /// The buffer ends before the attribute it announced, or before a full header.
   Truncated,
   /// The length field is smaller than the 4-byte header it must include.
   BadLength,
}

impl fmt::Display for AttrError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Truncated => f.write_str("truncated netlink attribute"),
         Self::BadLength => f.write_str("netlink attribute length below its 4-byte header"),
      }
   }
}

impl Error for AttrError {}

/// Iterates the attributes packed in one netlink payload.
///
/// A malformed stream yields one `Err` and then stops: continuing after a bogus length
/// would mean guessing where the next attribute starts.
pub struct AttrReader<'a> {
   buf: &'a [u8],
   offset: usize,
}

impl<'a> AttrReader<'a> {
   /// Starts at the beginning of `buf`.
   pub fn new(buf: &'a [u8]) -> Self {
      Self { buf, offset: 0 }
   }
}

impl<'a> Iterator for AttrReader<'a> {
   type Item = Result<Attr<'a>, AttrError>;

   fn next(&mut self) -> Option<Self::Item> {
      if self.offset >= self.buf.len() {
         return None;
      }
      let rest = &self.buf[self.offset..];
      if rest.len() < ATTR_HDR_LEN {
         self.offset = self.buf.len();
         return Some(Err(AttrError::Truncated));
      }
      let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
      if len < ATTR_HDR_LEN {
         self.offset = self.buf.len();
         return Some(Err(AttrError::BadLength));
      }
      if len > rest.len() {
         self.offset = self.buf.len();
         return Some(Err(AttrError::Truncated));
      }
      let kind = u16::from_ne_bytes([rest[2], rest[3]]);
      let payload = &rest[ATTR_HDR_LEN..len];
      // The padding is not part of `len`; advance past it, or past the end of the buffer
      // when the final attribute came without its (optional) trailing padding.
      let padded = (len + 3) & !3;
      self.offset += padded;
      Some(Ok(Attr { kind, payload }))
   }
}

/// Appends one attribute, including the padding that is not counted in its length.
///
/// The payload length is bounded by the 16-bit length field; the only caller that gets
/// near that limit is `NFQA_PAYLOAD`, whose range the kernel caps at 0xFFFF.
pub fn push_attr(buf: &mut Vec<u8>, kind: u16, payload: &[u8]) {
   let len = payload.len() + ATTR_HDR_LEN;
   assert!(
      len <= u16::MAX as usize,
      "netlink attribute payload too large"
   );
   buf.extend_from_slice(&(len as u16).to_ne_bytes());
   buf.extend_from_slice(&kind.to_ne_bytes());
   buf.extend_from_slice(payload);
   while !buf.len().is_multiple_of(4) {
      buf.push(0);
   }
}

/// Appends a `u32` attribute encoded big-endian, as every `__be32` kernel field is.
pub fn push_attr_u32(buf: &mut Vec<u8>, kind: u16, value: u32) {
   push_attr(buf, kind, &value.to_be_bytes());
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn attributes_round_trip() {
      let mut buf = Vec::new();
      push_attr(&mut buf, 9, b"abc");
      assert_eq!(buf.len(), 8, "3-byte payload pads to 8");
      assert_eq!(
         u16::from_ne_bytes([buf[0], buf[1]]),
         7,
         "len is 4 + payload"
      );
      assert_eq!(u16::from_ne_bytes([buf[2], buf[3]]), 9);
      assert_eq!(&buf[4..7], b"abc");
      assert_eq!(buf[7], 0, "padding is zero-filled");

      let attrs = AttrReader::new(&buf).collect::<Result<Vec<_>, _>>().unwrap();
      assert_eq!(attrs.len(), 1);
      assert_eq!(attrs[0].kind, 9);
      assert_eq!(attrs[0].payload, b"abc");

      let mut buf = Vec::new();
      push_attr(&mut buf, 1, b"a");
      push_attr_u32(&mut buf, 2, 0x0102_0304);
      push_attr(&mut buf, 3, b"wxyz");

      let attrs = AttrReader::new(&buf).collect::<Result<Vec<_>, _>>().unwrap();
      assert_eq!(attrs.len(), 3);
      assert_eq!((attrs[0].kind, attrs[0].payload), (1, &b"a"[..]));
      assert_eq!(
         (attrs[1].kind, attrs[1].payload),
         (2, &[1, 2, 3, 4][..])
      );
      assert_eq!(
         (attrs[2].kind, attrs[2].payload),
         (3, &b"wxyz"[..])
      );
   }

   #[test]
   fn padding_follows_the_attribute_length() {
      let mut buf = Vec::new();
      push_attr(&mut buf, 1, b"a");
      push_attr(&mut buf, 2, b"b");
      assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), 5);
      // The second attribute starts at the 4-byte boundary, not at 5.
      assert_eq!(buf[8..10], [5, 0]);

      // A 4-byte payload already ends on the boundary and gets no padding.
      let mut buf = Vec::new();
      push_attr(&mut buf, 1, &[1, 2, 3, 4]);
      assert_eq!(buf.len(), 8);
      push_attr(&mut buf, 2, &[5, 6, 7, 8]);
      assert_eq!(buf.len(), 16);
      let attrs = AttrReader::new(&buf).collect::<Result<Vec<_>, _>>().unwrap();
      assert_eq!(attrs.len(), 2);
      assert_eq!(attrs[1].payload, [5, 6, 7, 8]);
   }

   #[test]
   fn push_attr_u32_is_big_endian() {
      let mut buf = Vec::new();
      push_attr_u32(&mut buf, 4, 0x0000_1000);
      assert_eq!(&buf[4..8], &[0x00, 0x00, 0x10, 0x00]);
   }

   #[test]
   fn a_malformed_attribute_buffer_is_an_error() {
      // Announces 8 bytes but only 6 are present.
      let buf = [8, 0, 1, 0, b'a', b'b'];
      let result: Vec<_> = AttrReader::new(&buf).collect();
      assert_eq!(result, [Err(AttrError::Truncated)]);

      // A length smaller than the header it must include.
      let buf = [3, 0, 9, 0];
      let result: Vec<_> = AttrReader::new(&buf).collect();
      assert_eq!(result, [Err(AttrError::BadLength)]);

      // An empty buffer is not an error, it simply holds no attribute.
      assert_eq!(AttrReader::new(&[]).count(), 0);
   }

   #[test]
   fn every_truncation_of_a_valid_buffer_terminates_without_panic() {
      let mut buf = Vec::new();
      push_attr(&mut buf, 1, b"hello");
      push_attr_u32(&mut buf, 2, 42);
      push_attr(&mut buf, 3, b"xyz");
      for n in 0..=buf.len() {
         // The point is that this cannot panic; a truncated tail is simply an error or
         // an early end depending on where the cut lands.
         let collected: Vec<_> = AttrReader::new(&buf[..n]).collect();
         assert!(
            collected.len() <= 3,
            "reader invented attributes from {} bytes",
            n
         );
      }
   }
}
