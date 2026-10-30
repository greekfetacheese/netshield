//! The on-disk encoding of one rule.
//!
//! A rule is a handful of small fields, so it is encoded by hand instead of through a
//! serialisation dependency: the stored format then changes only when this file changes, and a
//! version byte at the front lets a future layout refuse to be misread rather than half-loading.
//! Every read is bounds-checked — the bytes come from a file the daemon opens as root, so a
//! corrupt record must be an error and never an index panic.

use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use netshield_core::ipnet::IpNet;
use netshield_core::{Action, AppMatcher, DestMatcher, Duration, Rule, RuleId};

/// The version of the layout in this file. Bump it when a field is added or reordered: an older
/// build then refuses the record instead of reading the new bytes as the old layout.
const RECORD_VERSION: u8 = 1;

const ACTION_ALLOW: u8 = 0;
const ACTION_DENY: u8 = 1;
const DURATION_ONCE: u8 = 0;
const DURATION_SESSION: u8 = 1;
const DURATION_FOREVER: u8 = 2;
const APP_ANY: u8 = 0;
const APP_EXE: u8 = 1;
const APP_UNKNOWN: u8 = 2;
const DEST_ANY: u8 = 0;
const DEST_DOMAIN: u8 = 1;
const DEST_IP: u8 = 2;
const DEST_PORT: u8 = 3;
const DEST_SET: u8 = 4;
const FAMILY_V4: u8 = 4;
const FAMILY_V6: u8 = 6;

/// An address is stored in sixteen bytes whichever family it is, so its offset never depends on
/// the family byte that precedes it.
const ADDRESS_BYTES: usize = 16;

/// Why one record cannot be read as a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
   /// The leading version byte is not the layout this build writes.
   UnknownVersion(u8),
   /// The bytes ended before the record did.
   Truncated,
   /// Bytes were left after the record ended.
   Trailing,
   /// A tag or flag byte names nothing this version defines.
   UnknownTag { field: &'static str, value: u8 },
   /// A length-prefixed field is not the text this version stores.
   InvalidText,
   /// A prefix length is wider than its address family allows.
   InvalidNetwork,
   /// A field is longer than its length prefix can hold.
   FieldTooLong,
   /// The record's key is not a rule identifier.
   MalformedId,
}

impl fmt::Display for RecordError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::UnknownVersion(version) => write!(
            f,
            "record version {version} is not supported (expected {RECORD_VERSION})"
         ),
         Self::Truncated => f.write_str("record ends in the middle of a field"),
         Self::Trailing => f.write_str("record has bytes after its last field"),
         Self::UnknownTag { field, value } => {
            write!(
               f,
               "{field} tag {value} is not one this version defines"
            )
         }
         Self::InvalidText => f.write_str("record holds a field that is not valid text"),
         Self::InvalidNetwork => f.write_str("record holds an invalid network"),
         Self::FieldTooLong => f.write_str("record holds a field that is too long"),
         Self::MalformedId => f.write_str("identifier is not sixteen hex digits"),
      }
   }
}

impl std::error::Error for RecordError {}

/// The key a rule is stored under.
pub fn id_key(id: &RuleId) -> Result<[u8; 8], RecordError> {
   id.to_bytes().ok_or(RecordError::MalformedId)
}

/// Encodes one rule. The identifier is not part of the value: it is the record's key.
pub fn encode(rule: &Rule) -> Result<Vec<u8>, RecordError> {
   let mut out = Vec::with_capacity(64);
   out.push(RECORD_VERSION);
   out.push(u8::from(rule.enabled));
   out.push(match rule.action {
      Action::Allow => ACTION_ALLOW,
      Action::Deny => ACTION_DENY,
   });
   out.push(match rule.duration {
      Duration::Once => DURATION_ONCE,
      Duration::Session => DURATION_SESSION,
      Duration::Forever => DURATION_FOREVER,
   });
   out.extend_from_slice(&rule.created_at.to_le_bytes());
   out.extend_from_slice(&rule.updated_at.to_le_bytes());
   out.extend_from_slice(&rule.hits.to_le_bytes());

   match rule.last_matched {
      Some(at) => {
         out.push(1);
         out.extend_from_slice(&at.to_le_bytes());
      }
      None => out.push(0),
   }
   match &rule.note {
      Some(note) => {
         out.push(1);
         push_bytes(&mut out, note.as_bytes())?;
      }
      None => out.push(0),
   }

   encode_app(&mut out, &rule.app)?;
   encode_dest(&mut out, &rule.dest)?;
   Ok(out)
}

/// Decodes one record, taking the identifier from its key.
pub fn decode(id: RuleId, bytes: &[u8]) -> Result<Rule, RecordError> {
   let mut reader = Reader { bytes, at: 0 };

   let version = reader.u8()?;
   if version != RECORD_VERSION {
      return Err(RecordError::UnknownVersion(version));
   }

   let enabled = reader.u8()? != 0;
   let action = match reader.u8()? {
      ACTION_ALLOW => Action::Allow,
      ACTION_DENY => Action::Deny,
      value => {
         return Err(RecordError::UnknownTag {
            field: "action",
            value,
         });
      }
   };
   let duration = match reader.u8()? {
      DURATION_ONCE => Duration::Once,
      DURATION_SESSION => Duration::Session,
      DURATION_FOREVER => Duration::Forever,
      value => {
         return Err(RecordError::UnknownTag {
            field: "duration",
            value,
         });
      }
   };

   let created_at = reader.u64()?;
   let updated_at = reader.u64()?;
   let hits = reader.u64()?;
   let last_matched = match reader.u8()? {
      0 => None,
      1 => Some(reader.u64()?),
      value => {
         return Err(RecordError::UnknownTag {
            field: "last_matched",
            value,
         });
      }
   };
   let note = match reader.u8()? {
      0 => None,
      1 => Some(reader.text()?),
      value => {
         return Err(RecordError::UnknownTag {
            field: "note",
            value,
         });
      }
   };

   let app = decode_app(&mut reader)?;
   let dest = decode_dest(&mut reader)?;
   reader.done()?;

   Ok(Rule {
      id,
      enabled,
      app,
      dest,
      action,
      duration,
      note,
      created_at,
      updated_at,
      last_matched,
      hits,
   })
}

fn encode_app(out: &mut Vec<u8>, app: &AppMatcher) -> Result<(), RecordError> {
   match app {
      AppMatcher::Any => out.push(APP_ANY),
      AppMatcher::Exe(path) => {
         out.push(APP_EXE);
         push_bytes(out, path.as_os_str().as_bytes())?;
      }
      AppMatcher::Unknown => out.push(APP_UNKNOWN),
   }
   Ok(())
}

fn decode_app(reader: &mut Reader<'_>) -> Result<AppMatcher, RecordError> {
   match reader.u8()? {
      APP_ANY => Ok(AppMatcher::Any),
      APP_EXE => Ok(AppMatcher::Exe(reader.path()?)),
      APP_UNKNOWN => Ok(AppMatcher::Unknown),
      value => Err(RecordError::UnknownTag {
         field: "app",
         value,
      }),
   }
}

fn encode_dest(out: &mut Vec<u8>, dest: &DestMatcher) -> Result<(), RecordError> {
   match dest {
      DestMatcher::Any => out.push(DEST_ANY),
      DestMatcher::Domain { host, subdomains } => {
         out.push(DEST_DOMAIN);
         out.push(u8::from(*subdomains));
         push_bytes(out, host.as_bytes())?;
      }
      DestMatcher::Ip(net) => {
         out.push(DEST_IP);
         let mut address = [0u8; ADDRESS_BYTES];
         match net.addr {
            IpAddr::V4(addr) => {
               out.push(FAMILY_V4);
               address[..4].copy_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
               out.push(FAMILY_V6);
               address.copy_from_slice(&addr.octets());
            }
         }
         out.extend_from_slice(&address);
         out.push(net.prefix);
      }
      DestMatcher::Port(port) => {
         out.push(DEST_PORT);
         out.extend_from_slice(&port.to_le_bytes());
      }
      DestMatcher::Set(entries) => {
         out.push(DEST_SET);
         let count = u16::try_from(entries.len()).map_err(|_| RecordError::FieldTooLong)?;
         out.extend_from_slice(&count.to_le_bytes());
         for entry in entries {
            encode_dest(out, entry)?;
         }
      }
   }
   Ok(())
}

fn decode_dest(reader: &mut Reader<'_>) -> Result<DestMatcher, RecordError> {
   match reader.u8()? {
      DEST_ANY => Ok(DestMatcher::Any),
      DEST_DOMAIN => {
         let subdomains = reader.u8()? != 0;
         Ok(DestMatcher::Domain {
            host: reader.text()?,
            subdomains,
         })
      }
      DEST_IP => {
         let family = reader.u8()?;
         let raw = reader.take(ADDRESS_BYTES)?;
         let addr = match family {
            FAMILY_V4 => IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
            FAMILY_V6 => {
               let octets =
                  <[u8; ADDRESS_BYTES]>::try_from(raw).map_err(|_| RecordError::Truncated)?;
               IpAddr::V6(Ipv6Addr::from(octets))
            }
            value => {
               return Err(RecordError::UnknownTag {
                  field: "ip family",
                  value,
               });
            }
         };
         // Through `IpNet::new` so a corrupt record cannot produce a prefix wider than its family.
         let net = IpNet::new(addr, reader.u8()?).map_err(|_| RecordError::InvalidNetwork)?;
         Ok(DestMatcher::Ip(net))
      }
      DEST_PORT => Ok(DestMatcher::Port(reader.u16()?)),
      DEST_SET => {
         let count = usize::from(reader.u16()?);
         let mut entries = Vec::with_capacity(count.min(64));
         for _ in 0..count {
            entries.push(decode_dest(reader)?);
         }
         Ok(DestMatcher::Set(entries))
      }
      value => Err(RecordError::UnknownTag {
         field: "destination",
         value,
      }),
   }
}

/// Writes a length-prefixed field.
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RecordError> {
   let len = u16::try_from(bytes.len()).map_err(|_| RecordError::FieldTooLong)?;
   out.extend_from_slice(&len.to_le_bytes());
   out.extend_from_slice(bytes);
   Ok(())
}

/// A bounds-checked cursor over one record.
struct Reader<'a> {
   bytes: &'a [u8],
   at: usize,
}

impl<'a> Reader<'a> {
   fn take(&mut self, len: usize) -> Result<&'a [u8], RecordError> {
      let end = self.at.checked_add(len).ok_or(RecordError::Truncated)?;
      let slice = self.bytes.get(self.at..end).ok_or(RecordError::Truncated)?;
      self.at = end;
      Ok(slice)
   }

   fn u8(&mut self) -> Result<u8, RecordError> {
      let byte = *self.bytes.get(self.at).ok_or(RecordError::Truncated)?;
      self.at += 1;
      Ok(byte)
   }

   fn u16(&mut self) -> Result<u16, RecordError> {
      let raw = self.take(2)?;
      Ok(u16::from_le_bytes([raw[0], raw[1]]))
   }

   fn u64(&mut self) -> Result<u64, RecordError> {
      let raw = self.take(8)?;
      let octets = <[u8; 8]>::try_from(raw).map_err(|_| RecordError::Truncated)?;
      Ok(u64::from_le_bytes(octets))
   }

   fn text(&mut self) -> Result<String, RecordError> {
      let len = usize::from(self.u16()?);
      let raw = self.take(len)?;
      String::from_utf8(raw.to_vec()).map_err(|_| RecordError::InvalidText)
   }

   fn path(&mut self) -> Result<PathBuf, RecordError> {
      let len = usize::from(self.u16()?);
      let raw = self.take(len)?;
      Ok(PathBuf::from(OsString::from_vec(raw.to_vec())))
   }

   fn done(&self) -> Result<(), RecordError> {
      if self.at == self.bytes.len() {
         Ok(())
      } else {
         Err(RecordError::Trailing)
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   fn rule(
      dest: DestMatcher,
      app: AppMatcher,
      note: Option<&str>,
      last_matched: Option<u64>,
   ) -> Rule {
      Rule {
         id: RuleId::new_unique(),
         enabled: true,
         app,
         dest,
         action: Action::Deny,
         duration: Duration::Forever,
         note: note.map(str::to_owned),
         created_at: 1_700_000_000,
         updated_at: 1_700_000_100,
         last_matched,
         hits: 9,
      }
   }

   #[test]
   fn every_matcher_round_trips() {
      let rules = [
         rule(DestMatcher::Any, AppMatcher::Any, None, None),
         rule(
            DestMatcher::Domain {
               host: "api.github.com".to_owned(),
               subdomains: true,
            },
            AppMatcher::Exe(PathBuf::from("/usr/bin/curl")),
            Some("a note"),
            Some(1_700_000_200),
         ),
         rule(
            DestMatcher::Ip("140.82.0.0/16".parse().unwrap()),
            AppMatcher::Unknown,
            None,
            Some(1),
         ),
         rule(
            DestMatcher::Ip("2001:db8::/32".parse().unwrap()),
            AppMatcher::Any,
            None,
            None,
         ),
         rule(DestMatcher::Port(53), AppMatcher::Any, None, None),
         rule(
            DestMatcher::Set(vec![
               DestMatcher::Domain {
                  host: "example.org".to_owned(),
                  subdomains: false,
               },
               DestMatcher::Ip("10.0.0.0/8".parse().unwrap()),
               DestMatcher::Port(443),
            ]),
            AppMatcher::Any,
            Some("a list"),
            None,
         ),
      ];

      for original in rules {
         let key = id_key(&original.id).expect("a minted id is storable");
         let encoded = encode(&original).expect("a rule this type built must encode");
         let decoded = decode(original.id.clone(), &encoded)
            .unwrap_or_else(|error| panic!("{error} for {original:?}"));
         assert_eq!(decoded, original);
         assert_eq!(key.len(), 8);
      }
   }

   #[test]
   fn a_foreign_record_version_is_refused() {
      let original = rule(DestMatcher::Any, AppMatcher::Any, None, None);
      let encoded = encode(&original).expect("encode");

      let mut future = encoded.clone();
      future[0] = 99;
      assert_eq!(
         decode(original.id.clone(), &future),
         Err(RecordError::UnknownVersion(99))
      );

      let short = &encoded[..encoded.len() - 1];
      assert!(
         matches!(
            decode(original.id.clone(), short),
            Err(RecordError::Truncated)
         ),
         "a record that ends early is refused, not guessed"
      );

      let mut trailing = encoded.clone();
      trailing.push(0);
      assert_eq!(
         decode(original.id.clone(), &trailing),
         Err(RecordError::Trailing)
      );
   }
}
