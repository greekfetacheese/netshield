//! The text form of a destination scope: one IP, CIDR or domain per line.
//!
//! The list lives in core rather than in the editor because it is the same contract a rule store
//! or a hand-written file would need, and because the code that decides what a firewall rule
//! means must be testable without a display. Every line becomes one [`DestMatcher`], and
//! [`dest_lines`] is its inverse, so opening and saving the editor without a change never
//! rewrites a rule.

use std::fmt;

use crate::ipnet::IpNet;
use crate::rule::{DestMatcher, normalize_host};

/// The most destinations one rule may list.
///
/// Every new flow is matched against every rule, so an unbounded list is a per-packet cost the
/// user never sees while typing. The cap is generous for a hand-written list and keeps matching
/// flat.
pub const MAX_LIST_ENTRIES: usize = 512;

/// Why a scope list could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestListError {
   /// No line carried a destination.
   Empty,
   /// A line that is not an address, a CIDR, a domain or a `*.domain` pattern.
   ///
   /// The line number is 1-based and counts every line of the box, so it points at the text the
   /// user can see rather than at the entry's position among the entries.
   NotADestination { line: usize },
   /// More entries than [`MAX_LIST_ENTRIES`].
   TooManyEntries,
}

impl fmt::Display for DestListError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Empty => f.write_str("a scope needs at least one destination"),
         Self::NotADestination { line } => write!(
            f,
            "line {line} is not an IP, CIDR, domain or *.domain"
         ),
         Self::TooManyEntries => {
            write!(
               f,
               "a rule may list at most {MAX_LIST_ENTRIES} destinations"
            )
         }
      }
   }
}

impl std::error::Error for DestListError {}

/// Reads a scope list, one destination per line.
///
/// Blank lines are skipped so a list can be spaced out while it is written. Every other line must
/// be an address, a CIDR, a domain or a `*.domain` pattern, and the first line that is none of
/// those is reported by its number rather than skipped: silently dropping a destination narrows
/// a rule, and silently dropping a typo hides a mistake.
pub fn parse_dest_lines(text: &str) -> Result<DestMatcher, DestListError> {
   let mut entries = Vec::new();
   for (index, raw) in text.lines().enumerate() {
      let line = raw.trim();
      if line.is_empty() {
         continue;
      }
      let parsed =
         parse_dest_line(line).ok_or(DestListError::NotADestination { line: index + 1 })?;
      entries.push(parsed);
      if entries.len() > MAX_LIST_ENTRIES {
         return Err(DestListError::TooManyEntries);
      }
   }

   DestMatcher::from_entries(entries).ok_or(DestListError::Empty)
}

/// Reads one line of a scope list, or `None` when it is not a destination.
///
/// `*.host` is the only widening the editor offers, so it is spelled explicitly rather than
/// guessed from a bare host; a stray `*` anywhere else is refused instead of becoming part of a
/// hostname no resolver would ever return.
fn parse_dest_line(line: &str) -> Option<DestMatcher> {
   if let Some(rest) = line.strip_prefix("*.") {
      let host = normalize_host(rest).ok()?;
      if host.contains('*') {
         return None;
      }
      return Some(DestMatcher::Domain {
         host,
         subdomains: true,
      });
   }

   // `IpNet` already reads a bare address as a full-width network.
   if let Ok(net) = line.parse::<IpNet>() {
      return Some(DestMatcher::Ip(net));
   }

   let host = normalize_host(line).ok()?;
   if host.contains('*') {
      return None;
   }
   Some(DestMatcher::Domain {
      host,
      subdomains: false,
   })
}

/// Renders a scope as the editor's text: one destination per line, in the syntax
/// [`parse_dest_lines`] accepts.
///
/// A `Set` keeps its entries' order, so a round trip is stable. There is no line syntax for a
/// port -- a port rule uses the editor's own field -- so one is rendered as `port N` and the
/// parser refuses it: a rule that somehow carries a port inside a list is shown honestly instead
/// of being rewritten.
pub fn dest_lines(dest: &DestMatcher) -> String {
   match dest {
      DestMatcher::Any => String::new(),
      DestMatcher::Domain { host, subdomains } => {
         if *subdomains {
            format!("*.{host}")
         } else {
            host.clone()
         }
      }
      DestMatcher::Ip(net) => net.to_string(),
      DestMatcher::Port(port) => format!("port {port}"),
      DestMatcher::Set(entries) => entries.iter().map(dest_lines).collect::<Vec<_>>().join("\n"),
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn parse_dest_lines_accepts_ips_cidrs_domains_and_wildcards() {
      let parsed =
         parse_dest_lines("  140.82.0.0/16 \n\nAPI.GitHub.com.\n*.example.org\n10.1.2.3\n::1\n")
            .expect("a well-formed list must parse");
      assert_eq!(
         parsed,
         DestMatcher::Set(vec![
            DestMatcher::Ip("140.82.0.0/16".parse().unwrap()),
            DestMatcher::Domain {
               host: "api.github.com".to_owned(),
               subdomains: false,
            },
            DestMatcher::Domain {
               host: "example.org".to_owned(),
               subdomains: true,
            },
            DestMatcher::Ip("10.1.2.3/32".parse().unwrap()),
            DestMatcher::Ip("::1/128".parse().unwrap()),
         ]),
         "blank lines are skipped, hosts are normalised, a bare address is full width"
      );

      assert_eq!(
         parse_dest_lines("example.com"),
         Ok(DestMatcher::Domain {
            host: "example.com".to_owned(),
            subdomains: false,
         }),
         "a one-line list is the plain matcher"
      );
      assert_eq!(
         parse_dest_lines("  \n \n"),
         Err(DestListError::Empty)
      );
   }

   #[test]
   fn parse_dest_lines_reports_the_line() {
      for (text, line) in [
         ("example.com\nnot a host", 2),
         ("\n\nexample.com:443", 3),
         ("*.", 1),
         ("*github.com", 1),
         ("10.0.0.0/33", 1),
      ] {
         assert_eq!(
            parse_dest_lines(text),
            Err(DestListError::NotADestination { line }),
            "{text:?}"
         );
      }
   }

   #[test]
   fn parse_dest_lines_refuses_more_than_the_cap() {
      let at_cap = (0..MAX_LIST_ENTRIES)
         .map(|index| format!("10.{}.{}.1", index / 256, index % 256))
         .collect::<Vec<_>>()
         .join("\n");
      assert!(
         parse_dest_lines(&at_cap).is_ok(),
         "the cap itself is allowed"
      );

      let over = format!("{at_cap}\n192.168.0.1");
      assert_eq!(
         parse_dest_lines(&over),
         Err(DestListError::TooManyEntries)
      );
   }

   #[test]
   fn dest_lines_round_trips_every_matcher() {
      let scopes = [
         DestMatcher::Ip("140.82.0.0/16".parse().unwrap()),
         DestMatcher::Domain {
            host: "api.github.com".to_owned(),
            subdomains: false,
         },
         DestMatcher::Domain {
            host: "example.org".to_owned(),
            subdomains: true,
         },
         DestMatcher::Set(vec![
            DestMatcher::Domain {
               host: "api.github.com".to_owned(),
               subdomains: false,
            },
            DestMatcher::Ip("140.82.0.0/16".parse().unwrap()),
            DestMatcher::Domain {
               host: "example.org".to_owned(),
               subdomains: true,
            },
         ]),
      ];
      for scope in scopes {
         assert_eq!(
            parse_dest_lines(&dest_lines(&scope)),
            Ok(scope.clone()),
            "{scope:?}"
         );
      }

      assert_eq!(dest_lines(&DestMatcher::Any), "");
      assert_eq!(dest_lines(&DestMatcher::Port(53)), "port 53");
   }
}
