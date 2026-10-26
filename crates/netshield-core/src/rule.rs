use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::connection::{Attribution, Connection};
use crate::ipnet::IpNet;

/// A stable identifier for a rule.
///
/// Rules are persisted and referenced by prompts and IPC messages, so the identifier has
/// to survive a daemon restart. It is opaque hex rather than an index because indices
/// shift when rules are removed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleId(String);

impl RuleId {
   /// Mints an identifier from the clock, PID and a process-wide counter.
   ///
   /// There is no random-number dependency by design. Mixing three independent sources
   /// keeps identifiers distinct across restarts and across daemons started in the same
   /// nanosecond, while the counter alone guarantees distinctness within one process.
   pub fn new_unique() -> Self {
      static COUNTER: AtomicU64 = AtomicU64::new(0);

      let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
      let nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos() as u64);
      let pid = u64::from(std::process::id());
      let mixed = mix(nanos ^ pid.rotate_left(32) ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
      Self(format!("{mixed:016x}"))
   }
}

impl fmt::Display for RuleId {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(&self.0)
   }
}

/// SplitMix64 finaliser: cheap avalanche so nearby inputs do not produce nearby IDs.
fn mix(mut value: u64) -> u64 {
   value ^= value >> 30;
   value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
   value ^= value >> 27;
   value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
   value ^ (value >> 31)
}

/// The verdict a matching rule applies to a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
   Allow,
   Deny,
}

/// How long a decision lasts.
///
/// `Once` and `Session` stay in memory; only `Forever` reaches the on-disk store, which
/// is why the distinction belongs in the model rather than in the persistence layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Duration {
   Once,
   Session,
   Forever,
}

/// Which application a rule is scoped to.
///
/// `Exe` stores the exact executable path because a basename match would let any binary
/// named `firefox` inherit the user's allow. `Unknown` exists so unattributable sockets
/// are governed explicitly instead of falling through to a permissive default.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum AppMatcher {
   Any,
   Exe(PathBuf),
   Unknown,
}

impl AppMatcher {
   /// Returns whether this matcher governs the connection's owner.
   pub fn matches(&self, process: &Attribution) -> bool {
      match self {
         Self::Any => true,
         Self::Unknown => matches!(process, Attribution::Unknown),
         Self::Exe(path) => process.exe() == Some(path.as_path()),
      }
   }
}

/// Which destination a rule is scoped to.
///
/// `Domain` is the precise scope the prompt offers ("only this domain"), with
/// `subdomains` as the one explicit widening. Nothing here guesses a public suffix.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum DestMatcher {
   Any,
   Domain { host: String, subdomains: bool },
   Ip(IpNet),
   Port(u16),
}

impl DestMatcher {
   /// Returns whether this matcher covers the connection's remote end.
   pub fn matches(&self, conn: &Connection) -> bool {
      match self {
         Self::Any => true,
         Self::Domain { host, subdomains } => {
            let Some(domain) = conn.domain.as_deref() else {
               return false;
            };
            if domain.eq_ignore_ascii_case(host) {
               return true;
            }
            if !subdomains {
               return false;
            }
            let domain = domain.to_ascii_lowercase();
            domain.len() > host.len() + 1
               && domain.ends_with(&format!(".{}", host.to_ascii_lowercase()))
         }
         Self::Ip(net) => net.contains(conn.remote.addr),
         Self::Port(port) => conn.remote.port == *port,
      }
   }

   /// Specificity used by [`crate::RuleSet::evaluate`]: exact domain 40, subdomain 30,
   /// IP 20, port 10, any 0. Higher wins, and the ordering is deliberately independent
   /// of the application dimension so application scope can be the outer key.
   pub fn rank(&self) -> u8 {
      match self {
         Self::Domain {
            subdomains: false, ..
         } => 40,
         Self::Domain {
            subdomains: true, ..
         } => 30,
         Self::Ip(_) => 20,
         Self::Port(_) => 10,
         Self::Any => 0,
      }
   }
}

/// A persisted policy rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
   pub id: RuleId,
   pub enabled: bool,
   pub app: AppMatcher,
   pub dest: DestMatcher,
   pub action: Action,
   pub duration: Duration,
   pub note: Option<String>,
   pub created_at: u64,
   pub updated_at: u64,
   pub last_matched: Option<u64>,
   pub hits: u64,
}

/// The answer to a prompt, expressed as the rule it should create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeRequest {
   pub action: Action,
   pub duration: Duration,
   pub dest: DestMatcher,
}

/// Builds the rule a prompt decision implies.
///
/// The application is resolved by the caller from the connection being prompted; this
/// function only fixes the parts the request itself determines, so timestamps and the
/// freshly minted id stay consistent.
pub fn rule_from_scope(id: RuleId, app: AppMatcher, scope: &ScopeRequest, now: u64) -> Rule {
   Rule {
      id,
      enabled: true,
      app,
      dest: scope.dest.clone(),
      action: scope.action,
      duration: scope.duration,
      note: None,
      created_at: now,
      updated_at: now,
      last_matched: None,
      hits: 0,
   }
}

/// Why a raw hostname could not be normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleError {
   EmptyHost,
   HostHasScheme,
   HostHasPort,
   HostHasPath,
   HostHasWhitespace,
   HostTooLong,
}

impl fmt::Display for RuleError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      let message = match self {
         Self::EmptyHost => "host is empty",
         Self::HostHasScheme => "host must not carry a URL scheme",
         Self::HostHasPort => "host must not carry a port",
         Self::HostHasPath => "host must not carry a path",
         Self::HostHasWhitespace => "host must not contain whitespace",
         Self::HostTooLong => "host is longer than 253 bytes",
      };
      f.write_str(message)
   }
}

impl std::error::Error for RuleError {}

/// Normalizes a hostname learned from DNS or typed into the prompt.
///
/// Lowercasing and stripping one trailing dot make `API.GitHub.com.` and `api.github.com`
/// the same rule scope. Anything that looks like a URL, a port or a path is rejected
/// rather than repaired: a caller that passes `host:443` has a bug, and guessing which
/// part was meant could silently scope a rule to the wrong destination.
///
/// IPv6 literals are accepted as hosts because a DNS answer can be addressed by literal;
/// the `:` check therefore runs only for non-literals.
pub fn normalize_host(raw: &str) -> Result<String, RuleError> {
   if raw.chars().any(char::is_whitespace) {
      return Err(RuleError::HostHasWhitespace);
   }
   if raw.contains("://") {
      return Err(RuleError::HostHasScheme);
   }

   let is_ipv6_literal = raw.parse::<std::net::IpAddr>().is_ok();
   if !is_ipv6_literal && raw.contains(':') {
      return Err(RuleError::HostHasPort);
   }
   if raw.contains('/') {
      return Err(RuleError::HostHasPath);
   }

   let host = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
   if host.is_empty() {
      return Err(RuleError::EmptyHost);
   }
   if host.len() > 253 {
      return Err(RuleError::HostTooLong);
   }
   Ok(host)
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::connection::{Endpoint, Family, L4Proto, ProcessInfo};
   use std::collections::HashSet;
   use std::net::{IpAddr, Ipv4Addr};
   use std::path::Path;

   fn process(exe: Option<&str>) -> Attribution {
      Attribution::Process(ProcessInfo {
         pid: 100,
         uid: 1000,
         exe: exe.map(PathBuf::from),
         comm: Some("firefox".to_owned()),
         cmdline: None,
      })
   }

   fn conn() -> Connection {
      Connection {
         family: Family::V4,
         proto: L4Proto::Tcp,
         local: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 50000,
         },
         remote: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(140, 82, 121, 78)),
            port: 443,
         },
         process: process(Some("/usr/lib/firefox/firefox")),
         domain: Some("api.github.com".to_owned()),
      }
   }

   #[test]
   fn new_unique_yields_distinct_hex_ids() {
      let ids: HashSet<String> = (0..1000).map(|_| RuleId::new_unique().to_string()).collect();
      assert_eq!(ids.len(), 1000, "RuleId::new_unique collided");
      for id in &ids {
         assert_eq!(id.len(), 16, "id {id:?} is not 16 hex chars");
         assert!(
            id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "id {id:?} is not lowercase hex"
         );
      }
   }

   #[test]
   fn normalize_host_lowercases_and_strips_one_trailing_dot() {
      assert_eq!(
         normalize_host("API.GitHub.COM.").unwrap(),
         "api.github.com"
      );
      assert_eq!(
         normalize_host("api.github.com..").unwrap(),
         "api.github.com."
      );
   }

   #[test]
   fn normalize_host_accepts_literals_and_fqdn() {
      assert_eq!(
         normalize_host("2001:DB8::1").unwrap(),
         "2001:db8::1"
      );
      assert_eq!(normalize_host("1.2.3.4").unwrap(), "1.2.3.4");
      assert_eq!(
         normalize_host("api.github.com").unwrap(),
         "api.github.com"
      );
   }

   #[test]
   fn normalize_host_rejects_caller_errors() {
      assert_eq!(
         normalize_host("https://x/y"),
         Err(RuleError::HostHasScheme)
      );
      assert_eq!(
         normalize_host("host:443"),
         Err(RuleError::HostHasPort)
      );
      assert_eq!(
         normalize_host("a b"),
         Err(RuleError::HostHasWhitespace)
      );
      assert_eq!(normalize_host(""), Err(RuleError::EmptyHost));
      assert_eq!(normalize_host("."), Err(RuleError::EmptyHost));
      assert_eq!(
         normalize_host("host/path"),
         Err(RuleError::HostHasPath)
      );
   }

   #[test]
   fn normalize_host_rejects_254_bytes_but_accepts_253() {
      let too_long = "a".repeat(254);
      assert_eq!(
         normalize_host(&too_long),
         Err(RuleError::HostTooLong)
      );
      let longest = "a".repeat(253);
      assert_eq!(normalize_host(&longest).unwrap().len(), 253);
   }

   #[test]
   fn app_matcher_semantics() {
      let exe = AppMatcher::Exe(PathBuf::from("/usr/lib/firefox/firefox"));
      assert!(exe.matches(&process(Some("/usr/lib/firefox/firefox"))));
      assert!(!exe.matches(&process(Some("/usr/bin/firefox"))));
      assert!(!exe.matches(&process(Some("/usr/lib/firefox/firefox-bin"))));
      assert!(!exe.matches(&Attribution::Unknown));

      assert!(AppMatcher::Any.matches(&Attribution::Unknown));
      assert!(AppMatcher::Any.matches(&process(None)));

      assert!(AppMatcher::Unknown.matches(&Attribution::Unknown));
      assert!(!AppMatcher::Unknown.matches(&process(Some("/usr/bin/x"))));
   }

   #[test]
   fn dest_matcher_ranks() {
      assert_eq!(
         DestMatcher::Domain {
            host: "a.example".to_owned(),
            subdomains: false
         }
         .rank(),
         40
      );
      assert_eq!(
         DestMatcher::Domain {
            host: "a.example".to_owned(),
            subdomains: true
         }
         .rank(),
         30
      );
      assert_eq!(
         DestMatcher::Ip("10.0.0.0/8".parse().unwrap()).rank(),
         20
      );
      assert_eq!(DestMatcher::Port(443).rank(), 10);
      assert_eq!(DestMatcher::Any.rank(), 0);
   }

   #[test]
   fn dest_matcher_domain_exact_and_subdomains() {
      let exact = DestMatcher::Domain {
         host: "api.github.com".to_owned(),
         subdomains: false,
      };
      assert!(exact.matches(&conn()));
      assert!(!exact.matches(&Connection {
         domain: Some("gist.github.com".to_owned()),
         ..conn()
      }));
      assert!(!exact.matches(&Connection {
         domain: None,
         ..conn()
      }));

      let wildcard = DestMatcher::Domain {
         host: "github.com".to_owned(),
         subdomains: true,
      };
      assert!(wildcard.matches(&conn()));
      assert!(wildcard.matches(&Connection {
         domain: Some("GITHUB.COM".to_owned()),
         ..conn()
      }));
      assert!(!wildcard.matches(&Connection {
         domain: Some("notgithub.com".to_owned()),
         ..conn()
      }));
      assert!(
         wildcard.matches(&Connection {
            domain: Some("github.com".to_owned()),
            ..conn()
         }),
         "subdomains: true covers the apex host too"
      );
   }

   #[test]
   fn dest_matcher_ip_and_port() {
      assert!(DestMatcher::Ip("140.82.0.0/16".parse().unwrap()).matches(&conn()));
      assert!(!DestMatcher::Ip("10.0.0.0/8".parse().unwrap()).matches(&conn()));
      assert!(DestMatcher::Port(443).matches(&conn()));
      assert!(!DestMatcher::Port(80).matches(&conn()));
      assert!(DestMatcher::Any.matches(&conn()));
   }

   #[test]
   fn rule_from_scope_copies_the_request() {
      let scope = ScopeRequest {
         action: Action::Deny,
         duration: Duration::Forever,
         dest: DestMatcher::Port(443),
      };
      let rule = rule_from_scope(
         RuleId::new_unique(),
         AppMatcher::Exe(PathBuf::from("/usr/bin/curl")),
         &scope,
         1234,
      );
      assert!(rule.enabled);
      assert_eq!(rule.action, Action::Deny);
      assert_eq!(rule.duration, Duration::Forever);
      assert_eq!(rule.dest, DestMatcher::Port(443));
      assert_eq!(
         rule.app,
         AppMatcher::Exe(PathBuf::from("/usr/bin/curl"))
      );
      assert_eq!(rule.created_at, 1234);
      assert_eq!(rule.updated_at, 1234);
      assert_eq!(rule.hits, 0);
      assert_eq!(rule.last_matched, None);
      assert_eq!(rule.note, None);
   }

   #[test]
   fn rule_serde_round_trip_is_lossless() {
      let rule = Rule {
         id: RuleId::new_unique(),
         enabled: false,
         app: AppMatcher::Exe(PathBuf::from("/usr/lib/firefox/firefox")),
         dest: DestMatcher::Domain {
            host: "api.github.com".to_owned(),
            subdomains: true,
         },
         action: Action::Allow,
         duration: Duration::Session,
         note: Some("seen in a prompt".to_owned()),
         created_at: 10,
         updated_at: 20,
         last_matched: Some(30),
         hits: 7,
      };
      let json = serde_json::to_string(&rule).unwrap();
      let back: Rule = serde_json::from_str(&json).unwrap();
      assert_eq!(back, rule);
   }

   #[test]
   fn every_matcher_variant_round_trips() {
      let apps = [
         AppMatcher::Any,
         AppMatcher::Exe(PathBuf::from("/usr/bin/curl")),
         AppMatcher::Unknown,
      ];
      for app in apps {
         let json = serde_json::to_string(&app).unwrap();
         assert_eq!(
            serde_json::from_str::<AppMatcher>(&json).unwrap(),
            app
         );
      }

      let dests = [
         DestMatcher::Any,
         DestMatcher::Domain {
            host: "example.com".to_owned(),
            subdomains: false,
         },
         DestMatcher::Domain {
            host: "example.com".to_owned(),
            subdomains: true,
         },
         DestMatcher::Ip("10.0.0.0/8".parse().unwrap()),
         DestMatcher::Port(53),
      ];
      for dest in dests {
         let json = serde_json::to_string(&dest).unwrap();
         assert_eq!(
            serde_json::from_str::<DestMatcher>(&json).unwrap(),
            dest
         );
      }
   }

   #[test]
   fn action_and_duration_serialize_lowercase() {
      assert_eq!(
         serde_json::to_string(&Action::Deny).unwrap(),
         "\"deny\""
      );
      assert_eq!(
         serde_json::to_string(&Duration::Forever).unwrap(),
         "\"forever\""
      );
   }

   #[test]
   fn exe_matcher_compares_paths_exactly() {
      let matcher = AppMatcher::Exe(PathBuf::from("/usr/lib/firefox/firefox"));
      // Path equality drops `.` components, so this is the same path; a different
      // basename or directory must not match.
      let attribution = process(Some("/usr/lib/firefox/./firefox"));
      assert!(matcher.matches(&attribution));
      assert!(!matcher.matches(&process(Some("/usr/bin/firefox"))));
      assert!(
         matcher.matches(&Attribution::Process(ProcessInfo {
            pid: 1,
            uid: 0,
            exe: Some(PathBuf::from("/usr/lib/firefox/firefox")),
            comm: None,
            cmdline: None,
         }))
      );
      assert_eq!(
         matcher,
         AppMatcher::Exe(PathBuf::from("/usr/lib/firefox").join(Path::new("firefox")))
      );
   }
}
