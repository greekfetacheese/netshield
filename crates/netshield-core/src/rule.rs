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

   /// The eight bytes this identifier is stored under, or `None` when it is not sixteen hex digits.
   ///
   /// [`RuleId::new_unique`] always produces that form, but an id arriving over the control socket
   /// is whatever the client sent, so the store has to be able to refuse one instead of writing a
   /// key it could never read back.
   pub fn to_bytes(&self) -> Option<[u8; 8]> {
      let raw = self.0.as_bytes();
      if raw.len() != 16 {
         return None;
      }
      let mut bytes = [0u8; 8];
      for (slot, pair) in bytes.iter_mut().zip(raw.as_chunks::<2>().0) {
         *slot = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
      }
      Some(bytes)
   }

   /// Rebuilds an identifier from its stored form, the inverse of [`RuleId::to_bytes`].
   ///
   /// Reconstructing rather than minting keeps the identifier stable across a restart: every
   /// reference the GUI holds and every prompt id that mentioned the rule depends on it.
   pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
      if bytes.len() != 8 {
         return None;
      }
      let mut hex = String::with_capacity(16);
      for byte in bytes {
         hex.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
         hex.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
      }
      Some(Self(hex))
   }
}

impl fmt::Display for RuleId {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(&self.0)
   }
}

/// Lowercase hex, the only form a stored rule id takes.
const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// The value of one lowercase hex digit.
fn hex_nibble(byte: u8) -> Option<u8> {
   match byte {
      b'0'..=b'9' => Some(byte - b'0'),
      b'a'..=b'f' => Some(byte - b'a' + 10),
      _ => None,
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
   Domain {
      host: String,
      subdomains: bool,
   },
   Ip(IpNet),
   Port(u16),
   /// Several destinations governed by one rule, matched as a union.
   ///
   /// A rule scoped to a list must not become one row per address in the table, so the list
   /// lives inside the matcher. [`DestMatcher::from_entries`] is the only constructor: it keeps
   /// the invariant that a set is never nested, never holds `Any`, never repeats an entry and
   /// never holds fewer than two entries.
   Set(Vec<DestMatcher>),
}

impl DestMatcher {
   /// Returns whether this matcher covers the connection's remote end.
   pub fn matches(&self, conn: &Connection) -> bool {
      self.matched_rank(conn).is_some()
   }

   /// The specificity of the entry that matched, or `None` when nothing matches.
   ///
   /// This is `RuleSet::evaluate`'s destination key: exact domain 40, subdomain 30, IP 20,
   /// port 10, any 0, and a set answers with the best of its matching entries — so a list ranks
   /// exactly as the separate rules it stands for would, not as its most specific entry on every
   /// flow. The ordering is deliberately independent of the application dimension so application
   /// scope can be the outer key.
   ///
   /// A `Domain` matcher ranks the connection's primary name and every alternate live name for
   /// the same address, answering with the best of them: the name a prompt displays is not the
   /// only name that address carries, and a rule must not depend on which one was learned last.
   pub fn matched_rank(&self, conn: &Connection) -> Option<u8> {
      match self {
         Self::Any => Some(0),
         Self::Domain { host, subdomains } => conn
            .domain
            .iter()
            .map(String::as_str)
            .chain(conn.also_domains.iter().map(String::as_str))
            .filter_map(|domain| domain_rank(domain, host, *subdomains))
            .max(),
         Self::Ip(net) => net.contains(conn.remote.addr).then_some(20),
         Self::Port(port) => (conn.remote.port == *port).then_some(10),
         Self::Set(entries) => entries.iter().filter_map(|entry| entry.matched_rank(conn)).max(),
      }
   }

   /// Canonicalises a list of destinations into one matcher.
   ///
   /// Nested sets are flattened, repeated entries collapse to their first occurrence (so the
   /// order the user typed survives), a list that contains "anywhere" is "anywhere" — the union
   /// with everything is everything — and a list of one is simply that entry, which keeps every
   /// existing single-destination rule byte-identical. An empty list is `None`: a rule that
   /// matches nothing is not a narrowing, it is a mistake.
   pub fn from_entries(entries: Vec<Self>) -> Option<Self> {
      let mut unique: Vec<Self> = Vec::with_capacity(entries.len());
      for entry in entries {
         let entry = match entry {
            Self::Set(nested) => match Self::from_entries(nested) {
               Some(matcher) => matcher,
               // An empty nested set contributes nothing.
               None => continue,
            },
            other => other,
         };
         if entry == Self::Any {
            return Some(Self::Any);
         }
         if !unique.contains(&entry) {
            unique.push(entry);
         }
      }

      match unique.len() {
         0 => None,
         1 => unique.pop(),
         _ => Some(Self::Set(unique)),
      }
   }
}

/// How specifically `domain` matches the rule host: 40 for an exact name, 30 for a subdomain
/// when the rule allows subdomains, `None` otherwise.
///
/// This is the single per-name rule shared by the primary and the alternate names, so the two
/// paths cannot drift apart.
fn domain_rank(domain: &str, host: &str, subdomains: bool) -> Option<u8> {
   if domain.eq_ignore_ascii_case(host) {
      return Some(40);
   }
   if !subdomains {
      return None;
   }
   let domain = domain.to_ascii_lowercase();
   (domain.len() > host.len() + 1 && domain.ends_with(&format!(".{}", host.to_ascii_lowercase())))
      .then_some(30)
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

/// Why a rule from the control socket is refused, or `None` when it may be accepted.
///
/// The socket may express everything a prompt's answer can produce and nothing more. A rule that
/// governs every application *and* every destination is not a scope any prompt offers — the alert
/// drops the app-wide row for an unattributed flow for exactly this reason — and accepting one would
/// turn a single request into a silent allow-all that also survives a restart. The rules store can
/// still hold such a rule when the owner edits it in deliberately.
pub fn socket_rule_refusal(rule: &Rule) -> Option<&'static str> {
   let every_app = matches!(rule.app, AppMatcher::Any | AppMatcher::Unknown);
   if every_app && covers_every_destination(&rule.dest) {
      Some(
         "a rule for every application and every destination is not accepted over the control \
          socket; add it to the rules store deliberately",
      )
   } else {
      None
   }
}

/// Whether `dest` matches every address — `Any` written another way.
///
/// `DestMatcher::Ip` with prefix `0` is a whole address space, so a rule for "any application" over it is
/// the same silent allow-all the socket refuses in its `Any` form; a `Set` answers for its members.
fn covers_every_destination(dest: &DestMatcher) -> bool {
   match dest {
      DestMatcher::Any => true,
      DestMatcher::Ip(net) => net.prefix == 0,
      DestMatcher::Set(entries) => entries.iter().any(covers_every_destination),
      DestMatcher::Domain { .. } | DestMatcher::Port(_) => false,
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
   use crate::ruleset::{Outcome, RuleSet};
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
         also_domains: Vec::new(),
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
      for (raw, expected) in [
         ("API.GitHub.COM.", "api.github.com"),
         ("api.github.com..", "api.github.com."),
         ("2001:DB8::1", "2001:db8::1"),
         ("1.2.3.4", "1.2.3.4"),
         ("api.github.com", "api.github.com"),
      ] {
         assert_eq!(normalize_host(raw).unwrap(), expected, "{raw:?}");
      }
   }

   #[test]
   fn normalize_host_rejects_caller_errors() {
      for (raw, expected) in [
         ("https://x/y", RuleError::HostHasScheme),
         ("host:443", RuleError::HostHasPort),
         ("a b", RuleError::HostHasWhitespace),
         ("", RuleError::EmptyHost),
         (".", RuleError::EmptyHost),
         ("host/path", RuleError::HostHasPath),
      ] {
         assert_eq!(normalize_host(raw), Err(expected), "{raw:?}");
      }

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
   fn a_domain_rule_matches_every_live_name_for_the_address() {
      let shadowed = Connection {
         domain: Some("cdn.example".to_owned()),
         also_domains: vec!["evil.com".to_owned(), "a.evil.com".to_owned()],
         ..conn()
      };

      let exact_alt = DestMatcher::Domain {
         host: "evil.com".to_owned(),
         subdomains: false,
      };
      assert_eq!(
         exact_alt.matched_rank(&shadowed),
         Some(40),
         "an exact rule on an alternate live name must match"
      );
      assert_eq!(
         DestMatcher::Domain {
            host: "cdn.example".to_owned(),
            subdomains: false,
         }
         .matched_rank(&shadowed),
         Some(40),
         "an exact rule on the primary name still matches"
      );
      assert_eq!(
         DestMatcher::Domain {
            host: "unrelated.example".to_owned(),
            subdomains: false,
         }
         .matched_rank(&shadowed),
         None,
         "a name that is neither primary nor alternate does not match"
      );
      assert_eq!(
         DestMatcher::Domain {
            host: "evil.com".to_owned(),
            subdomains: true,
         }
         .matched_rank(&shadowed),
         Some(40),
         "the exact alternate outranks its subdomain entry"
      );

      let subdomain_alt = DestMatcher::Domain {
         host: "evil.com".to_owned(),
         subdomains: true,
      };
      let only_nested = Connection {
         domain: Some("cdn.example".to_owned()),
         also_domains: vec!["a.evil.com".to_owned()],
         ..conn()
      };
      assert_eq!(
         subdomain_alt.matched_rank(&only_nested),
         Some(30),
         "the subdomain form matches a nested alternate live name"
      );
   }

   #[test]
   fn a_deny_on_a_shadowed_name_still_wins() {
      let mut set = RuleSet::new();
      for (host, action, updated_at) in [
         ("cdn.example", Action::Allow, 0),
         ("evil.com", Action::Deny, 0),
      ] {
         set.upsert(rule_from_scope(
            RuleId::new_unique(),
            AppMatcher::Any,
            &ScopeRequest {
               action,
               duration: Duration::Forever,
               dest: DestMatcher::Domain {
                  host: host.to_owned(),
                  subdomains: false,
               },
            },
            updated_at,
         ));
      }

      let connection = Connection {
         domain: Some("cdn.example".to_owned()),
         also_domains: vec!["evil.com".to_owned()],
         ..conn()
      };
      assert!(
         matches!(set.evaluate(&connection), Outcome::Deny { .. }),
         "a deny on an alternate live name must not be shadowed by an allow on the primary"
      );
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
   fn the_rule_and_matcher_wire_shapes() {
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
         DestMatcher::Set(vec![
            DestMatcher::Domain {
               host: "example.com".to_owned(),
               subdomains: false,
            },
            DestMatcher::Ip("10.0.0.0/8".parse().unwrap()),
         ]),
      ];
      for dest in dests {
         let json = serde_json::to_string(&dest).unwrap();
         assert_eq!(
            serde_json::from_str::<DestMatcher>(&json).unwrap(),
            dest
         );
      }

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

   #[test]
   fn from_entries_collapses_dedupes_and_flattens() {
      let domain = DestMatcher::Domain {
         host: "github.com".to_owned(),
         subdomains: false,
      };
      let net = DestMatcher::Ip("10.0.0.0/8".parse().unwrap());

      assert_eq!(
         DestMatcher::from_entries(vec![domain.clone()]),
         Some(domain.clone()),
         "one entry must collapse to that matcher"
      );
      assert_eq!(DestMatcher::from_entries(Vec::new()), None);
      assert_eq!(
         DestMatcher::from_entries(vec![domain.clone(), domain.clone(), net.clone()]),
         Some(DestMatcher::Set(vec![
            domain.clone(),
            net.clone()
         ])),
         "duplicates collapse and the typed order is kept"
      );
      assert_eq!(
         DestMatcher::from_entries(vec![
            DestMatcher::Set(vec![domain.clone()]),
            net.clone()
         ]),
         Some(DestMatcher::Set(vec![
            domain.clone(),
            net.clone()
         ])),
         "a nested set is flattened"
      );
      assert_eq!(
         DestMatcher::from_entries(vec![domain.clone(), DestMatcher::Any]),
         Some(DestMatcher::Any),
         "a union with anywhere is anywhere"
      );
      assert_eq!(
         DestMatcher::from_entries(vec![DestMatcher::Set(vec![DestMatcher::Any])]),
         Some(DestMatcher::Any),
         "anywhere nested inside a set still answers for the whole list"
      );
   }

   #[test]
   fn a_set_matches_any_of_its_entries() {
      let set = DestMatcher::Set(vec![
         DestMatcher::Domain {
            host: "example.com".to_owned(),
            subdomains: false,
         },
         DestMatcher::Ip("10.0.0.0/8".parse().unwrap()),
      ]);

      assert!(
         set.matches(&Connection {
            domain: Some("example.com".to_owned()),
            ..conn()
         }),
         "the domain entry matches"
      );
      assert!(
         set.matches(&Connection {
            domain: None,
            remote: Endpoint {
               addr: IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
               port: 443,
            },
            ..conn()
         }),
         "the address entry matches without a learned name"
      );
      assert!(
         !set.matches(&Connection {
            domain: Some("gist.github.com".to_owned()),
            ..conn()
         }),
         "an entry that matches alone cannot make the set match"
      );
   }

   #[test]
   fn a_rule_for_every_app_and_destination_is_refused() {
      for app in [AppMatcher::Any, AppMatcher::Unknown] {
         let rule = rule_from_scope(
            RuleId::new_unique(),
            app.clone(),
            &ScopeRequest {
               action: Action::Allow,
               duration: Duration::Forever,
               dest: DestMatcher::Any,
            },
            0,
         );
         assert!(
            socket_rule_refusal(&rule).is_some(),
            "{app:?} over any destination must be refused"
         );
      }
   }

   #[test]
   fn a_zero_prefix_destination_is_refused_for_every_app() {
      let global = |app: AppMatcher, dest: DestMatcher| {
         rule_from_scope(
            RuleId::new_unique(),
            app,
            &ScopeRequest {
               action: Action::Allow,
               duration: Duration::Forever,
               dest,
            },
            0,
         )
      };

      for dest in [
         DestMatcher::Ip("0.0.0.0/0".parse().expect("a global v4 net")),
         DestMatcher::Ip("::/0".parse().expect("a global v6 net")),
         DestMatcher::Set(vec![
            DestMatcher::Ip("0.0.0.0/0".parse().expect("a global v4 net")),
            DestMatcher::Ip("192.0.2.1/32".parse().expect("a lit net")),
         ]),
      ] {
         for app in [AppMatcher::Any, AppMatcher::Unknown] {
            assert!(
               socket_rule_refusal(&global(app.clone(), dest.clone())).is_some(),
               "{app:?} over {dest:?} covers every address and must be refused"
            );
         }
      }

      // One application over every address is a prompt's own scope, and stays accepted.
      let exe = AppMatcher::Exe(PathBuf::from("/usr/bin/firefox"));
      assert_eq!(
         socket_rule_refusal(&global(
            exe,
            DestMatcher::Ip("0.0.0.0/0".parse().expect("a global v4 net")),
         )),
         None,
         "an application-wide rule over every address is expressible"
      );
   }

   #[test]
   fn a_narrow_rule_is_accepted_from_the_socket() {
      let exe = AppMatcher::Exe(PathBuf::from("/usr/bin/firefox"));
      let any_dest = rule_from_scope(
         RuleId::new_unique(),
         exe.clone(),
         &ScopeRequest {
            action: Action::Allow,
            duration: Duration::Forever,
            dest: DestMatcher::Any,
         },
         0,
      );
      assert_eq!(
         socket_rule_refusal(&any_dest),
         None,
         "one application over every destination is a prompt's own scope"
      );
      let any_app = rule_from_scope(
         RuleId::new_unique(),
         AppMatcher::Any,
         &ScopeRequest {
            action: Action::Deny,
            duration: Duration::Session,
            dest: DestMatcher::Ip("192.0.2.0/24".parse().expect("literal")),
         },
         0,
      );
      assert_eq!(
         socket_rule_refusal(&any_app),
         None,
         "any application over one network is also offered"
      );
   }

   #[test]
   fn a_rule_id_survives_its_stored_form() {
      let id = RuleId::new_unique();
      let bytes = id.to_bytes().expect("a minted id is sixteen hex digits");
      assert_eq!(RuleId::from_bytes(&bytes), Some(id.clone()));
      assert_eq!(bytes.len(), 8);

      assert_eq!(RuleId::from_bytes(&[0u8; 7]), None);
      assert_eq!(RuleId::from_bytes(&[0u8; 9]), None);
      for bad in ["", "xyz", "00112233445566778899", "0011223344556 78"] {
         assert_eq!(
            RuleId::from_bytes(&[]),
            None,
            "a short slice is never an id ({bad})"
         );
      }
   }
}
