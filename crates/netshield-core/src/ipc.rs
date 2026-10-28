//! The newline-framed JSON protocol between `netshieldd` and its clients.
//!
//! The wire format is one JSON value per line over a `SOCK_STREAM` Unix socket, so a
//! reader needs a maximum frame size before it allocates and both sides need one
//! serialisation of the domain model. These types are that contract: the daemon and the
//! GUI share them rather than each growing its own copy.

use std::net::IpAddr;

use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::connection::{Attribution, Connection, Family, L4Proto};
use crate::rule::{Action, Duration, Rule, RuleId};

/// Bumped whenever the meaning of a message changes; a client that does not match is
/// rejected at `Hello` instead of failing later in the middle of a prompt.
pub const PROTOCOL_VERSION: u32 = 1;

/// The largest frame the daemon will accept or produce, including the newline.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Which front end is connected, so the daemon can shape what it sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientKind {
   Gui,
   Cli,
}

impl Serialize for Family {
   /// The wire spelling is fixed here rather than in `connection.rs`, which stays free of
   /// a serialisation dependency.
   fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
      serializer.serialize_str(match self {
         Self::V4 => "v4",
         Self::V6 => "v6",
      })
   }
}

impl<'de> Deserialize<'de> for Family {
   fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
      let label = String::deserialize(deserializer)?;
      match label.as_str() {
         "v4" => Ok(Self::V4),
         "v6" => Ok(Self::V6),
         other => Err(de::Error::unknown_variant(other, &["v4", "v6"])),
      }
   }
}

impl Serialize for L4Proto {
   /// Follows the crate's adjacent `kind`/`value` tagging, and `Other` keeps its numeric
   /// protocol number so a round trip does not lose what the packet actually carried.
   fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
      use serde::ser::SerializeMap;

      let mut map = serializer.serialize_map(None)?;
      match self {
         Self::Tcp => map.serialize_entry("kind", "tcp")?,
         Self::Udp => map.serialize_entry("kind", "udp")?,
         Self::Icmp => map.serialize_entry("kind", "icmp")?,
         Self::Other(proto) => {
            map.serialize_entry("kind", "other")?;
            map.serialize_entry("value", proto)?;
         }
      }
      map.end()
   }
}

/// Wire mirror of [`L4Proto`], including the protocol number `Other` carries.
#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
enum L4ProtoWire {
   Tcp,
   Udp,
   Icmp,
   Other(u8),
}

impl<'de> Deserialize<'de> for L4Proto {
   fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
      Ok(match L4ProtoWire::deserialize(deserializer)? {
         L4ProtoWire::Tcp => Self::Tcp,
         L4ProtoWire::Udp => Self::Udp,
         L4ProtoWire::Icmp => Self::Icmp,
         L4ProtoWire::Other(proto) => Self::Other(proto),
      })
   }
}

/// One connection as a client displays it.
///
/// This is a snapshot, not a handle: `domain` is the name the cache learned and
/// `domain_candidates` keeps the alternatives so the prompt can offer an exact choice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionView {
   pub app_name: String,
   pub exe: Option<String>,
   pub pid: Option<u32>,
   pub uid: Option<u32>,
   pub family: Family,
   pub proto: L4Proto,
   pub remote_ip: IpAddr,
   pub remote_port: u16,
   pub local_port: u16,
   pub domain: Option<String>,
   pub domain_candidates: Vec<String>,
}

impl ConnectionView {
   /// Projects a [`Connection`] plus the names the DNS cache learned for its address.
   ///
   /// An unattributable socket keeps `pid`/`exe` empty instead of inventing an owner;
   /// the prompt renders that as `unknown`.
   pub fn from_connection(conn: &Connection, candidates: &[String]) -> Self {
      let (pid, uid, exe) = match &conn.process {
         Attribution::Process(process) => (
            Some(process.pid),
            Some(process.uid),
            process.exe.as_ref().map(|path| path.to_string_lossy().into_owned()),
         ),
         Attribution::Unknown => (None, None, None),
      };

      Self {
         app_name: conn.app_name(),
         exe,
         pid,
         uid,
         family: conn.family,
         proto: conn.proto,
         remote_ip: conn.remote.addr,
         remote_port: conn.remote.port,
         local_port: conn.local.port,
         domain: candidates.first().cloned(),
         domain_candidates: candidates.to_vec(),
      }
   }
}

/// The destination scope a decision may create.
///
/// `Address` carries no host because it scopes to the exact remote address of the flow
/// being answered: the daemon has the connection, and an unattributed flow usually has no
/// learned name to carry. It is what keeps a narrow answer available when the broad
/// `AnyConnection` scope must not be offered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScopeChoice {
   AnyConnection,
   Domain {
      host: String,
      subdomains: bool,
   },
   Address,
   /// Every destination the prompt listed, each scoped to itself. This is what a group means
   /// when the user says "only these destinations"; it must never be inferred from the number
   /// of destinations.
   TheseDestinations,
}

/// A question the daemon puts to the user.
///
/// One prompt covers every destination of one application that is waiting on an answer, so
/// the user decides a page's several origins once instead of once per origin. `connection`
/// is kept as the first destination for a client that predates `dests`; a current client
/// lists `dests`, which is every destination the answer will cover. `dests` defaults to
/// empty so an older daemon's frame still decodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptRequest {
   pub id: u64,
   /// The first destination, retained for older readers.
   pub connection: ConnectionView,
   /// Every destination the answer will cover.
   #[serde(default)]
   pub dests: Vec<ConnectionView>,
   pub timeout_secs: u64,
   /// False when no name was learned, so the UI disables domain scope rather than
   /// guessing one.
   pub domain_scope_available: bool,
   /// Other prompts already queued behind this one.
   pub pending: usize,
}

/// The user's answer to a [`PromptRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideRequest {
   pub prompt_id: u64,
   pub action: Action,
   pub duration: Duration,
   pub scope: ScopeChoice,
}

/// A message from a client to the daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Request {
   Hello { version: u32, client: ClientKind },
   Subscribe,
   Decide(DecideRequest),
   ListRules,
   UpsertRule { rule: Rule },
   DeleteRule { id: RuleId },
   SetRuleEnabled { id: RuleId, enabled: bool },
   SetMode { mode: Mode },
   Status,
}

/// Whether new connections may reach the network without asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
   Alert,
   Silent,
}

/// How a prompt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Resolution {
   Allowed,
   Denied,
   TimedOut,
   /// The daemon was in silent mode, so the new connection was allowed without asking.
   SilentAutoAllowed,
}

/// A connection that reached a verdict, for the GUI's activity list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionEvent {
   pub at: u64,
   pub connection: ConnectionView,
   pub allowed: bool,
   pub matched_rule: Option<RuleId>,
   pub via_prompt: bool,
}

/// A snapshot of the daemon, shown in the GUI's status panel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
   pub daemon_pid: u32,
   pub mode: Mode,
   pub rule_count: usize,
   pub pending_prompts: usize,
   pub queue_num: u16,
   pub queue_drops: u64,
   /// True when the daemon verified the nftables table at startup, whether it adopted an
   /// existing one or installed a fresh one. False is not a fail-open promise: the only
   /// way to observe enforcement from inside the daemon is this check, and an unverified
   /// table is a startup error, not a running state.
   pub table_verified: bool,
   pub started_at: u64,
}

/// A message from the daemon to a client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Response {
   Hello {
      version: u32,
      daemon_pid: u32,
      mode: Mode,
      rule_count: usize,
   },
   Rules {
      rules: Vec<Rule>,
   },
   Prompt(PromptRequest),
   PromptClosed {
      id: u64,
      resolution: Resolution,
   },
   Connection(ConnectionEvent),
   Status(StatusInfo),
   Error {
      message: String,
   },
}

/// Serialises one value as a single newline-terminated frame.
///
/// The newline is part of the frame, so a reader can hand the daemon a line without
/// re-terminating it.
pub fn encode_line<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
   let mut bytes = serde_json::to_vec(value)?;
   bytes.push(b'\n');
   Ok(bytes)
}

/// Deserialises one frame, tolerating the trailing newline a socket read left in place.
pub fn decode_line<T: DeserializeOwned>(line: &[u8]) -> Result<T, serde_json::Error> {
   let body = line.strip_suffix(b"\n").unwrap_or(line);
   serde_json::from_slice(body)
}

/// Returns whether `len` bytes fit the protocol's frame limit.
pub fn frame_len_ok(len: usize) -> bool {
   len <= MAX_FRAME_LEN
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::rule::{AppMatcher, DestMatcher, RuleId};
   use std::net::{Ipv4Addr, Ipv6Addr};
   use std::path::PathBuf;

   fn view() -> ConnectionView {
      ConnectionView {
         app_name: "firefox".to_owned(),
         exe: Some("/usr/lib/firefox/firefox".to_owned()),
         pid: Some(42),
         uid: Some(1000),
         family: Family::V6,
         proto: L4Proto::Other(132),
         remote_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
         remote_port: 443,
         local_port: 51_000,
         domain: Some("example.com".to_owned()),
         domain_candidates: vec!["example.com".to_owned()],
      }
   }

   fn rule() -> Rule {
      Rule {
         id: RuleId::new_unique(),
         enabled: true,
         app: AppMatcher::Exe(PathBuf::from("/usr/bin/curl")),
         dest: DestMatcher::Domain {
            host: "example.com".to_owned(),
            subdomains: false,
         },
         action: Action::Allow,
         duration: Duration::Session,
         note: None,
         created_at: 1,
         updated_at: 2,
         last_matched: None,
         hits: 0,
      }
   }

   fn requests() -> Vec<Request> {
      vec![
         Request::Hello {
            version: PROTOCOL_VERSION,
            client: ClientKind::Gui,
         },
         Request::Subscribe,
         Request::Decide(DecideRequest {
            prompt_id: 7,
            action: Action::Deny,
            duration: Duration::Once,
            scope: ScopeChoice::Domain {
               host: "example.com".to_owned(),
               subdomains: true,
            },
         }),
         Request::ListRules,
         Request::UpsertRule { rule: rule() },
         Request::DeleteRule {
            id: RuleId::new_unique(),
         },
         Request::SetRuleEnabled {
            id: RuleId::new_unique(),
            enabled: false,
         },
         Request::SetMode { mode: Mode::Silent },
         Request::Status,
      ]
   }

   fn responses() -> Vec<Response> {
      vec![
         Response::Hello {
            version: PROTOCOL_VERSION,
            daemon_pid: 99,
            mode: Mode::Alert,
            rule_count: 3,
         },
         Response::Rules {
            rules: vec![rule()],
         },
         Response::Prompt(PromptRequest {
            id: 1,
            connection: view(),
            dests: vec![view()],
            timeout_secs: 30,
            domain_scope_available: true,
            pending: 2,
         }),
         Response::PromptClosed {
            id: 1,
            resolution: Resolution::SilentAutoAllowed,
         },
         Response::Connection(ConnectionEvent {
            at: 123,
            connection: view(),
            allowed: true,
            matched_rule: Some(RuleId::new_unique()),
            via_prompt: false,
         }),
         Response::Status(StatusInfo {
            daemon_pid: 99,
            mode: Mode::Silent,
            rule_count: 4,
            pending_prompts: 1,
            queue_num: 0,
            queue_drops: 2,
            table_verified: true,
            started_at: 100,
         }),
         Response::Error {
            message: "bad frame".to_owned(),
         },
      ]
   }

   #[test]
   fn encoded_frame_ends_with_exactly_one_newline() {
      for request in requests() {
         let bytes = encode_line(&request).expect("serialisable request");
         assert_eq!(bytes.last(), Some(&b'\n'));
         assert_eq!(
            bytes.iter().filter(|byte| **byte == b'\n').count(),
            1
         );
      }
   }

   #[test]
   fn requests_round_trip() {
      for request in requests() {
         let bytes = encode_line(&request).expect("serialisable request");
         let decoded = decode_line::<Request>(&bytes).expect("decodable request");
         assert_eq!(decoded, request);
      }
   }

   #[test]
   fn responses_round_trip() {
      for response in responses() {
         let bytes = encode_line(&response).expect("serialisable response");
         let decoded = decode_line::<Response>(&bytes).expect("decodable response");
         assert_eq!(decoded, response);
      }
   }

   /// A frame from a daemon that predates `dests` must still decode, with an empty list
   /// rather than a missing field error; the retained `connection` is what such a client
   /// shows.
   #[test]
   fn a_prompt_frame_without_dests_decodes_with_an_empty_vec() {
      let mut frame = serde_json::to_value(Response::Prompt(PromptRequest {
         id: 3,
         connection: view(),
         dests: vec![view(), view()],
         timeout_secs: 30,
         domain_scope_available: true,
         pending: 0,
      }))
      .expect("serialisable response");
      let body = frame.get_mut("value").expect("the prompt is the variant's value");
      body.as_object_mut().expect("a prompt is an object").remove("dests");

      let bytes = encode_line(&frame).expect("serialisable frame");
      let Response::Prompt(prompt) = decode_line::<Response>(&bytes).expect("decodable frame")
      else {
         panic!("the frame is a prompt");
      };
      assert!(prompt.dests.is_empty());
      assert_eq!(prompt.connection, view());
      assert_eq!(prompt.id, 3);
   }

   #[test]
   fn scope_choice_address_round_trips() {
      let scope = ScopeChoice::Address;
      let bytes = encode_line(&scope).expect("serialisable scope");
      assert_eq!(
         decode_line::<ScopeChoice>(&bytes).expect("decodable scope"),
         scope
      );
      assert_eq!(
         serde_json::to_value(&scope).expect("serialisable scope"),
         serde_json::json!({ "kind": "address" })
      );
   }

   #[test]
   fn scope_choice_these_destinations_serializes_without_a_value() {
      let scope = ScopeChoice::TheseDestinations;
      let bytes = encode_line(&scope).expect("serialisable scope");
      assert_eq!(
         serde_json::to_value(&scope).expect("serialisable scope"),
         serde_json::json!({ "kind": "these_destinations" })
      );
      assert_eq!(
         decode_line::<ScopeChoice>(&bytes).expect("decodable scope"),
         scope
      );
   }

   #[test]
   fn trailing_newline_is_tolerated_but_arrays_are_not() {
      assert_eq!(
         decode_line::<Request>(b"{\"kind\":\"subscribe\"}\n").expect("decodable"),
         Request::Subscribe
      );
      assert!(decode_line::<Request>(b"[]").is_err());
      assert!(decode_line::<Request>(b"[{\"kind\":\"subscribe\"}]").is_err());
   }

   #[test]
   fn frame_len_boundary_is_inclusive() {
      assert!(frame_len_ok(0));
      assert!(frame_len_ok(MAX_FRAME_LEN));
      assert!(!frame_len_ok(MAX_FRAME_LEN + 1));
   }

   #[test]
   fn view_copies_endpoints_and_the_first_candidate() {
      let conn = Connection {
         family: Family::V4,
         proto: L4Proto::Tcp,
         local: crate::connection::Endpoint {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 51_234,
         },
         remote: crate::connection::Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port: 443,
         },
         process: Attribution::Process(crate::connection::ProcessInfo {
            pid: 7,
            uid: 1000,
            exe: Some(PathBuf::from("/usr/lib/firefox/firefox")),
            comm: Some("firefox".to_owned()),
            cmdline: None,
         }),
         domain: Some("ignored.example".to_owned()),
      };
      let candidates = vec!["api.github.com".to_owned(), "github.com".to_owned()];
      let view = ConnectionView::from_connection(&conn, &candidates);

      assert_eq!(view.app_name, "firefox");
      assert_eq!(
         view.exe.as_deref(),
         Some("/usr/lib/firefox/firefox")
      );
      assert_eq!(view.pid, Some(7));
      assert_eq!(view.uid, Some(1000));
      assert_eq!(view.family, Family::V4);
      assert_eq!(view.proto, L4Proto::Tcp);
      assert_eq!(
         view.remote_ip,
         IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
      );
      assert_eq!(view.remote_port, 443);
      assert_eq!(view.local_port, 51_234);
      assert_eq!(view.domain.as_deref(), Some("api.github.com"));
      assert_eq!(view.domain_candidates, candidates);
   }

   #[test]
   fn unknown_attribution_leaves_pid_and_exe_empty() {
      let conn = Connection {
         family: Family::V6,
         proto: L4Proto::Udp,
         local: crate::connection::Endpoint {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 5353,
         },
         remote: crate::connection::Endpoint {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 53,
         },
         process: Attribution::Unknown,
         domain: None,
      };
      let view = ConnectionView::from_connection(&conn, &[]);
      assert_eq!(view.app_name, "unknown");
      assert_eq!(view.pid, None);
      assert_eq!(view.exe, None);
      assert_eq!(view.uid, None);
      assert_eq!(view.domain, None);
      assert!(view.domain_candidates.is_empty());
   }
}
