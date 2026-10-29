//! A bounded, render-ready history of connection events.
//!
//! The daemon streams events for as long as the GUI runs, so the history must never grow
//! without bound: the oldest rows are dropped and counted instead. Each row is flattened
//! when it is pushed so the table does no formatting work on every frame.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use netshield_core::ipc::{ConnectionEvent, ConnectionView};
use netshield_core::rule::RuleId;

/// Seconds in a day. The clock is UTC because this crate deliberately has no timezone
/// dependency; the table header says so rather than inventing a local offset.
const SECS_PER_DAY: u64 = 86_400;

/// One rendered connection, already flattened for the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
   /// Unix seconds from the event, kept for tests and later sorting.
   pub at: u64,
   /// `HH:MM:SS` in UTC.
   pub time: String,
   /// App name, else the exe basename, else `unknown`.
   pub app: String,
   /// The process path the daemon reported, kept for the Connections detail pane.
   pub exe: Option<String>,
   /// Domain when known, else the remote address.
   pub dest: String,
   /// `<ip>:<port>`, with brackets around an IPv6 address.
   pub addr: String,
   /// `tcp`, `udp`, `icmp`, or `other`.
   pub proto: String,
   pub allowed: bool,
   pub via_prompt: bool,
   /// The rule that decided this connection, resolved against the rule list at render time.
   pub rule_id: Option<RuleId>,
   /// First domain candidate when no domain was resolved; the table italicises it so the
   /// difference between a name and an address stays visible.
   pub candidate: Option<String>,
}

impl Row {
   /// Flattens one event, preferring the values a person recognises over raw wire data.
   fn from_event(event: &ConnectionEvent) -> Self {
      let view = &event.connection;
      let domain = view.domain.as_deref().filter(|name| !name.is_empty());
      Self {
         at: event.at,
         time: clock(event.at),
         app: app_label(view),
         exe: view.exe.clone(),
         dest: domain.map_or_else(|| view.remote_ip.to_string(), str::to_owned),
         addr: SocketAddr::new(view.remote_ip, view.remote_port).to_string(),
         proto: view.proto.as_str().to_owned(),
         allowed: event.allowed,
         via_prompt: event.via_prompt,
         rule_id: event.matched_rule.clone(),
         candidate: if domain.is_none() {
            view.domain_candidates.first().cloned()
         } else {
            None
         },
      }
   }
}

/// Formats unix seconds as `HH:MM:SS` in UTC.
pub fn clock(at: u64) -> String {
   let secs = at % SECS_PER_DAY;
   format!(
      "{:02}:{:02}:{:02}",
      secs / 3600,
      (secs / 60) % 60,
      secs % 60
   )
}

/// Picks the most human name available for the process behind a connection.
fn app_label(view: &ConnectionView) -> String {
   if !view.app_name.is_empty() {
      return view.app_name.clone();
   }
   match view.exe.as_deref().and_then(|exe| Path::new(exe).file_name()) {
      Some(name) => name.to_string_lossy().into_owned(),
      None => "unknown".to_owned(),
   }
}

/// One application's slice of the log: a ring of its own, so the busiest process on the
/// machine cannot evict a quiet one's history.
#[derive(Clone, Debug)]
struct AppLog {
   /// This application's rows, oldest first, never more than `ConnectionLog::per_app`.
   rows: VecDeque<Arc<Row>>,
   /// Unix seconds of the newest row, which is what picks the application to evict.
   last_at: u64,
}

/// A bounded, render-ready history of connection events, capped per application.
///
/// The cap is per process on purpose: one p2p client opening hundreds of flows a second used
/// to fill a single global ring and evict every other process from the history.
#[derive(Debug)]
pub struct ConnectionLog {
   /// One ring per application, in the order the applications were first seen. That order is
   /// not an output order — the Connections page sorts what it draws.
   apps: Vec<AppLog>,
   /// Application name → slot in `apps`.
   index: HashMap<String, usize>,
   /// How many rows one application may keep.
   per_app: usize,
   /// How many applications the log tracks at once.
   max_apps: usize,
   dropped: u64,
   /// Bumped whenever the contents change, so the UI can cache a derived line list and
   /// rebuild it only when the log actually moved.
   version: u64,
}

impl ConnectionLog {
   /// Creates a log that keeps at most `per_app` rows for each of `max_apps` applications.
   pub fn new(per_app: usize, max_apps: usize) -> Self {
      Self {
         apps: Vec::with_capacity(max_apps),
         index: HashMap::new(),
         per_app,
         max_apps,
         dropped: 0,
         version: 0,
      }
   }

   /// Appends one event, dropping the row that fell out of its own application's ring.
   pub fn push(&mut self, event: &ConnectionEvent) {
      if self.per_app == 0 || self.max_apps == 0 {
         self.dropped += 1;
         self.version += 1;
         return;
      }
      let row = Arc::new(Row::from_event(event));
      let app = row.app.clone();
      let at = row.at;
      let slot = match self.index.get(&app).copied() {
         Some(slot) => slot,
         None => {
            if self.apps.len() >= self.max_apps {
               self.evict_the_quietest();
            }
            self.apps.push(AppLog {
               rows: VecDeque::new(),
               last_at: at,
            });
            self.index.insert(app, self.apps.len() - 1);
            self.apps.len() - 1
         }
      };

      let mut evicted = 0_u64;
      {
         let log = &mut self.apps[slot];
         while log.rows.len() >= self.per_app {
            log.rows.pop_front();
            evicted += 1;
         }
         log.last_at = log.last_at.max(at);
         log.rows.push_back(row);
      }
      self.dropped += evicted;
      self.version += 1;
   }

   /// Drops the application that has been quiet longest, so a new one fits.
   ///
   /// Ties break on the name, so the choice never depends on hash order.
   fn evict_the_quietest(&mut self) {
      let quietest = self
         .index
         .iter()
         .min_by(
            |(left_name, left_slot), (right_name, right_slot)| {
               self.apps[**left_slot]
                  .last_at
                  .cmp(&self.apps[**right_slot].last_at)
                  .then_with(|| left_name.cmp(right_name))
            },
         )
         .map(|(name, slot)| (name.clone(), *slot));
      let Some((name, slot)) = quietest else {
         return;
      };

      let removed = self.apps.remove(slot);
      self.dropped += removed.rows.len() as u64;
      self.index.remove(&name);
      // The slots after the removed application shifted down by one.
      for index in self.index.values_mut() {
         if *index > slot {
            *index -= 1;
         }
      }
   }

   /// Every row, oldest first within each application.
   ///
   /// The interleaving between applications is not an order: the Connections page sorts the
   /// rows it draws, so a caller that needs one sorts by `at` itself.
   pub fn rows(&self) -> impl Iterator<Item = &Row> {
      self.apps.iter().flat_map(|log| log.rows.iter()).map(AsRef::as_ref)
   }

   /// A frozen copy of the log for a background rebuild.
   ///
   /// The rows are shared, so this is a refcount bump per row rather than a deep clone of every
   /// string in the history; the copy never moves while a derivation reads it, which is the whole
   /// point of taking one.
   pub fn snapshot(&self) -> Self {
      Self {
         apps: self.apps.clone(),
         index: self.index.clone(),
         per_app: self.per_app,
         max_apps: self.max_apps,
         dropped: self.dropped,
         version: self.version,
      }
   }

   pub fn len(&self) -> usize {
      self.apps.iter().map(|log| log.rows.len()).sum()
   }

   pub fn is_empty(&self) -> bool {
      self.apps.iter().all(|log| log.rows.is_empty())
   }

   /// How many rows fell out of the front of the log.
   pub fn dropped(&self) -> u64 {
      self.dropped
   }

   /// A counter that changes whenever a row is pushed or dropped, never on a read.
   pub fn version(&self) -> u64 {
      self.version
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use netshield_core::connection::{Family, L4Proto};
   use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

   fn view(ip: IpAddr) -> ConnectionView {
      ConnectionView {
         app_name: "firefox".to_owned(),
         exe: Some("/usr/lib/firefox/firefox".to_owned()),
         pid: Some(42),
         uid: Some(1000),
         family: Family::V4,
         proto: L4Proto::Tcp,
         remote_ip: ip,
         remote_port: 443,
         local_port: 51_000,
         domain: None,
         domain_candidates: Vec::new(),
      }
   }

   fn event(at: u64, connection: ConnectionView) -> ConnectionEvent {
      ConnectionEvent {
         at,
         connection,
         allowed: true,
         matched_rule: None,
         via_prompt: false,
      }
   }

   #[test]
   fn keeps_capacity_and_drops_the_oldest() {
      let mut log = ConnectionLog::new(500, 32);
      for at in 0..520 {
         log.push(&event(at, view(IpAddr::V4(Ipv4Addr::LOCALHOST))));
      }

      assert_eq!(log.len(), 500);
      assert_eq!(log.dropped(), 20);
      assert_eq!(log.rows().next().map(|row| row.at), Some(20));
      assert_eq!(log.rows().last().map(|row| row.at), Some(519));
   }

   #[test]
   fn a_row_names_its_destination_from_the_name_then_the_address() {
      let mut connection = view(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
      connection.domain = Some("example.com".to_owned());
      let row = Row::from_event(&event(0, connection));

      assert_eq!(row.dest, "example.com");
      assert_eq!(row.addr, "93.184.216.34:443");
      assert_eq!(row.candidate, None);

      let mut connection = view(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
      connection.domain_candidates = vec!["api.example.com".to_owned()];
      let row = Row::from_event(&event(0, connection));

      assert_eq!(row.dest, "93.184.216.34");
      assert_eq!(row.candidate.as_deref(), Some("api.example.com"));
   }

   #[test]
   fn ipv6_addresses_are_bracketed() {
      let row = Row::from_event(&event(0, view(IpAddr::V6(Ipv6Addr::LOCALHOST))));
      assert_eq!(row.addr, "[::1]:443");
   }

   #[test]
   fn app_falls_back_to_the_exe_basename_then_unknown() {
      let mut connection = view(IpAddr::V4(Ipv4Addr::LOCALHOST));
      connection.app_name.clear();
      let row = Row::from_event(&event(0, connection));
      assert_eq!(row.app, "firefox");

      let mut connection = view(IpAddr::V4(Ipv4Addr::LOCALHOST));
      connection.app_name.clear();
      connection.exe = None;
      let row = Row::from_event(&event(0, connection));
      assert_eq!(row.app, "unknown");
   }

   #[test]
   fn the_version_moves_only_when_the_log_changes() {
      let mut log = ConnectionLog::new(2, 32);
      let start = log.version();
      assert_eq!(
         log.version(),
         start,
         "an idle log keeps its version"
      );

      log.push(&event(0, view(IpAddr::V4(Ipv4Addr::LOCALHOST))));
      assert!(log.version() > start, "a push is a change");

      let pushed = log.version();
      log.push(&event(1, view(IpAddr::V4(Ipv4Addr::LOCALHOST))));
      log.push(&event(2, view(IpAddr::V4(Ipv4Addr::LOCALHOST))));
      assert!(log.version() > pushed, "a drop is a change too");

      // A zero-capacity log has no rows but still counts its drops.
      let mut empty = ConnectionLog::new(0, 32);
      let before = empty.version();
      empty.push(&event(0, view(IpAddr::V4(Ipv4Addr::LOCALHOST))));
      assert_eq!(empty.version(), before + 1);
   }

   #[test]
   fn one_process_cannot_evict_another() {
      let mut log = ConnectionLog::new(100, 32);
      for at in 0..300 {
         log.push(&event(at, view(IpAddr::V4(Ipv4Addr::LOCALHOST))));
      }
      assert_eq!(
         log.len(),
         100,
         "the busy app is capped on its own"
      );
      assert_eq!(log.dropped(), 200);

      // A quiet app keeps every row it ever had, however busy the other one is.
      let mut quiet = view(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
      quiet.app_name = "quiet".to_owned();
      for at in 0..3 {
         log.push(&event(300 + at, quiet.clone()));
      }
      assert_eq!(log.len(), 103);
      assert_eq!(
         log.rows().filter(|row| row.app == "quiet").count(),
         3,
         "the busy app's overflow never reaches another app's history"
      );
   }

   #[test]
   fn the_quietest_app_is_the_one_evicted() {
      let mut log = ConnectionLog::new(10, 2);
      let mut alpha = view(IpAddr::V4(Ipv4Addr::LOCALHOST));
      alpha.app_name = "alpha".to_owned();
      let mut bravo = view(IpAddr::V4(Ipv4Addr::LOCALHOST));
      bravo.app_name = "bravo".to_owned();
      let mut charlie = view(IpAddr::V4(Ipv4Addr::LOCALHOST));
      charlie.app_name = "charlie".to_owned();

      log.push(&event(10, alpha.clone()));
      log.push(&event(20, bravo));
      assert_eq!(log.len(), 2);

      // charlie arrives against a two-app budget: alpha goes, because its newest row is oldest.
      log.push(&event(30, charlie));
      assert_eq!(log.len(), 2);
      assert_eq!(log.dropped(), 1);
      assert_eq!(
         log.rows().map(|row| row.app.as_str()).collect::<Vec<_>>(),
         vec!["bravo", "charlie"]
      );

      // alpha speaks again, so bravo is now the quiet one — not the oldest slot.
      log.push(&event(40, alpha));
      assert_eq!(
         log.rows().map(|row| row.app.as_str()).collect::<Vec<_>>(),
         vec!["charlie", "alpha"],
         "the quietest app goes, not the first one inserted"
      );
   }
}
