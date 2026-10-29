//! A bounded, render-ready history of connection events.
//!
//! The daemon streams events for as long as the GUI runs, so the history must never grow
//! without bound: the oldest rows are dropped and counted instead. Each row is flattened
//! when it is pushed so the table does no formatting work on every frame.

use std::collections::VecDeque;
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

/// A fixed-capacity ring of rendered connections, oldest first.
#[derive(Debug)]
pub struct ConnectionLog {
   /// Rows are shared rather than owned so handing a snapshot of the log to another thread
   /// is a refcount bump instead of a deep clone of every string in the history.
   rows: VecDeque<Arc<Row>>,
   capacity: usize,
   dropped: u64,
   /// Bumped whenever the contents change, so the UI can cache a derived line list and
   /// rebuild it only when the log actually moved.
   version: u64,
}

impl ConnectionLog {
   /// Creates a log that keeps at most `capacity` rows.
   pub fn new(capacity: usize) -> Self {
      Self {
         rows: VecDeque::with_capacity(capacity),
         capacity,
         dropped: 0,
         version: 0,
      }
   }

   /// Appends one event, dropping the oldest row once the capacity is reached.
   pub fn push(&mut self, event: &ConnectionEvent) {
      if self.capacity == 0 {
         self.dropped += 1;
         self.version += 1;
         return;
      }
      while self.rows.len() >= self.capacity {
         self.rows.pop_front();
         self.dropped += 1;
      }
      self.rows.push_back(Arc::new(Row::from_event(event)));
      self.version += 1;
   }

   /// Rows oldest first; the table reverses this so the newest is on top.
   /// The rows are shared, so this borrows through the reference rather than handing out the
   /// owning count.
   pub fn rows(&self) -> impl DoubleEndedIterator<Item = &Row> {
      self.rows.iter().map(std::convert::AsRef::as_ref)
   }

   /// A frozen copy of the log for a background rebuild.
   ///
   /// The rows are shared, so this is a refcount bump per row rather than a deep clone of every
   /// string in the history; the copy never moves while a derivation reads it, which is the whole
   /// point of taking one.
   pub fn snapshot(&self) -> Self {
      Self {
         rows: self.rows.clone(),
         capacity: self.capacity,
         dropped: self.dropped,
         version: self.version,
      }
   }

   pub fn len(&self) -> usize {
      self.rows.len()
   }

   pub fn is_empty(&self) -> bool {
      self.rows.is_empty()
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
      let mut log = ConnectionLog::new(500);
      for at in 0..520 {
         log.push(&event(at, view(IpAddr::V4(Ipv4Addr::LOCALHOST))));
      }

      assert_eq!(log.len(), 500);
      assert_eq!(log.dropped(), 20);
      assert_eq!(log.rows().next().map(|row| row.at), Some(20));
      assert_eq!(
         log.rows().next_back().map(|row| row.at),
         Some(519)
      );
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
      let mut log = ConnectionLog::new(2);
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
      let mut empty = ConnectionLog::new(0);
      let before = empty.version();
      empty.push(&event(0, view(IpAddr::V4(Ipv4Addr::LOCALHOST))));
      assert_eq!(empty.version(), before + 1);
   }
}
