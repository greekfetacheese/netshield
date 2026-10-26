//! The prompts the daemon is waiting on, and the packet ids each one owns.
//!
//! This is the correctness-critical state of the prompt lifecycle. A TCP SYN retransmits
//! roughly once a second, and every retransmission is a *new* packet id that the kernel is
//! holding until the daemon answers. If a prompt remembered only the first id, the retries
//! would queue up unverdicted and the connection would stall — or, worse, the kernel queue
//! would fill and unrelated traffic would be dropped. A prompt therefore owns *every*
//! packet id of its flow (ARCHITECTURE §8), and a duplicate attempt from the same app to
//! the same destination joins the open prompt instead of stacking a second alert.
//!
//! The module takes `Instant` and `Duration` at every entry point, so deadlines are
//! unit-testable without sleeping.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use netshield_core::connection::{Connection, FlowKey};

/// One unanswered prompt and the packets it must eventually answer together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptRecord {
   pub id: u64,
   pub connection: Connection,
   /// Every packet id belonging to this flow, in arrival order.
   pub packet_ids: Vec<u32>,
   pub deadline: Instant,
}

/// Open prompts, keyed by id, plus the flow index that de-duplicates them.
#[derive(Debug, Default)]
pub struct PendingPrompts {
   by_id: HashMap<u64, PromptRecord>,
   by_flow: HashMap<FlowKey, u64>,
   next_id: u64,
}

impl PendingPrompts {
   /// Creates an empty set; the first prompt id will be 1.
   pub fn new() -> Self {
      Self {
         by_id: HashMap::new(),
         by_flow: HashMap::new(),
         next_id: 1,
      }
   }

   /// Opens a prompt for `connection`, owning `first_packet`, and returns its id.
   ///
   /// A prompt already open for the flow is extended rather than duplicated: the caller
   /// checks [`PendingPrompts::attach`] first, but calling `open` twice must not create two
   /// windows for one connection attempt.
   pub fn open(
      &mut self,
      connection: Connection,
      first_packet: u32,
      timeout: Duration,
      now: Instant,
   ) -> u64 {
      let flow = connection.flow_key();
      if let Some(id) = self.by_flow.get(&flow).copied() {
         self.attach(&flow, first_packet);
         return id;
      }

      let id = self.next_id;
      self.next_id += 1;
      let record = PromptRecord {
         id,
         connection,
         packet_ids: vec![first_packet],
         deadline: now.checked_add(timeout).unwrap_or(now),
      };
      self.by_id.insert(id, record);
      self.by_flow.insert(flow, id);
      id
   }

   /// Attaches another packet to the prompt already open for `flow`.
   ///
   /// Returns the prompt id, or `None` when no prompt is open for that flow. A packet id
   /// already in the set is ignored, so a duplicated netlink message cannot make the
   /// verdict path answer the same id twice.
   pub fn attach(&mut self, flow: &FlowKey, packet_id: u32) -> Option<u64> {
      let id = *self.by_flow.get(flow)?;
      let record = self.by_id.get_mut(&id)?;
      if !record.packet_ids.contains(&packet_id) {
         record.packet_ids.push(packet_id);
      }
      Some(id)
   }

   /// Removes and returns the prompt with `id`.
   ///
   /// `None` means it was already answered, timed out or never existed; the caller must not
   /// answer its packet ids a second time.
   pub fn resolve(&mut self, id: u64) -> Option<PromptRecord> {
      let record = self.by_id.remove(&id)?;
      self.by_flow.remove(&record.connection.flow_key());
      Some(record)
   }

   /// Removes and returns every open prompt, for a mode switch that answers them all.
   pub fn take_all(&mut self) -> Vec<PromptRecord> {
      self.by_flow.clear();
      std::mem::take(&mut self.by_id).into_values().collect()
   }

   /// Removes and returns every prompt whose deadline has passed.
   pub fn expired(&mut self, now: Instant) -> Vec<PromptRecord> {
      let ids: Vec<u64> = self
         .by_id
         .values()
         .filter(|record| record.deadline <= now)
         .map(|record| record.id)
         .collect();
      ids.into_iter().filter_map(|id| self.resolve(id)).collect()
   }

   /// Number of open prompts.
   pub fn len(&self) -> usize {
      self.by_id.len()
   }

   /// Whether no prompt is open.
   pub fn is_empty(&self) -> bool {
      self.by_id.is_empty()
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use netshield_core::connection::{Attribution, Endpoint, Family, L4Proto, ProcessInfo};
   use std::net::{IpAddr, Ipv4Addr};
   use std::path::PathBuf;

   fn conn(port: u16) -> Connection {
      Connection {
         family: Family::V4,
         proto: L4Proto::Tcp,
         local: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 50_000,
         },
         remote: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(140, 82, 121, 78)),
            port,
         },
         process: Attribution::Process(ProcessInfo {
            pid: 4242,
            uid: 1000,
            exe: Some(PathBuf::from("/usr/lib/firefox/firefox")),
            comm: Some("firefox".to_owned()),
            cmdline: None,
         }),
         domain: Some("api.github.com".to_owned()),
      }
   }

   const TIMEOUT: Duration = Duration::from_secs(30);

   #[test]
   fn attach_twice_then_resolve_returns_all_three_ids() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let connection = conn(443);
      let flow = connection.flow_key();
      let id = pending.open(connection.clone(), 10, TIMEOUT, start);

      assert_eq!(pending.attach(&flow, 11), Some(id));
      assert_eq!(pending.attach(&flow, 12), Some(id));

      let record = pending.resolve(id).expect("still open");
      assert_eq!(record.packet_ids, vec![10, 11, 12]);
      assert_eq!(record.connection, connection);
      assert_eq!(record.deadline, start + TIMEOUT);
      assert_eq!(pending.len(), 0);
   }

   #[test]
   fn a_duplicate_packet_id_is_attached_once() {
      let mut pending = PendingPrompts::new();
      let connection = conn(443);
      let flow = connection.flow_key();
      let id = pending.open(connection, 10, TIMEOUT, Instant::now());

      pending.attach(&flow, 10);
      pending.attach(&flow, 11);
      pending.attach(&flow, 11);

      let record = pending.resolve(id).expect("still open");
      assert_eq!(record.packet_ids, vec![10, 11]);
   }

   #[test]
   fn a_second_attempt_joins_the_open_prompt_instead_of_opening_another() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let first = pending.open(conn(443), 10, TIMEOUT, start);
      let second = pending.open(
         conn(443),
         11,
         TIMEOUT,
         start + Duration::from_secs(5),
      );

      assert_eq!(first, second, "one prompt per flow");
      assert_eq!(pending.len(), 1);
      let record = pending.resolve(first).expect("still open");
      assert_eq!(record.packet_ids, vec![10, 11]);
      assert_eq!(
         record.deadline,
         start + TIMEOUT,
         "the first deadline stands"
      );
   }

   #[test]
   fn a_different_flow_gets_its_own_prompt() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let first = pending.open(conn(443), 10, TIMEOUT, start);
      let second = pending.open(conn(8443), 11, TIMEOUT, start);

      assert_ne!(first, second);
      assert_eq!(pending.len(), 2);
      assert_eq!(
         pending.attach(&conn(443).flow_key(), 12),
         Some(first)
      );
      assert_eq!(
         pending.attach(&conn(8443).flow_key(), 21),
         Some(second)
      );
   }

   #[test]
   fn attach_without_an_open_prompt_is_none() {
      let mut pending = PendingPrompts::new();
      assert_eq!(pending.attach(&conn(443).flow_key(), 1), None);
   }

   #[test]
   fn expired_returns_only_prompts_past_their_deadline() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let short = pending.open(conn(443), 10, Duration::from_secs(5), start);
      let long = pending.open(conn(8443), 20, TIMEOUT, start);

      assert!(pending.expired(start + Duration::from_secs(4)).is_empty());
      let due = pending.expired(start + Duration::from_secs(5));
      assert_eq!(due.len(), 1);
      assert_eq!(due[0].id, short);
      assert_eq!(due[0].packet_ids, vec![10]);

      assert_eq!(pending.len(), 1);
      let due = pending.expired(start + TIMEOUT);
      assert_eq!(due.len(), 1);
      assert_eq!(due[0].id, long);
      assert!(pending.is_empty());
   }

   #[test]
   fn resolving_a_taken_prompt_returns_none() {
      let mut pending = PendingPrompts::new();
      let flow = conn(443).flow_key();
      let id = pending.open(conn(443), 10, TIMEOUT, Instant::now());
      assert!(pending.resolve(id).is_some());

      assert_eq!(pending.resolve(id), None, "already answered");
      assert_eq!(
         pending.attach(&flow, 11),
         None,
         "a resolved flow no longer accepts packets"
      );
   }

   #[test]
   fn take_all_empties_the_set_and_returns_every_prompt() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      pending.open(conn(443), 10, TIMEOUT, start);
      pending.open(conn(8443), 20, TIMEOUT, start);

      let mut taken = pending.take_all();
      taken.sort_by_key(|record| record.packet_ids[0]);
      assert_eq!(taken.len(), 2);
      assert_eq!(taken[0].packet_ids, vec![10]);
      assert_eq!(taken[1].packet_ids, vec![20]);
      assert!(pending.is_empty());
      assert_eq!(pending.attach(&conn(443).flow_key(), 11), None);
      assert!(pending.take_all().is_empty());
   }

   #[test]
   fn ids_are_unique_and_never_reused() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let first = pending.open(conn(443), 1, TIMEOUT, start);
      pending.resolve(first);
      let second = pending.open(conn(443), 2, TIMEOUT, start);
      assert_ne!(first, second);
   }
}
