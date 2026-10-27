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
//! Prompts form a FIFO with exactly one active head: only the head has a deadline and is
//! broadcast to the clients, so every prompt gets the full timeout once it is visible
//! instead of spending that time queued behind the others. Resolving or expiring the head
//! activates the next prompt with a deadline counted from that moment.
//!
//! The module takes `Instant` and `Duration` at every entry point, so deadlines are
//! unit-testable without sleeping.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use netshield_core::connection::{Connection, FlowKey};

/// One unanswered prompt and the packets it must eventually answer together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptRecord {
   pub id: u64,
   pub connection: Connection,
   /// Every packet id belonging to this flow, in arrival order.
   pub packet_ids: Vec<u32>,
   /// When the prompt expires; `None` while it is queued behind the active head.
   pub deadline: Option<Instant>,
   /// The timeout this prompt was opened with, applied when it becomes the head.
   timeout: Duration,
}

/// The prompt that left the set, plus the queued prompt activated in its place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
   pub record: PromptRecord,
   /// The new head when `record` was the head, already carrying its deadline.
   pub activated: Option<PromptRecord>,
}

/// Open prompts in arrival order, keyed by id, plus the flow index that de-duplicates them.
#[derive(Debug, Default)]
pub struct PendingPrompts {
   by_id: HashMap<u64, PromptRecord>,
   by_flow: HashMap<FlowKey, u64>,
   /// Prompt ids in arrival order; the front is the active head.
   queue: VecDeque<u64>,
   next_id: u64,
}

impl PendingPrompts {
   /// Creates an empty set; the first prompt id will be 1.
   pub fn new() -> Self {
      Self {
         by_id: HashMap::new(),
         by_flow: HashMap::new(),
         queue: VecDeque::new(),
         next_id: 1,
      }
   }

   /// Opens a prompt for `connection`, owning `first_packet`, and returns its id.
   ///
   /// Only a prompt that becomes the head is given a deadline; one queued behind it waits
   /// without a clock until it is activated. A prompt already open for the flow is
   /// extended rather than duplicated: the caller checks [`PendingPrompts::attach`] first,
   /// but calling `open` twice must not create two windows for one connection attempt.
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
      let deadline = if self.queue.is_empty() {
         Some(now.checked_add(timeout).unwrap_or(now))
      } else {
         None
      };
      let record = PromptRecord {
         id,
         connection,
         packet_ids: vec![first_packet],
         deadline,
         timeout,
      };
      self.by_id.insert(id, record);
      self.by_flow.insert(flow, id);
      self.queue.push_back(id);
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
   /// answer its packet ids a second time. Removing the head activates the next queued
   /// prompt with a deadline counted from `now`, not from that prompt's arrival.
   pub fn resolve(&mut self, id: u64, now: Instant) -> Option<Resolved> {
      let was_head = self.queue.front() == Some(&id);
      let record = self.by_id.remove(&id)?;
      self.by_flow.remove(&record.connection.flow_key());
      if was_head {
         self.queue.pop_front();
      } else if let Some(position) = self.queue.iter().position(|queued| *queued == id) {
         self.queue.remove(position);
      }
      let activated = if was_head { self.activate(now) } else { None };
      Some(Resolved { record, activated })
   }

   /// Gives the queued head its deadline and returns a snapshot of it.
   fn activate(&mut self, now: Instant) -> Option<PromptRecord> {
      let id = *self.queue.front()?;
      let record = self.by_id.get_mut(&id)?;
      record.deadline = Some(now.checked_add(record.timeout).unwrap_or(now));
      Some(record.clone())
   }

   /// Removes and returns every open prompt, for a mode switch that answers them all.
   pub fn take_all(&mut self) -> Vec<PromptRecord> {
      self.by_flow.clear();
      self.queue.clear();
      std::mem::take(&mut self.by_id).into_values().collect()
   }

   /// Every open prompt that is **not** the active head, in arrival order.
   ///
   /// Used when a new rule may already cover flows the user has not been shown yet.
   pub fn queued_records(&self) -> Vec<PromptRecord> {
      self.queue.iter().skip(1).filter_map(|id| self.by_id.get(id).cloned()).collect()
   }

   /// Removes and returns the active prompt when its deadline has passed.
   ///
   /// Queued prompts have no deadline and can never expire here, however much time passes.
   /// The newly activated head carries a deadline counted from `now`.
   pub fn expired(&mut self, now: Instant) -> Option<Resolved> {
      let id = *self.queue.front()?;
      if self.by_id.get(&id)?.deadline? > now {
         return None;
      }
      self.resolve(id, now)
   }

   /// The prompt with `id`, if it is still open.
   pub fn get(&self, id: u64) -> Option<&PromptRecord> {
      self.by_id.get(&id)
   }

   /// Whether `id` is the active head, and therefore the prompt the clients can see.
   pub fn is_active(&self, id: u64) -> bool {
      self.queue.front() == Some(&id)
   }

   /// How many prompts are waiting behind `id`, which is what its broadcast reports as
   /// `pending`; `0` when `id` is unknown or last.
   pub fn queued_behind(&self, id: u64) -> usize {
      self
         .queue
         .iter()
         .position(|queued| *queued == id)
         .map_or(0, |at| self.queue.len() - at - 1)
   }

   /// Number of open prompts, resolved or not: the active head plus everything queued.
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

   /// Opens three prompts one second apart and returns their ids.
   fn open_three(pending: &mut PendingPrompts, start: Instant) -> (u64, u64, u64) {
      let first = pending.open(conn(443), 10, TIMEOUT, start);
      let second = pending.open(
         conn(8443),
         20,
         TIMEOUT,
         start + Duration::from_secs(1),
      );
      let third = pending.open(
         conn(9443),
         30,
         TIMEOUT,
         start + Duration::from_secs(2),
      );
      (first, second, third)
   }

   #[test]
   fn attach_twice_then_resolve_returns_all_three_ids() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let connection = conn(443);
      let flow = connection.flow_key();
      let id = pending.open(connection.clone(), 10, TIMEOUT, start);

      assert_eq!(pending.attach(&flow, 11), Some(id));
      assert_eq!(pending.attach(&flow, 12), Some(id));

      let resolved = pending.resolve(id, start).expect("still open");
      let record = resolved.record;
      assert_eq!(record.packet_ids, vec![10, 11, 12]);
      assert_eq!(record.connection, connection);
      assert_eq!(record.deadline, Some(start + TIMEOUT));
      assert_eq!(
         resolved.activated, None,
         "nothing was queued behind it"
      );
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

      let record = pending.resolve(id, Instant::now()).expect("still open").record;
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
      let record = pending
         .resolve(first, start + Duration::from_secs(5))
         .expect("still open")
         .record;
      assert_eq!(record.packet_ids, vec![10, 11]);
      assert_eq!(
         record.deadline,
         Some(start + TIMEOUT),
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
   fn opening_three_prompts_activates_only_the_first() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);

      assert!(
         pending.is_active(first),
         "the first prompt is the head"
      );
      assert!(!pending.is_active(second));
      assert!(!pending.is_active(third));
      assert_eq!(pending.len(), 3);
      assert_eq!(
         pending.get(first).expect("open").deadline,
         Some(start + TIMEOUT),
         "only the head carries a deadline"
      );
      assert_eq!(pending.get(second).expect("open").deadline, None);
      assert_eq!(pending.get(third).expect("open").deadline, None);
   }

   #[test]
   fn queued_prompts_never_expire_while_the_head_is_open() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);

      assert!(pending.expired(start + TIMEOUT - Duration::from_millis(1)).is_none());
      assert_eq!(
         pending.get(second).expect("open").deadline,
         None,
         "the second prompt still has no clock"
      );
      assert_eq!(pending.get(third).expect("open").deadline, None);

      // Time running far past every arrival changes nothing for the queued prompts: only
      // the head's own deadline can expire a prompt.
      let far_future = start + Duration::from_secs(3_600);
      let expired = pending.expired(far_future).expect("the head is overdue");
      assert_eq!(expired.record.id, first);
      assert_eq!(
         expired.activated.as_ref().map(|record| record.id),
         Some(second)
      );
      assert_eq!(pending.len(), 2);
      assert_eq!(
         pending.get(third).expect("open").deadline,
         None,
         "the third prompt did not expire with the head"
      );
      assert!(
         pending.expired(far_future).is_none(),
         "the newly activated head is not overdue yet"
      );
   }

   #[test]
   fn resolving_the_head_activates_the_next_from_the_resolution_moment() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);

      let resolved_at = start + Duration::from_secs(5);
      let resolved = pending.resolve(first, resolved_at).expect("head is open");

      let activated = resolved.activated.expect("the second prompt became active");
      assert_eq!(activated.id, second);
      assert_eq!(
         activated.deadline,
         Some(resolved_at + TIMEOUT),
         "the deadline starts at activation, not at arrival"
      );
      assert!(pending.is_active(second));
      assert_eq!(pending.get(third).expect("open").deadline, None);
   }

   #[test]
   fn expiring_the_head_activates_the_next_from_the_expiry_moment() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);

      let expired_at = start + TIMEOUT;
      let expired = pending.expired(expired_at).expect("the head is due");
      assert_eq!(expired.record.id, first);

      let activated = expired.activated.expect("the second prompt became active");
      assert_eq!(activated.id, second);
      assert_eq!(
         activated.deadline,
         Some(expired_at + TIMEOUT),
         "the queued prompt gets its full timeout from activation"
      );
      assert!(pending.is_active(second));
      assert_eq!(pending.get(third).expect("open").deadline, None);
   }

   #[test]
   fn the_count_broadcast_with_each_head_falls_from_two_to_zero() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);
      assert_eq!(
         pending.queued_behind(first),
         2,
         "the first head reports two queued behind it"
      );

      let answered_at = start + Duration::from_secs(5);
      let resolved = pending.resolve(first, answered_at).expect("head is open");
      assert_eq!(
         resolved.activated.as_ref().map(|record| record.id),
         Some(second)
      );
      assert_eq!(
         pending.queued_behind(second),
         1,
         "the second head reports one queued behind it"
      );

      // The second prompt gets a full timeout from its activation, then the third is the
      // only prompt left and is broadcast with nothing behind it.
      assert!(pending.expired(answered_at + TIMEOUT - Duration::from_millis(1)).is_none());
      let expired = pending.expired(answered_at + TIMEOUT).expect("the head is due");
      assert_eq!(expired.record.id, second);
      assert_eq!(
         expired.activated.as_ref().map(|record| record.id),
         Some(third)
      );
      assert_eq!(pending.queued_behind(third), 0);
   }

   #[test]
   fn a_packet_joining_the_head_does_not_change_the_queue_or_any_deadline() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);
      let head_deadline = pending.get(first).expect("open").deadline;

      assert_eq!(
         pending.attach(&conn(443).flow_key(), 11),
         Some(first)
      );
      assert_eq!(
         pending.get(first).expect("open").deadline,
         head_deadline,
         "a retransmission does not move the head's deadline"
      );
      assert_eq!(pending.get(second).expect("open").deadline, None);
      assert_eq!(pending.get(third).expect("open").deadline, None);
      assert!(pending.is_active(first));
      assert_eq!(pending.len(), 3);
      assert_eq!(pending.queued_behind(first), 2);

      let resolved = pending.resolve(first, start + Duration::from_secs(5));
      assert_eq!(
         resolved.expect("head is open").activated.map(|record| record.id),
         Some(second),
         "the queue order is unchanged"
      );
   }

   #[test]
   fn a_packet_joining_a_queued_prompt_attaches_to_it_not_to_the_head() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);

      assert_eq!(
         pending.attach(&conn(8443).flow_key(), 21),
         Some(second),
         "the queued prompt owns the packet"
      );
      assert_eq!(
         pending.get(second).expect("open").packet_ids,
         vec![20, 21]
      );
      assert_eq!(
         pending.get(first).expect("open").packet_ids,
         vec![10],
         "the head did not absorb the queued prompt's packet"
      );
      assert_eq!(
         pending.get(third).expect("open").packet_ids,
         vec![30]
      );
      assert!(pending.is_active(first));
      assert_eq!(pending.get(second).expect("open").deadline, None);
   }

   #[test]
   fn resolving_a_queued_prompt_leaves_the_head_active() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, _third) = open_three(&mut pending, start);

      let resolved = pending
         .resolve(second, start + Duration::from_secs(5))
         .expect("queued prompt is open");
      assert_eq!(
         resolved.activated, None,
         "the head was not removed"
      );
      assert!(pending.is_active(first));
      assert_eq!(pending.len(), 2);
      assert_eq!(
         pending.get(first).expect("open").deadline,
         Some(start + TIMEOUT)
      );
   }

   #[test]
   fn resolving_a_taken_prompt_returns_none() {
      let mut pending = PendingPrompts::new();
      let flow = conn(443).flow_key();
      let now = Instant::now();
      let id = pending.open(conn(443), 10, TIMEOUT, now);
      assert!(pending.resolve(id, now).is_some());

      assert_eq!(pending.resolve(id, now), None, "already answered");
      assert_eq!(
         pending.attach(&flow, 11),
         None,
         "a resolved flow no longer accepts packets"
      );
   }

   #[test]
   fn queued_records_returns_every_non_head_prompt_in_arrival_order() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);

      let queued = pending.queued_records();
      assert_eq!(
         queued.iter().map(|record| record.id).collect::<Vec<_>>(),
         vec![second, third],
         "the head is excluded and arrival order is kept"
      );
      assert_eq!(queued[0].packet_ids, vec![20]);
      assert_eq!(
         queued[0].deadline, None,
         "queued prompts carry no clock"
      );
      assert_eq!(queued[1].deadline, None);
      assert!(pending.is_active(first), "nothing was removed");
      assert_eq!(pending.len(), 3);
   }

   #[test]
   fn queued_records_of_a_single_prompt_is_empty() {
      let mut pending = PendingPrompts::new();
      let id = pending.open(conn(443), 10, TIMEOUT, Instant::now());
      assert!(pending.queued_records().is_empty());
      assert!(pending.is_active(id));
   }

   #[test]
   fn queued_records_returns_clones_not_the_live_records() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);

      let mut queued = pending.queued_records();
      let mut record = queued.pop().expect("the third prompt is queued");
      assert_eq!(record.id, third);
      record.packet_ids.push(99);
      assert_eq!(
         pending.get(third).expect("still open").packet_ids,
         vec![30],
         "mutating the snapshot must not touch the live prompt"
      );
      assert!(
         pending.is_active(first),
         "the snapshot left the queue alone"
      );
      assert_eq!(pending.get(second).expect("open").deadline, None);

      // Answering every queued prompt removes them by id, and the head is still active.
      for record in pending.queued_records() {
         let resolved = pending.resolve(record.id, start).expect("still open");
         assert_eq!(
            resolved.activated, None,
            "resolving a queued prompt leaves the head active"
         );
      }
      assert!(pending.is_active(first));
      assert_eq!(pending.len(), 1);
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
      pending.resolve(first, start);
      let second = pending.open(conn(443), 2, TIMEOUT, start);
      assert_ne!(first, second);
   }
}
