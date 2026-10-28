//! The prompts the daemon is waiting on, and the packet ids each one owns.
//!
//! This is the correctness-critical state of the prompt lifecycle. A TCP SYN retransmits
//! roughly once a second, and every retransmission is a *new* packet id that the kernel is
//! holding until the daemon answers. If a prompt remembered only the first id, the retries
//! would queue up unverdicted and the connection would stall — or, worse, the kernel queue
//! would fill and unrelated traffic would be dropped. A prompt therefore owns *every*
//! packet id of every destination it lists (ARCHITECTURE §8), and a duplicate attempt from
//! the same app to the same destination joins that destination instead of stacking a second
//! alert.
//!
//! One prompt belongs to one *app*, identified by its resolved executable path plus uid, and
//! lists every destination of that app waiting on an answer. A page that opens six origins
//! therefore asks one question with six destinations rather than six questions in sequence,
//! and an answer covers exactly the destinations that were on screen. A flow of an app whose
//! prompt is already open joins that prompt — as a new destination, or as another packet on a
//! destination already listed. An unattributed flow, or one whose executable could not be
//! resolved, never groups: those keep the old one-prompt-per-flow behaviour, keyed by flow.
//!
//! Prompts form a FIFO of *apps* with exactly one active head: only the head has a deadline
//! and is broadcast to the clients, so every prompt gets the full timeout once it is visible
//! instead of spending that time queued behind the others. Resolving or expiring the head
//! activates the next prompt with a deadline counted from that moment. Within a group there
//! is no queue.
//!
//! The module takes `Instant` and `Duration` at every entry point, so deadlines are
//! unit-testable without sleeping.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use netshield_core::connection::{Attribution, Connection, FlowKey};

/// One destination inside a prompt, with the packets waiting on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptDest {
   pub connection: Connection,
   /// Every packet id belonging to this flow, in arrival order.
   pub packet_ids: Vec<u32>,
}

/// One unanswered prompt: the app's destinations and the packets they must answer together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptRecord {
   pub id: u64,
   /// Every destination waiting on this answer, in arrival order. Never empty.
   pub dests: Vec<PromptDest>,
   /// When the prompt expires; `None` while it is queued behind the active head.
   pub deadline: Option<Instant>,
   /// The timeout this prompt was opened with, applied when it becomes the head.
   timeout: Duration,
}

impl PromptRecord {
   /// The destination an older client shows: the first one listed.
   pub fn first(&self) -> Option<&PromptDest> {
      self.dests.first()
   }

   /// The app this prompt belongs to, taken from its first destination.
   pub fn app_name(&self) -> String {
      self.first().map_or_else(
         || "unknown".to_owned(),
         |dest| dest.connection.app_name(),
      )
   }

   /// The same prompt narrowed to `dests`: id, deadline and timeout are unchanged.
   ///
   /// A policy sweep can settle some destinations of a group while the rest still need the
   /// user; the survivors keep the prompt, its clock and its place in the queue.
   pub fn with_dests(&self, dests: Vec<PromptDest>) -> PromptRecord {
      PromptRecord {
         id: self.id,
         dests,
         deadline: self.deadline,
         timeout: self.timeout,
      }
   }

   /// Every held packet id, destination by destination, in arrival order.
   pub fn packet_ids(&self) -> impl Iterator<Item = u32> + '_ {
      self.dests.iter().flat_map(|dest| dest.packet_ids.iter().copied())
   }
}

/// The prompt that left the set, plus the queued prompt activated in its place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
   pub record: PromptRecord,
   /// The new head when `record` was the head, already carrying its deadline.
   pub activated: Option<PromptRecord>,
}

/// What [`PendingPrompts::open`] did with a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
   /// The packet joined a destination already listed on prompt `id`.
   Attached(u64),
   /// A new destination joined the open group prompt `id`.
   Joined(u64),
   /// A new prompt `id` was opened.
   Created(u64),
}

impl Opened {
   /// The id of the prompt that owns the packet.
   pub fn id(self) -> u64 {
      match self {
         Self::Attached(id) | Self::Joined(id) | Self::Created(id) => id,
      }
   }
}

/// The destinations [`PendingPrompts::take_dests`] removed, and what became of their prompt.
#[derive(Debug)]
pub struct TakenDests {
   /// The removed destinations, in the order they were listed.
   pub dests: Vec<PromptDest>,
   /// What is left of the prompt.
   pub outcome: DestRemoval,
}

/// What a destination removal left behind.
#[derive(Debug)]
pub enum DestRemoval {
   /// The prompt still has destinations, carrying a snapshot with the survivors.
   Remaining(PromptRecord),
   /// Every destination was removed, and the prompt with them.
   Resolved(Resolved),
}

/// The key that makes two flows one prompt: the app's resolved executable path and its uid.
///
/// `None` for a flow that must never group — an unattributed owner, or an attributed one
/// whose executable could not be resolved. Those keep a prompt per flow, as before.
fn group_key(connection: &Connection) -> Option<(PathBuf, u32)> {
   match &connection.process {
      Attribution::Process(process) => process.exe.clone().map(|exe| (exe, process.uid)),
      Attribution::Unknown => None,
   }
}

/// Open prompts in arrival order, keyed by id, plus the indexes that de-duplicate them.
#[derive(Debug, Default)]
pub struct PendingPrompts {
   by_id: HashMap<u64, PromptRecord>,
   /// The prompt a flow's packets attach to.
   by_flow: HashMap<FlowKey, u64>,
   /// The open prompt for an app, so a second flow joins it instead of queueing.
   by_group: HashMap<(PathBuf, u32), u64>,
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
         by_group: HashMap::new(),
         queue: VecDeque::new(),
         next_id: 1,
      }
   }

   /// Registers `first_packet` for `connection`, opening or joining a prompt as needed.
   ///
   /// A flow already in the set only grows its destination's packet list. A flow whose app
   /// has an open prompt joins it as a new destination; there is no queue within a group.
   /// Only a prompt that becomes the head is given a deadline.
   pub fn open(
      &mut self,
      connection: Connection,
      first_packet: u32,
      timeout: Duration,
      now: Instant,
   ) -> Opened {
      let flow = connection.flow_key();
      if let Some(id) = self.by_flow.get(&flow).copied() {
         self.attach(&flow, first_packet);
         return Opened::Attached(id);
      }

      let group = group_key(&connection);
      if let Some(group) = &group
         && let Some(id) = self.by_group.get(group).copied()
      {
         if let Some(record) = self.by_id.get_mut(&id) {
            record.dests.push(PromptDest {
               connection,
               packet_ids: vec![first_packet],
            });
            self.by_flow.insert(flow, id);
            return Opened::Joined(id);
         }
         // A stale group index must not make a flow invisible; forget it and open normally.
         self.by_group.remove(group);
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
         dests: vec![PromptDest {
            connection,
            packet_ids: vec![first_packet],
         }],
         deadline,
         timeout,
      };
      self.by_id.insert(id, record);
      self.by_flow.insert(flow, id);
      if let Some(group) = group {
         self.by_group.insert(group, id);
      }
      self.queue.push_back(id);
      Opened::Created(id)
   }

   /// Attaches another packet to the destination already listed for `flow`.
   ///
   /// Returns the prompt id, or `None` when no prompt is open for that flow. A packet id
   /// already in the set is ignored, so a duplicated netlink message cannot make the
   /// verdict path answer the same id twice.
   pub fn attach(&mut self, flow: &FlowKey, packet_id: u32) -> Option<u64> {
      let id = *self.by_flow.get(flow)?;
      let record = self.by_id.get_mut(&id)?;
      let dest = record.dests.iter_mut().find(|dest| dest.connection.flow_key() == *flow)?;
      if !dest.packet_ids.contains(&packet_id) {
         dest.packet_ids.push(packet_id);
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
      for dest in &record.dests {
         self.by_flow.remove(&dest.connection.flow_key());
      }
      if let Some(group) = record.first().and_then(|dest| group_key(&dest.connection))
         && self.by_group.get(&group) == Some(&id)
      {
         self.by_group.remove(&group);
      }
      if was_head {
         self.queue.pop_front();
      } else if let Some(position) = self.queue.iter().position(|queued| *queued == id) {
         self.queue.remove(position);
      }
      let activated = if was_head { self.activate(now) } else { None };
      Some(Resolved { record, activated })
   }

   /// Removes the destinations whose flow is in `flows` from prompt `id`.
   ///
   /// Used by the prompt sweep, which decides individual destinations without asking: a
   /// destination the policy already covers leaves the group while the rest wait on the
   /// user. Returns `None` when the prompt is unknown or none of the flows is listed.
   pub fn take_dests(&mut self, id: u64, flows: &[FlowKey], now: Instant) -> Option<TakenDests> {
      let record = self.by_id.get(&id)?;
      let all = record.dests.iter().all(|dest| flows.contains(&dest.connection.flow_key()));
      if all {
         let resolved = self.resolve(id, now)?;
         let dests = resolved.record.dests.clone();
         return Some(TakenDests {
            dests,
            outcome: DestRemoval::Resolved(resolved),
         });
      }

      let record = self.by_id.get_mut(&id)?;
      let mut dests = Vec::new();
      let mut kept = Vec::with_capacity(record.dests.len());
      for dest in record.dests.drain(..) {
         if flows.contains(&dest.connection.flow_key()) {
            dests.push(dest);
         } else {
            kept.push(dest);
         }
      }
      record.dests = kept;
      if dests.is_empty() {
         return None;
      }
      for dest in &dests {
         self.by_flow.remove(&dest.connection.flow_key());
      }
      let remaining = self.by_id.get(&id)?.clone();
      Some(TakenDests {
         dests,
         outcome: DestRemoval::Remaining(remaining),
      })
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
      self.by_group.clear();
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

   /// The id of the active head, or `None` when no prompt is open.
   pub fn head_id(&self) -> Option<u64> {
      self.queue.front().copied()
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
   use netshield_core::connection::{Endpoint, Family, L4Proto, ProcessInfo};
   use std::net::{IpAddr, Ipv4Addr};

   fn process(exe: &str) -> Attribution {
      Attribution::Process(ProcessInfo {
         pid: 4242,
         uid: 1000,
         exe: Some(PathBuf::from(exe)),
         comm: Some("firefox".to_owned()),
         cmdline: None,
      })
   }

   fn conn(port: u16) -> Connection {
      connection(process("/usr/lib/firefox/firefox"), port)
   }

   fn app_conn(exe: &str, port: u16) -> Connection {
      connection(process(exe), port)
   }

   fn unknown_conn(port: u16) -> Connection {
      connection(Attribution::Unknown, port)
   }

   fn connection(process: Attribution, port: u16) -> Connection {
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
         process,
         domain: Some("api.github.com".to_owned()),
      }
   }

   const TIMEOUT: Duration = Duration::from_secs(30);

   /// Opens three prompts for three different apps one second apart and returns their ids.
   fn open_three(pending: &mut PendingPrompts, start: Instant) -> (u64, u64, u64) {
      let first = pending.open(conn(443), 10, TIMEOUT, start);
      let second = pending.open(
         app_conn("/usr/bin/curl", 8443),
         20,
         TIMEOUT,
         start + Duration::from_secs(1),
      );
      let third = pending.open(
         app_conn("/usr/bin/wget", 9443),
         30,
         TIMEOUT,
         start + Duration::from_secs(2),
      );
      (first.id(), second.id(), third.id())
   }

   #[test]
   fn attach_twice_then_resolve_returns_all_three_ids() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let connection = conn(443);
      let flow = connection.flow_key();
      let id = pending.open(connection.clone(), 10, TIMEOUT, start).id();

      assert_eq!(pending.attach(&flow, 11), Some(id));
      assert_eq!(pending.attach(&flow, 12), Some(id));

      let resolved = pending.resolve(id, start).expect("still open");
      let record = resolved.record;
      assert_eq!(
         record.packet_ids().collect::<Vec<_>>(),
         vec![10, 11, 12]
      );
      assert_eq!(record.dests.len(), 1);
      assert_eq!(
         record.first().map(|dest| &dest.connection),
         Some(&connection)
      );
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
      let id = pending.open(connection, 10, TIMEOUT, Instant::now()).id();

      pending.attach(&flow, 10);
      pending.attach(&flow, 11);
      pending.attach(&flow, 11);

      let record = pending.resolve(id, Instant::now()).expect("still open").record;
      assert_eq!(
         record.packet_ids().collect::<Vec<_>>(),
         vec![10, 11]
      );
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

      assert_eq!(first, Opened::Created(1));
      assert_eq!(
         second,
         Opened::Attached(1),
         "one destination per flow"
      );
      assert_eq!(pending.len(), 1);
      let record = pending
         .resolve(first.id(), start + Duration::from_secs(5))
         .expect("still open")
         .record;
      assert_eq!(
         record.packet_ids().collect::<Vec<_>>(),
         vec![10, 11]
      );
      assert_eq!(record.dests.len(), 1);
      assert_eq!(
         record.deadline,
         Some(start + TIMEOUT),
         "the first deadline stands"
      );
   }

   #[test]
   fn flows_of_one_app_share_a_prompt() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let first = pending.open(conn(443), 10, TIMEOUT, start);
      let second = pending.open(conn(8443), 11, TIMEOUT, start);

      assert_eq!(first.id(), second.id(), "one prompt for the app");
      assert_eq!(second, Opened::Joined(first.id()));
      assert_eq!(pending.len(), 1);

      let record = pending.get(first.id()).expect("open");
      assert_eq!(
         record.dests.len(),
         2,
         "both destinations are listed"
      );
      assert_eq!(record.dests[0].packet_ids, vec![10]);
      assert_eq!(record.dests[1].packet_ids, vec![11]);
      assert_eq!(
         record.dests[1].connection.remote.port, 8443,
         "the joined destination keeps its own address"
      );
   }

   #[test]
   fn flows_of_different_apps_do_not_share() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let first = pending.open(conn(443), 10, TIMEOUT, start);
      let second = pending.open(
         app_conn("/usr/bin/curl", 9443),
         11,
         TIMEOUT,
         start + Duration::from_secs(1),
      );

      assert_ne!(first.id(), second.id());
      assert_eq!(second, Opened::Created(second.id()));
      assert_eq!(pending.len(), 2);
      assert_eq!(pending.head_id(), Some(first.id()));
      assert!(pending.is_active(first.id()));
      assert!(
         !pending.is_active(second.id()),
         "the second app queues"
      );
      assert_eq!(
         pending.get(second.id()).expect("open").deadline,
         None,
         "only the head has a clock"
      );
   }

   #[test]
   fn an_unknown_app_never_groups() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let first = pending.open(unknown_conn(443), 10, TIMEOUT, start);
      let second = pending.open(unknown_conn(8443), 20, TIMEOUT, start);

      assert_ne!(first.id(), second.id());
      assert_eq!(pending.len(), 2);
      assert_eq!(
         pending.get(first.id()).expect("open").dests.len(),
         1,
         "an unattributed flow gets a destination of its own"
      );
      assert_eq!(
         pending.get(second.id()).expect("open").dests.len(),
         1
      );
   }

   #[test]
   fn a_group_answers_every_packet_once() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let group = pending.open(conn(443), 10, TIMEOUT, start).id();
      pending.open(conn(8443), 11, TIMEOUT, start);
      pending.attach(&conn(8443).flow_key(), 12);
      let other = pending
         .open(
            app_conn("/usr/bin/curl", 9443),
            20,
            TIMEOUT,
            start,
         )
         .id();
      pending.attach(&app_conn("/usr/bin/curl", 9443).flow_key(), 21);

      let resolved = pending.resolve(group, start).expect("group is open");
      let answered: Vec<u32> = resolved.record.packet_ids().collect();
      assert_eq!(answered, vec![10, 11, 12]);
      let mut unique = answered.clone();
      unique.sort_unstable();
      unique.dedup();
      assert_eq!(
         unique.len(),
         answered.len(),
         "no packet is answered twice"
      );

      let survivor = pending.get(other).expect("the other group is untouched");
      assert_eq!(
         survivor.packet_ids().collect::<Vec<_>>(),
         vec![20, 21]
      );
      assert_eq!(survivor.dests.len(), 1);
      assert_eq!(pending.len(), 1);
   }

   #[test]
   fn taking_a_covered_destination_keeps_the_rest_of_the_group_open() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let id = pending.open(conn(443), 10, TIMEOUT, start).id();
      pending.open(conn(8443), 20, TIMEOUT, start);

      let covered = conn(443).flow_key();
      let taken = pending.take_dests(id, &[covered], start).expect("the destination is listed");
      assert_eq!(taken.dests.len(), 1);
      assert_eq!(taken.dests[0].packet_ids, vec![10]);
      let DestRemoval::Remaining(remaining) = taken.outcome else {
         panic!("the group still has a destination");
      };
      assert_eq!(remaining.id, id);
      assert_eq!(remaining.dests.len(), 1);
      assert_eq!(remaining.dests[0].packet_ids, vec![20]);
      assert!(
         pending.is_active(id),
         "the head is still the head"
      );

      let taken = pending
         .take_dests(id, &[conn(8443).flow_key()], start)
         .expect("the last destination is listed");
      assert!(matches!(taken.outcome, DestRemoval::Resolved(_)));
      assert!(pending.is_empty());
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
         pending.attach(&app_conn("/usr/bin/curl", 8443).flow_key(), 21),
         Some(second),
         "the queued prompt owns the packet"
      );
      assert_eq!(
         pending.get(second).expect("open").packet_ids().collect::<Vec<_>>(),
         vec![20, 21]
      );
      assert_eq!(
         pending.get(first).expect("open").packet_ids().collect::<Vec<_>>(),
         vec![10],
         "the head did not absorb the queued prompt's packet"
      );
      assert_eq!(
         pending.get(third).expect("open").packet_ids().collect::<Vec<_>>(),
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
      let id = pending.open(conn(443), 10, TIMEOUT, now).id();
      assert!(pending.resolve(id, now).is_some());

      assert_eq!(pending.resolve(id, now), None, "already answered");
      assert_eq!(
         pending.attach(&flow, 11),
         None,
         "a resolved flow no longer accepts packets"
      );
   }

   #[test]
   fn head_id_is_the_arrival_front_and_none_when_empty() {
      let mut pending = PendingPrompts::new();
      assert_eq!(
         pending.head_id(),
         None,
         "an empty queue has no head"
      );

      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);
      assert_eq!(pending.head_id(), Some(first));
      pending.resolve(first, start);
      assert_eq!(
         pending.head_id(),
         Some(second),
         "the prompt behind the head becomes the head"
      );
      pending.resolve(second, start);
      assert_eq!(pending.head_id(), Some(third));
      pending.resolve(third, start);
      assert_eq!(pending.head_id(), None, "the queue drained");
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
      assert_eq!(
         queued[0].packet_ids().collect::<Vec<_>>(),
         vec![20]
      );
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
      let id = pending.open(conn(443), 10, TIMEOUT, Instant::now()).id();
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
      record.dests[0].packet_ids.push(99);
      assert_eq!(
         pending.get(third).expect("still open").packet_ids().collect::<Vec<_>>(),
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
      pending.open(
         app_conn("/usr/bin/curl", 8443),
         20,
         TIMEOUT,
         start,
      );

      let mut taken = pending.take_all();
      taken.sort_by_key(|record| record.packet_ids().next());
      assert_eq!(taken.len(), 2);
      assert_eq!(
         taken[0].packet_ids().collect::<Vec<_>>(),
         vec![10]
      );
      assert_eq!(
         taken[1].packet_ids().collect::<Vec<_>>(),
         vec![20]
      );
      assert!(pending.is_empty());
      assert_eq!(pending.attach(&conn(443).flow_key(), 11), None);
      assert!(pending.take_all().is_empty());
   }

   #[test]
   fn ids_are_unique_and_never_reused() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let first = pending.open(conn(443), 1, TIMEOUT, start).id();
      pending.resolve(first, start);
      let second = pending.open(conn(443), 2, TIMEOUT, start).id();
      assert_ne!(first, second);
   }
}
