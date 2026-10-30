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
//! Every prompt is live from the moment it is opened: it carries its own deadline, is
//! broadcast at once and expires on its own clock. Nothing waits behind anything else, so a
//! prompt for one app can no longer delay an unrelated app's prompt. The `queue` is only the
//! presentation order — the oldest unanswered prompt first — and expiry reaps every due
//! prompt in one pass. Within a group there is no queue at all.
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
   /// When the prompt expires; every live prompt has one, counted from its own arrival.
   pub deadline: Option<Instant>,
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

   /// The same prompt narrowed to `dests`: id and deadline are unchanged.
   ///
   /// A policy sweep can settle some destinations of a group while the rest still need the
   /// user; the survivors keep the prompt, its clock and its place in the presentation order.
   pub fn with_dests(&self, dests: Vec<PromptDest>) -> PromptRecord {
      PromptRecord {
         id: self.id,
         dests,
         deadline: self.deadline,
      }
   }

   /// Every held packet id, destination by destination, in arrival order.
   pub fn packet_ids(&self) -> impl Iterator<Item = u32> + '_ {
      self.dests.iter().flat_map(|dest| dest.packet_ids.iter().copied())
   }
}

/// The prompt that left the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
   pub record: PromptRecord,
}

/// How many prompts may be open at once.
///
/// An unbounded prompt set is a same-uid memory DoS: a process that opens distinct flows
/// keeps every one of their `Connection`s and packet ids alive here until it is answered or
/// times out, and nothing else bounds that. The cap is far above any interactive session,
/// so only a flood can reach it; a flow past it is denied instead of queued for ever.
pub const MAX_PROMPTS: usize = 2000;

/// What [`PendingPrompts::open`] did with a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
   /// The packet joined a destination already listed on prompt `id`.
   Attached(u64),
   /// A new destination joined the open group prompt `id`.
   Joined(u64),
   /// A new prompt `id` was opened.
   Created(u64),
   /// The set is at [`MAX_PROMPTS`] and the flow would have opened a new prompt.
   ///
   /// The caller must deny the packet: the set never grows past the cap, and silently
   /// accepting the flow would hide that the user was never asked.
   Full,
}

impl Opened {
   /// The id of the prompt that owns the packet.
   ///
   /// [`Opened::Full`] owns no prompt and reports `0`, the protocol's "no prompt" marker;
   /// callers must handle `Full` before asking for an id.
   pub fn id(self) -> u64 {
      match self {
         Self::Attached(id) | Self::Joined(id) | Self::Created(id) => id,
         Self::Full => 0,
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
   /// The open prompt for an app, so a second flow joins it instead of opening another.
   by_group: HashMap<(PathBuf, u32), u64>,
   /// Prompt ids in arrival order: the order the clients list them in.
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
   /// Every created prompt is given its own deadline from `now`. At [`MAX_PROMPTS`] a flow
   /// that already has a prompt still attaches or joins — those only add a packet id or a
   /// destination to a prompt that exists — while a flow that would open a new one returns
   /// [`Opened::Full`] and changes nothing.
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

      // Only a flow that would create a prompt is refused at the cap: the packet is denied
      // by the caller rather than dropped from a prompt that already holds its verdict.
      if self.by_id.len() >= MAX_PROMPTS {
         return Opened::Full;
      }

      let id = self.next_id;
      self.next_id += 1;
      let record = PromptRecord {
         id,
         dests: vec![PromptDest {
            connection,
            packet_ids: vec![first_packet],
         }],
         deadline: Some(now.checked_add(timeout).unwrap_or(now)),
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
   /// answer its packet ids a second time. Nothing is activated: every other prompt is already
   /// live with its own deadline.
   pub fn resolve(&mut self, id: u64) -> Option<Resolved> {
      let record = self.by_id.remove(&id)?;
      for dest in &record.dests {
         self.by_flow.remove(&dest.connection.flow_key());
      }
      if let Some(group) = record.first().and_then(|dest| group_key(&dest.connection))
         && self.by_group.get(&group) == Some(&id)
      {
         self.by_group.remove(&group);
      }
      if let Some(position) = self.queue.iter().position(|queued| *queued == id) {
         self.queue.remove(position);
      }
      Some(Resolved { record })
   }

   /// Removes the destinations whose flow is in `flows` from prompt `id`.
   ///
   /// Used by the prompt sweep, which decides individual destinations without asking: a
   /// destination the policy already covers leaves the group while the rest wait on the
   /// user. Returns `None` when the prompt is unknown or none of the flows is listed.
   pub fn take_dests(&mut self, id: u64, flows: &[FlowKey]) -> Option<TakenDests> {
      let record = self.by_id.get(&id)?;
      let all = record.dests.iter().all(|dest| flows.contains(&dest.connection.flow_key()));
      if all {
         let resolved = self.resolve(id)?;
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

   /// Removes and returns every open prompt, for a mode switch that answers them all.
   pub fn take_all(&mut self) -> Vec<PromptRecord> {
      self.by_flow.clear();
      self.by_group.clear();
      self.queue.clear();
      std::mem::take(&mut self.by_id).into_values().collect()
   }

   /// Every open prompt, in arrival order.
   ///
   /// Used when a new rule may already cover flows the user was shown but has not answered.
   pub fn queued_records(&self) -> Vec<PromptRecord> {
      self.queue.iter().filter_map(|id| self.by_id.get(id).cloned()).collect()
   }

   /// Removes and returns every prompt whose deadline has passed, in arrival order.
   ///
   /// One pass reaps every due prompt, not just the oldest: each prompt runs on its own clock,
   /// so an overdue prompt never holds another one's expiry back.
   pub fn expired_all(&mut self, now: Instant) -> Vec<Resolved> {
      let due: Vec<u64> = self
         .queue
         .iter()
         .filter(|id| {
            self
               .by_id
               .get(id)
               .and_then(|record| record.deadline)
               .is_some_and(|deadline| deadline <= now)
         })
         .copied()
         .collect();
      due.into_iter().filter_map(|id| self.resolve(id)).collect()
   }

   /// The id of the oldest unanswered prompt, or `None` when no prompt is open.
   pub fn head_id(&self) -> Option<u64> {
      self.queue.front().copied()
   }

   /// The prompt with `id`, if it is still open.
   pub fn get(&self, id: u64) -> Option<&PromptRecord> {
      self.by_id.get(&id)
   }

   /// Whether `id` is the oldest unanswered prompt, which the clients list first.
   pub fn is_active(&self, id: u64) -> bool {
      self.queue.front() == Some(&id)
   }

   /// How many *other* prompts are open right now, which is what a prompt's broadcast reports
   /// as `pending`; `0` when `id` is unknown or is the only one open.
   pub fn others_open(&self, id: u64) -> usize {
      self.by_id.len().saturating_sub(usize::from(self.by_id.contains_key(&id)))
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
         also_domains: Vec::new(),
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
   fn attaching_a_packet_to_an_open_prompt_answers_every_packet_once() {
      // A retransmission is a new packet id, so every attach must land on the same prompt,
      // and a duplicate id must not be answered twice.
      let start = Instant::now();
      for (attached, expected) in [
         (&[11u32, 12][..], vec![10, 11, 12]),
         (&[10, 11, 11][..], vec![10, 11]),
      ] {
         let mut pending = PendingPrompts::new();
         let connection = conn(443);
         let flow = connection.flow_key();
         let id = pending.open(connection.clone(), 10, TIMEOUT, start).id();
         for packet_id in attached {
            assert_eq!(pending.attach(&flow, *packet_id), Some(id));
         }

         let resolved = pending.resolve(id).expect("still open");
         let record = resolved.record;
         assert_eq!(record.packet_ids().collect::<Vec<_>>(), expected);
         assert_eq!(record.dests.len(), 1);
         assert_eq!(
            record.first().map(|dest| &dest.connection),
            Some(&connection)
         );
         assert_eq!(record.deadline, Some(start + TIMEOUT));
         assert_eq!(pending.len(), 0);
      }

      // Every packet of every destination in the group is answered by one resolve.
      let mut pending = PendingPrompts::new();
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

      let resolved = pending.resolve(group).expect("group is open");
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
   fn a_second_flow_of_the_same_app_joins_the_same_prompt() {
      // A second destination of one app joins the open prompt as a new destination.
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

      // The same flow again is an attach, not a new destination, and keeps the first clock.
      let mut pending = PendingPrompts::new();
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
      let record = pending.resolve(first.id()).expect("still open").record;
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

      // A packet attaches to the prompt for its own app, never to another app's.
      let mut pending = PendingPrompts::new();
      let (first, second, third) = open_three(&mut pending, start);

      assert_eq!(
         pending.attach(&app_conn("/usr/bin/curl", 8443).flow_key(), 21),
         Some(second),
         "the prompt for that app owns the packet"
      );
      assert_eq!(
         pending.get(second).expect("open").packet_ids().collect::<Vec<_>>(),
         vec![20, 21]
      );
      assert_eq!(
         pending.get(first).expect("open").packet_ids().collect::<Vec<_>>(),
         vec![10],
         "another prompt did not absorb the packet"
      );
      assert_eq!(
         pending.get(third).expect("open").packet_ids().collect::<Vec<_>>(),
         vec![30]
      );
      assert_eq!(
         pending.get(second).expect("open").deadline,
         Some(start + Duration::from_secs(1) + TIMEOUT),
         "a retransmission does not move the deadline"
      );
   }

   #[test]
   fn flows_of_different_apps_get_their_own_prompt() {
      // Two apps are two prompts, each listed after the other and each on its own clock.
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
         "the newest prompt is listed after the oldest"
      );
      assert_eq!(
         pending.get(second.id()).expect("open").deadline,
         Some(start + Duration::from_secs(1) + TIMEOUT),
         "every prompt has its own clock"
      );

      // Both prompts are live at once, with ids from one counter.
      let mut pending = PendingPrompts::new();
      let first = pending.open(conn(443), 10, TIMEOUT, start);
      let second = pending.open(
         app_conn("/usr/bin/curl", 8443),
         20,
         TIMEOUT,
         start + Duration::from_secs(1),
      );

      assert_eq!(first.id(), 1);
      assert_eq!(second.id(), 2);
      assert_eq!(
         pending.get(first.id()).expect("open").deadline,
         Some(start + TIMEOUT)
      );
      assert_eq!(
         pending.get(second.id()).expect("open").deadline,
         Some(start + Duration::from_secs(1) + TIMEOUT),
         "the second prompt is timed from its own arrival, not from the first"
      );
      assert_eq!(pending.len(), 2, "both prompts are open at once");
      assert_eq!(
         pending.others_open(second.id()),
         1,
         "the second prompt reports the first as open alongside it"
      );

      // A packet for a flow that never opened a prompt attaches to nothing.
      let mut pending = PendingPrompts::new();
      assert_eq!(pending.attach(&conn(443).flow_key(), 1), None);
   }

   #[test]
   fn each_prompt_expires_on_its_own_clock() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let first = pending.open(conn(443), 10, TIMEOUT, start).id();

      let half = start + TIMEOUT / 2;
      let second = pending.open(app_conn("/usr/bin/curl", 8443), 20, TIMEOUT, half).id();

      // A is due at `start + TIMEOUT`, B only at `half + TIMEOUT`.
      let expired = pending.expired_all(start + TIMEOUT);
      assert_eq!(
         expired.iter().map(|resolved| resolved.record.id).collect::<Vec<_>>(),
         vec![first],
         "only the prompt whose own deadline passed is reaped"
      );
      assert_eq!(
         pending.get(second).expect("still open").deadline,
         Some(half + TIMEOUT)
      );

      let expired = pending.expired_all(half + TIMEOUT);
      assert_eq!(
         expired.iter().map(|resolved| resolved.record.id).collect::<Vec<_>>(),
         vec![second]
      );
      assert!(pending.is_empty());

      // Answering one prompt leaves the other open, and the survivor still expires.
      let mut pending = PendingPrompts::new();
      let first = pending.open(conn(443), 10, TIMEOUT, start).id();
      let second = pending
         .open(
            app_conn("/usr/bin/curl", 8443),
            20,
            TIMEOUT,
            start,
         )
         .id();

      let resolved = pending.resolve(first).expect("the first is open");
      assert_eq!(resolved.record.id, first);
      assert_eq!(pending.len(), 1);
      assert_eq!(
         pending.head_id(),
         Some(second),
         "the other prompt is still open"
      );

      let expired = pending.expired_all(start + TIMEOUT);
      assert_eq!(
         expired.iter().map(|resolved| resolved.record.id).collect::<Vec<_>>(),
         vec![second],
         "the survivor still expires on its own clock"
      );
   }

   #[test]
   fn taking_a_covered_destination_keeps_the_rest_of_the_group_open() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let id = pending.open(conn(443), 10, TIMEOUT, start).id();
      pending.open(conn(8443), 20, TIMEOUT, start);

      let covered = conn(443).flow_key();
      let taken = pending.take_dests(id, &[covered]).expect("the destination is listed");
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
         "the oldest prompt is still listed first"
      );

      let taken = pending
         .take_dests(id, &[conn(8443).flow_key()])
         .expect("the last destination is listed");
      assert!(matches!(taken.outcome, DestRemoval::Resolved(_)));
      assert!(pending.is_empty());

      // A prompt that was already taken answers nothing a second time.
      let mut pending = PendingPrompts::new();
      let flow = conn(443).flow_key();
      let id = pending.open(conn(443), 10, TIMEOUT, start).id();
      assert!(pending.resolve(id).is_some());

      assert_eq!(pending.resolve(id), None, "already answered");
      assert_eq!(
         pending.attach(&flow, 11),
         None,
         "a resolved flow no longer accepts packets"
      );
   }

   #[test]
   fn head_id_and_queued_records_follow_arrival_order() {
      // The head is the oldest prompt, and drains in arrival order.
      let mut pending = PendingPrompts::new();
      assert_eq!(
         pending.head_id(),
         None,
         "an empty set has no oldest prompt"
      );

      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);
      assert_eq!(
         pending.head_id(),
         Some(first),
         "the oldest is listed first"
      );
      pending.resolve(first);
      assert_eq!(
         pending.head_id(),
         Some(second),
         "the next-oldest prompt becomes the front of the list"
      );
      pending.resolve(second);
      assert_eq!(pending.head_id(), Some(third));
      pending.resolve(third);
      assert_eq!(pending.head_id(), None, "the set drained");

      // The snapshot lists every open prompt, oldest first, with its own clock.
      let mut pending = PendingPrompts::new();
      let (first, second, third) = open_three(&mut pending, start);

      let records = pending.queued_records();
      assert_eq!(
         records.iter().map(|record| record.id).collect::<Vec<_>>(),
         vec![first, second, third],
         "every open prompt is returned, oldest first"
      );
      assert_eq!(
         records[0].packet_ids().collect::<Vec<_>>(),
         vec![10]
      );
      assert_eq!(records[0].deadline, Some(start + TIMEOUT));
      assert_eq!(
         records[1].deadline,
         Some(start + Duration::from_secs(1) + TIMEOUT)
      );
      assert_eq!(pending.len(), 3);

      // The snapshot is a clone: mutating it never touches the live prompt.
      let mut pending = PendingPrompts::new();
      let (first, _second, third) = open_three(&mut pending, start);

      let mut records = pending.queued_records();
      let mut record = records.pop().expect("the third prompt is open");
      assert_eq!(record.id, third);
      record.dests[0].packet_ids.push(99);
      assert_eq!(
         pending.get(third).expect("still open").packet_ids().collect::<Vec<_>>(),
         vec![30],
         "mutating the snapshot must not touch the live prompt"
      );
      assert!(
         pending.is_active(first),
         "the snapshot left the set alone"
      );

      // Answering every open prompt removes them by id.
      for record in pending.queued_records() {
         assert!(pending.resolve(record.id).is_some());
      }
      assert!(pending.is_empty());
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

      // Ids come from one counter and are never handed out twice.
      let mut pending = PendingPrompts::new();
      let first = pending.open(conn(443), 1, TIMEOUT, start).id();
      pending.resolve(first);
      let second = pending.open(conn(443), 2, TIMEOUT, start).id();
      assert_ne!(first, second);
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
   fn expiring_both_in_one_pass_returns_both_in_arrival_order() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      // All three opened on the same clock, so one pass finds all three due.
      let first = pending.open(conn(443), 10, TIMEOUT, start).id();
      let second = pending
         .open(
            app_conn("/usr/bin/curl", 8443),
            20,
            TIMEOUT,
            start,
         )
         .id();
      let third = pending
         .open(
            app_conn("/usr/bin/wget", 9443),
            30,
            TIMEOUT,
            start,
         )
         .id();

      let expired = pending.expired_all(start + TIMEOUT);
      assert_eq!(
         expired.iter().map(|resolved| resolved.record.id).collect::<Vec<_>>(),
         vec![first, second, third],
         "one pass reaps every due prompt, oldest first"
      );
      assert!(pending.is_empty());
   }

   #[test]
   fn pending_counts_the_other_open_prompts() {
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      let (first, second, third) = open_three(&mut pending, start);

      assert_eq!(pending.others_open(first), 2);
      assert_eq!(pending.others_open(second), 2);
      assert_eq!(pending.others_open(third), 2);

      pending.resolve(third).expect("the third is open");
      assert_eq!(
         pending.others_open(first),
         1,
         "a resolved prompt stops counting for everyone else"
      );
      pending.resolve(second).expect("the second is open");
      assert_eq!(pending.others_open(first), 0);
      pending.resolve(first).expect("the first is open");
      assert_eq!(
         pending.others_open(first),
         0,
         "an unknown id reports nothing open"
      );
   }

   #[test]
   fn a_capped_prompt_set_still_attaches_and_joins() {
      // A flood of distinct apps and destinations fills the set exactly to the cap, and the
      // next new flow is refused instead of growing it further.
      let mut pending = PendingPrompts::new();
      let start = Instant::now();
      for index in 0..MAX_PROMPTS {
         let app = format!("/usr/bin/app{index}");
         let port = 10_000 + u16::try_from(index).expect("the cap fits in a port range");
         let opened = pending.open(
            app_conn(&app, port),
            index as u32 + 1,
            TIMEOUT,
            start,
         );
         assert_eq!(opened, Opened::Created(opened.id()));
      }
      assert_eq!(pending.len(), MAX_PROMPTS);

      let port = 10_000 + u16::try_from(MAX_PROMPTS).expect("the cap fits in a port range");
      let refused = pending.open(
         app_conn("/usr/bin/flood", port),
         99_999,
         TIMEOUT,
         start,
      );
      assert_eq!(
         refused,
         Opened::Full,
         "a new flow past the cap is refused"
      );
      assert_eq!(
         pending.len(),
         MAX_PROMPTS,
         "the set never grows past the cap"
      );

      // Flows that already own a prompt keep working at exactly the cap: one attaches a
      // packet to its own destination, one joins as a new destination of its app.
      let first_app = "/usr/bin/app0";
      let attached = pending.open(
         app_conn(first_app, 10_000),
         100_001,
         TIMEOUT,
         start + Duration::from_secs(1),
      );
      assert_eq!(
         attached,
         Opened::Attached(1),
         "a retransmission still attaches"
      );
      let joined = pending.open(
         app_conn(first_app, 20_000),
         100_002,
         TIMEOUT,
         start + Duration::from_secs(1),
      );
      assert_eq!(
         joined,
         Opened::Joined(1),
         "a new destination still joins"
      );
      assert_eq!(
         pending.len(),
         MAX_PROMPTS,
         "neither one created a prompt"
      );

      let record = pending.get(1).expect("the first prompt is open");
      assert_eq!(record.dests.len(), 2);
      assert_eq!(record.dests[0].packet_ids, vec![1, 100_001]);
      assert_eq!(record.dests[1].packet_ids, vec![100_002]);

      // The cap does not freeze the set: answering one prompt makes room for one new flow.
      assert!(pending.resolve(2).is_some());
      let made_room = pending.open(
         app_conn("/usr/bin/after-the-cap", port),
         100_003,
         TIMEOUT,
         start,
      );
      assert_eq!(made_room, Opened::Created(MAX_PROMPTS as u64 + 1));
      assert_eq!(pending.len(), MAX_PROMPTS);
   }
}
