//! Synthetic traffic for `--mock`: prompts and connection events without a daemon.
//!
//! The cadence is driven by the [`Instant`] the caller passes in, so tests can drive fake
//! time. Prompt shapes cycle deterministically, which makes the three rendering cases --
//! named destination, bare address, unattributable process -- reviewable one after another.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use netshield_core::connection::{Family, L4Proto};
use netshield_core::ipc::{ConnectionEvent, ConnectionView, PromptRequest};

/// One prompt arrives every six seconds.
const PROMPT_EVERY: u64 = 6;

/// One connection event arrives every two seconds.
const CONNECTION_EVERY: u64 = 2;

/// How long a synthetic prompt stays open, matching the daemon's default.
const PROMPT_TIMEOUT: u64 = 30;

/// How many prompts the mock keeps unanswered at once, so the countdown is observable.
const CLOSE_AFTER_PROMPTS: u64 = PROMPT_TIMEOUT / PROMPT_EVERY;

/// What the mock produced this poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockEvent {
   Prompt(PromptRequest),
   Closed(u64),
}

/// A deterministic stream of fake prompts and connection events.
pub struct Mock {
   /// Number of prompts emitted; selects the next prompt shape.
   tick: usize,
   /// Set on the first poll, so the caller's clock defines the cadence.
   started: Option<Instant>,
   prompts: u64,
   connections: u64,
}

impl Mock {
   /// Starts a stream whose first prompt and connection are due immediately.
   pub fn new() -> Self {
      Self {
         tick: 0,
         started: None,
         prompts: 0,
         connections: 0,
      }
   }

   /// Returns every prompt and close due at `now`.
   ///
   /// A caller that was paused catches up one prompt per elapsed six seconds rather than
   /// dropping the backlog. An answered prompt's later synthetic close is harmless: the
   /// app ignores a close for an id it no longer holds.
   pub fn poll(&mut self, now: Instant) -> Vec<MockEvent> {
      let elapsed = self.elapsed(now);
      let mut events = Vec::new();

      let due_prompts = elapsed / PROMPT_EVERY + 1;
      while self.prompts < due_prompts {
         self.prompts += 1;
         let id = self.prompts;
         events.push(MockEvent::Prompt(prompt(
            id,
            self.tick,
            pending_before(id),
         )));
         self.tick += 1;

         if id > CLOSE_AFTER_PROMPTS {
            events.push(MockEvent::Closed(id - CLOSE_AFTER_PROMPTS));
         }
      }

      events
   }

   /// Returns every synthetic connection event due at `now`.
   ///
   /// Separate from [`Self::poll`] because the app feeds these to the connection log,
   /// while prompts go through the alert queue.
   pub fn connections(&mut self, now: Instant) -> Vec<ConnectionEvent> {
      let elapsed = self.elapsed(now);
      let due = elapsed / CONNECTION_EVERY + 1;
      let mut events = Vec::new();
      while self.connections < due {
         let shape = self.connections as usize % 3;
         self.connections += 1;
         events.push(connection_event(shape));
      }
      events
   }

   /// Seconds since the first poll, shared by both streams.
   fn elapsed(&mut self, now: Instant) -> u64 {
      let started = *self.started.get_or_insert(now);
      now.saturating_duration_since(started).as_secs()
   }
}

impl Default for Mock {
   fn default() -> Self {
      Self::new()
   }
}

/// How many earlier prompts are still open behind `id`.
///
/// The mock closes prompts after five slots, so the "N more waiting" line is exercised
/// without growing forever in `--mock`.
fn pending_before(id: u64) -> usize {
   (id - 1).min(CLOSE_AFTER_PROMPTS) as usize
}

/// One of the three prompt shapes, chosen by `tick % 3`.
fn prompt(id: u64, tick: usize, pending: usize) -> PromptRequest {
   let shape = tick % 3;
   let (app_name, pid, uid, ip, port, proto, domain) = match shape {
      0 => (
         "firefox",
         Some(4_242),
         Some(1_000),
         [142, 250, 185, 78],
         443,
         L4Proto::Tcp,
         Some("www.google.com"),
      ),
      1 => (
         "python3.12",
         Some(9_001),
         Some(1_000),
         [140, 82, 121, 6],
         443,
         L4Proto::Tcp,
         None,
      ),
      _ => (
         "unknown",
         None,
         None,
         [1, 1, 1, 1],
         53,
         L4Proto::Udp,
         None,
      ),
   };

   PromptRequest {
      id,
      connection: ConnectionView {
         app_name: app_name.to_owned(),
         exe: None,
         pid,
         uid,
         family: Family::V4,
         proto,
         remote_ip: IpAddr::V4(Ipv4Addr::from(ip)),
         remote_port: port,
         local_port: 51_000,
         domain: domain.map(str::to_owned),
         domain_candidates: Vec::new(),
      },
      timeout_secs: PROMPT_TIMEOUT,
      // The mock keeps the single-destination shape: the fallback fills this from
      // `connection`, exactly as an older daemon's frame is handled.
      dests: Vec::new(),
      // Only the named shape has a hostname, so only it may offer domain scope.
      domain_scope_available: domain.is_some(),
      pending,
   }
}

/// One synthetic verdict, cycling the same three shapes with an alternating verdict.
fn connection_event(shape: usize) -> ConnectionEvent {
   let (app_name, ip, port, proto, domain) = match shape % 3 {
      0 => (
         "firefox",
         [142, 250, 185, 78],
         443,
         L4Proto::Tcp,
         Some("www.google.com"),
      ),
      1 => (
         "python3.12",
         [140, 82, 121, 6],
         443,
         L4Proto::Tcp,
         None,
      ),
      _ => ("unknown", [1, 1, 1, 1], 53, L4Proto::Udp, None),
   };
   let allowed = shape.is_multiple_of(2);

   ConnectionEvent {
      at: unix_now(),
      connection: ConnectionView {
         app_name: app_name.to_owned(),
         exe: None,
         pid: None,
         uid: None,
         family: Family::V4,
         proto,
         remote_ip: IpAddr::V4(Ipv4Addr::from(ip)),
         remote_port: port,
         local_port: 51_000,
         domain: domain.map(str::to_owned),
         domain_candidates: Vec::new(),
      },
      allowed,
      matched_rule: None,
      via_prompt: !allowed,
   }
}

/// Seconds since the unix epoch, for the synthetic event's timestamp.
fn unix_now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs())
}
