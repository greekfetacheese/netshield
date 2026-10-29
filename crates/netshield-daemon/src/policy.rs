//! The decision layer between the rule set and the packet path.
//!
//! A [`Policy`] answers one question — what happens to this connection — and owns the two
//! pieces of state that answer depends on: the loaded [`RuleSet`] and the short-lived
//! per-flow grants a `Once` answer leaves behind. Grants are consulted first because a
//! user who allowed a single connection answered a question about *that* flow, not about
//! the rule set; a later rule edit must not retroactively override that answer before the
//! grant expires (ARCHITECTURE §8).
//!
//! The module is deliberately clock-free: every entry point takes `now` in unix seconds,
//! so expiry is unit-tested without sleeping.

use std::collections::HashMap;

use netshield_core::DefaultAction;
use netshield_core::connection::{Connection, FlowKey};
use netshield_core::rule::{Action, Rule, RuleId};
use netshield_core::ruleset::{Outcome, RuleSet};

/// The verdict for one connection, before it becomes a packet verdict.
///
/// A `Prompt` is a real outcome rather than an error: it tells the daemon loop to ask the
/// user instead of guessing an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
   Allow { rule: Option<RuleId> },
   Deny { rule: Option<RuleId> },
   Prompt,
}

/// How long a `Once` grant lives, in seconds.
///
/// A TCP flow retransmits and then carries payload for longer than a single packet, and
/// the grant is keyed by the flow rather than by a packet id. Two minutes covers a normal
/// connection's lifetime without remembering a one-off answer into the next session.
pub const GRANT_TTL_SECS: u64 = 120;

/// One remembered answer for a flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Grant {
   action: Action,
   expires_at: u64,
}

/// How an inserted rule related to the rules already present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
   /// No equivalent rule existed, so a new one was added.
   Created,
   /// An equivalent rule existed and was updated in place.
   Refreshed,
}

/// The rule engine plus the state that sits in front of it.
#[derive(Debug)]
pub struct Policy {
   ruleset: RuleSet,
   default_action: DefaultAction,
   /// Keyed by flow so a reconnect from the same app to the same service reuses the
   /// answer even though the source port changed.
   grants: HashMap<FlowKey, Grant>,
}

impl Policy {
   /// Wraps a loaded rule set with the configured fallback for unmatched flows.
   pub fn new(ruleset: RuleSet, default_action: DefaultAction) -> Self {
      Self {
         ruleset,
         default_action,
         grants: HashMap::new(),
      }
   }

   /// Decides one connection.
   ///
   /// A live grant wins over the rule set, because it is the most recent explicit answer
   /// for this exact flow. Otherwise the rule set decides; [`Outcome::Ask`] becomes
   /// [`Decision::Prompt`] only when the configuration actually asks, and never a silent
   /// allow.
   pub fn decide(&mut self, conn: &Connection, now: u64) -> Decision {
      if let Some(grant) = self.grants.get(&conn.flow_key())
         && grant.expires_at > now
      {
         return match grant.action {
            Action::Allow => Decision::Allow { rule: None },
            Action::Deny => Decision::Deny { rule: None },
         };
      }

      match self.ruleset.evaluate(conn) {
         Outcome::Allow { rule } => Decision::Allow { rule: Some(rule) },
         Outcome::Deny { rule } => Decision::Deny { rule: Some(rule) },
         Outcome::Ask => match self.default_action {
            DefaultAction::Prompt => Decision::Prompt,
            DefaultAction::Allow => Decision::Allow { rule: None },
            DefaultAction::Deny => Decision::Deny { rule: None },
         },
      }
   }

   /// Remembers one answer for `key` until `expires_at`.
   ///
   /// The caller may pass a shorter deadline than [`GRANT_TTL_SECS`] (a prompt's scope can
   /// be narrower than the TTL); a longer one is clamped, so a bug cannot turn a one-off
   /// answer into a permanent rule that never reaches disk.
   pub fn grant(&mut self, key: FlowKey, action: Action, expires_at: u64) {
      let deadline = expires_at.min(now_secs().saturating_add(GRANT_TTL_SECS));
      self.grants.insert(
         key,
         Grant {
            action,
            expires_at: deadline,
         },
      );
   }

   /// Inserts or replaces a rule in the in-memory set.
   ///
   /// Persistence is the caller's job: the store write may fail, and a rule the user just
   /// approved should still govern traffic for this run. This is the plain upsert by id;
   /// [`Policy::apply`] is what refuses to add a duplicate.
   pub fn upsert_rule(&mut self, rule: Rule) {
      self.ruleset.upsert(rule);
   }

   /// Inserts `rule`, or refreshes an equivalent rule already in the set.
   ///
   /// A rule is equivalent when its application matcher, destination matcher, action and
   /// duration all match exactly. Answering the same prompt twice must not leave two rules
   /// that can disagree, so an equivalent incumbent keeps its id and its place in the
   /// insertion order, gets `updated_at`, and is enabled again if the user had disabled it.
   /// The caller persists whichever rule comes back: a refresh replaces the stored copy.
   pub fn apply(&mut self, rule: Rule) -> (Rule, Applied) {
      let existing = self
         .ruleset
         .iter()
         .find(|existing| {
            existing.app == rule.app
               && existing.dest == rule.dest
               && existing.action == rule.action
               && existing.duration == rule.duration
         })
         .cloned();

      let Some(mut existing) = existing else {
         self.ruleset.upsert(rule.clone());
         return (rule, Applied::Created);
      };

      existing.enabled = true;
      existing.updated_at = rule.updated_at;
      self.ruleset.upsert(existing.clone());
      (existing, Applied::Refreshed)
   }

   /// Removes a rule, leaving the flow grants untouched.
   ///
   /// A deleted rule must not cancel a `Once` answer the user already gave for a flow:
   /// the grant is about that connection, not about the rule that was just removed.
   pub fn remove_rule(&mut self, id: &RuleId) -> bool {
      self.ruleset.remove(id)
   }

   /// The rules the policy is currently evaluating.
   pub fn ruleset(&self) -> &RuleSet {
      &self.ruleset
   }

   /// Records that `id` decided a connection, for the GUI's hit counters.
   pub fn record_hit(&mut self, id: &RuleId, now: u64) {
      self.ruleset.record_hit(id, now);
   }

   /// Drops every grant whose deadline has passed, returning how many were removed.
   pub fn expire_grants(&mut self, now: u64) -> usize {
      let before = self.grants.len();
      self.grants.retain(|_, grant| grant.expires_at > now);
      before - self.grants.len()
   }
}

/// Seconds since the Unix epoch, or 0 when the clock is before it.
fn now_secs() -> u64 {
   std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::net::{IpAddr, Ipv4Addr};
   use std::path::PathBuf;

   use netshield_core::connection::{Attribution, Endpoint, L4Proto, ProcessInfo};
   use netshield_core::rule::{AppMatcher, DestMatcher, Duration, rule_from_scope};

   const FIREFOX: &str = "/usr/lib/firefox/firefox";

   fn conn() -> Connection {
      Connection {
         family: netshield_core::Family::V4,
         proto: L4Proto::Tcp,
         local: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 50_000,
         },
         remote: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(140, 82, 121, 78)),
            port: 443,
         },
         process: Attribution::Process(ProcessInfo {
            pid: 4242,
            uid: 1000,
            exe: Some(PathBuf::from(FIREFOX)),
            comm: Some("firefox".to_owned()),
            cmdline: None,
         }),
         domain: Some("api.github.com".to_owned()),
      }
   }

   fn allow_rule(updated_at: u64) -> Rule {
      rule_from_scope(
         RuleId::new_unique(),
         AppMatcher::Exe(PathBuf::from(FIREFOX)),
         &netshield_core::ScopeRequest {
            action: Action::Allow,
            duration: Duration::Forever,
            dest: DestMatcher::Any,
         },
         updated_at,
      )
   }

   fn deny_rule(updated_at: u64) -> Rule {
      let mut rule = allow_rule(updated_at);
      rule.action = Action::Deny;
      rule
   }

   #[test]
   fn a_grant_wins_over_a_rule() {
      let deny = deny_rule(10);
      let mut set = RuleSet::new();
      set.upsert(deny.clone());
      let mut policy = Policy::new(set, DefaultAction::Prompt);

      assert_eq!(
         policy.decide(&conn(), 100),
         Decision::Deny {
            rule: Some(deny.id.clone())
         }
      );

      policy.grant(conn().flow_key(), Action::Allow, 200);
      assert_eq!(
         policy.decide(&conn(), 100),
         Decision::Allow { rule: None },
         "the grant must be consulted before the rule set"
      );
   }

   #[test]
   fn expiry_restores_the_rule_verdict() {
      let deny = deny_rule(10);
      let mut set = RuleSet::new();
      set.upsert(deny.clone());
      let mut policy = Policy::new(set, DefaultAction::Prompt);
      policy.grant(conn().flow_key(), Action::Allow, 150);

      assert_eq!(
         policy.decide(&conn(), 149),
         Decision::Allow { rule: None }
      );
      assert_eq!(policy.expire_grants(149), 0, "not expired yet");
      assert_eq!(
         policy.decide(&conn(), 150),
         Decision::Deny {
            rule: Some(deny.id.clone())
         },
         "the deadline itself is past"
      );
      assert_eq!(policy.expire_grants(150), 1);

      let mut policy = Policy::new(RuleSet::new(), DefaultAction::Prompt);
      policy.grant(conn().flow_key(), Action::Allow, 100);
      let mut other = conn();
      other.remote.port = 8443;
      policy.grant(other.flow_key(), Action::Allow, 500);

      assert_eq!(policy.expire_grants(99), 0);
      assert_eq!(policy.expire_grants(100), 1);
      assert_eq!(
         policy.decide(&other, 100),
         Decision::Allow { rule: None },
         "the longer grant survives"
      );
   }

   #[test]
   fn the_default_action_decides_a_flow_with_no_rule() {
      let cases = [
         (DefaultAction::Prompt, Decision::Prompt),
         (
            DefaultAction::Allow,
            Decision::Allow { rule: None },
         ),
         (DefaultAction::Deny, Decision::Deny { rule: None }),
      ];
      for (default, expected) in cases {
         let mut policy = Policy::new(RuleSet::new(), default);
         assert_eq!(policy.decide(&conn(), 0), expected, "{default:?}");
      }
   }

   #[test]
   fn a_disabled_rule_is_skipped() {
      let mut disabled = allow_rule(10);
      disabled.enabled = false;
      let mut set = RuleSet::new();
      set.upsert(disabled);
      let mut policy = Policy::new(set, DefaultAction::Prompt);

      assert_eq!(
         policy.decide(&conn(), 0),
         Decision::Prompt,
         "a disabled rule must not decide anything"
      );
   }

   #[test]
   fn upsert_rule_and_record_hit_reach_the_rule_set() {
      let mut policy = Policy::new(RuleSet::new(), DefaultAction::Prompt);
      let rule = allow_rule(10);
      policy.upsert_rule(rule.clone());
      assert_eq!(policy.ruleset().len(), 1);
      assert_eq!(
         policy.decide(&conn(), 0),
         Decision::Allow {
            rule: Some(rule.id.clone())
         }
      );

      policy.record_hit(&rule.id, 42);
      let stored = policy.ruleset().get(&rule.id).expect("rule is present");
      assert_eq!(stored.hits, 1);
      assert_eq!(stored.last_matched, Some(42));
   }

   #[test]
   fn removing_a_rule_keeps_the_grants_it_was_answered_with() {
      let rule = allow_rule(10);
      let mut set = RuleSet::new();
      set.upsert(rule.clone());
      let mut policy = Policy::new(set, DefaultAction::Prompt);
      policy.grant(conn().flow_key(), Action::Allow, 200);

      assert!(policy.remove_rule(&rule.id));
      assert!(!policy.remove_rule(&rule.id));
      assert_eq!(policy.ruleset().len(), 0);
      assert_eq!(
         policy.decide(&conn(), 100),
         Decision::Allow { rule: None },
         "the Once answer outlives the rule it was made for"
      );
   }

   #[test]
   fn grant_ttl_is_clamped_to_two_minutes() {
      let key = conn().flow_key();
      let mut policy = Policy::new(RuleSet::new(), DefaultAction::Prompt);
      let now = now_secs();

      policy.grant(key, Action::Allow, u64::MAX);
      assert_eq!(policy.expire_grants(now + GRANT_TTL_SECS - 1), 0);
      assert_eq!(policy.expire_grants(now + GRANT_TTL_SECS), 1);

      let key = conn().flow_key();
      let mut policy = Policy::new(RuleSet::new(), DefaultAction::Prompt);
      policy.grant(key, Action::Allow, now + 5);
      assert_eq!(policy.expire_grants(now + 4), 0);
      assert_eq!(policy.expire_grants(now + 5), 1);
   }
}
