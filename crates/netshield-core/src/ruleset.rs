use crate::connection::Connection;
use crate::rule::{Action, AppMatcher, Rule, RuleId};

/// The verdict for one connection.
///
/// `Ask` is a real outcome rather than an error: falling through every rule means the
/// configured default applies, and the daemon may turn that into a prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
   Allow { rule: RuleId },
   Deny { rule: RuleId },
   Ask,
}

/// The in-memory rule set.
///
/// Insertion order is part of the specification: it is the last tie-break in
/// [`RuleSet::evaluate`], so rules are stored in a `Vec` rather than a map keyed by id.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
   rules: Vec<Rule>,
}

impl RuleSet {
   /// Creates an empty set. An empty set answers [`Outcome::Ask`] for everything.
   pub fn new() -> Self {
      Self { rules: Vec::new() }
   }

   /// Picks the most specific matching rule, or `Ask` when none matches.
   ///
   /// Comparison is lexicographic on `(app rank, destination rank)`, then `Deny` over
   /// `Allow`, then most recently updated, then first inserted. Application scope is the
   /// outer key so a global allow can never override an application-level deny.
   pub fn evaluate(&self, conn: &Connection) -> Outcome {
      let mut winner: Option<Winner> = None;

      for rule in &self.rules {
         if !rule.enabled || !rule.app.matches(&conn.process) {
            continue;
         }
         let Some(dest_rank) = rule.dest.matched_rank(conn) else {
            continue;
         };
         let candidate = Winner {
            app_rank: app_rank(&rule.app),
            dest_rank,
            action: rule.action,
            updated_at: rule.updated_at,
            id: &rule.id,
         };
         if winner.as_ref().is_none_or(|current| candidate.beats(current)) {
            winner = Some(candidate);
         }
      }

      match winner {
         Some(winner) => match winner.action {
            Action::Allow => Outcome::Allow {
               rule: winner.id.clone(),
            },
            Action::Deny => Outcome::Deny {
               rule: winner.id.clone(),
            },
         },
         None => Outcome::Ask,
      }
   }

   /// Inserts or replaces a rule by id, returning the previous value on replacement.
   pub fn upsert(&mut self, rule: Rule) -> Option<Rule> {
      if let Some(slot) = self.rules.iter_mut().find(|existing| existing.id == rule.id) {
         return Some(std::mem::replace(slot, rule));
      }
      self.rules.push(rule);
      None
   }

   /// Removes a rule, reporting whether it existed.
   pub fn remove(&mut self, id: &RuleId) -> bool {
      let before = self.rules.len();
      self.rules.retain(|rule| rule.id != *id);
      self.rules.len() != before
   }

   /// Looks a rule up by id.
   pub fn get(&self, id: &RuleId) -> Option<&Rule> {
      self.rules.iter().find(|rule| rule.id == *id)
   }

   /// Iterates in insertion order, which is the order the last tie-break depends on.
   pub fn iter(&self) -> impl Iterator<Item = &Rule> {
      self.rules.iter()
   }

   /// Number of stored rules, including disabled ones.
   pub fn len(&self) -> usize {
      self.rules.len()
   }

   /// Whether no rules are stored.
   pub fn is_empty(&self) -> bool {
      self.rules.is_empty()
   }

   /// Swaps in a freshly loaded rule list wholesale.
   ///
   /// Reload keeps the file's order because it is the insertion order the tie-break
   /// needs; merging would make that order depend on reload history.
   pub fn replace_all(&mut self, rules: Vec<Rule>) {
      self.rules = rules;
   }

   /// Records that a rule decided a connection.
   ///
   /// A missing id is ignored because the caller may race a removal; there is no policy
   /// decision riding on the counter.
   pub fn record_hit(&mut self, id: &RuleId, now: u64) {
      if let Some(rule) = self.rules.iter_mut().find(|rule| rule.id == *id) {
         rule.hits = rule.hits.saturating_add(1);
         rule.last_matched = Some(now);
      }
   }
}

/// The application-specificity half of the ranking tuple.
fn app_rank(app: &AppMatcher) -> u8 {
   match app {
      AppMatcher::Exe(_) | AppMatcher::Unknown => 2,
      AppMatcher::Any => 0,
   }
}

/// A candidate rule reduced to the fields the comparison needs.
struct Winner<'a> {
   app_rank: u8,
   dest_rank: u8,
   action: Action,
   updated_at: u64,
   id: &'a RuleId,
}

impl Winner<'_> {
   /// Strictly-better comparison, so an equal candidate never displaces the incumbent and
   /// the first rule in insertion order wins the final tie.
   fn beats(&self, other: &Self) -> bool {
      match (self.app_rank, self.dest_rank).cmp(&(other.app_rank, other.dest_rank)) {
         std::cmp::Ordering::Greater => true,
         std::cmp::Ordering::Less => false,
         std::cmp::Ordering::Equal => {
            let self_denies = self.action == Action::Deny;
            let other_denies = other.action == Action::Deny;
            if self_denies != other_denies {
               return self_denies;
            }
            self.updated_at > other.updated_at
         }
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::connection::{Attribution, Connection, Endpoint, Family, L4Proto, ProcessInfo};
   use crate::ipnet::IpNet;
   use crate::rule::{AppMatcher, DestMatcher, Duration, ScopeRequest, rule_from_scope};
   use std::net::{IpAddr, Ipv4Addr};
   use std::path::PathBuf;

   const FIREFOX: &str = "/usr/lib/firefox/firefox";

   fn firefox_conn() -> Connection {
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
         process: Attribution::Process(ProcessInfo {
            pid: 4242,
            uid: 1000,
            exe: Some(PathBuf::from(FIREFOX)),
            comm: Some("firefox".to_owned()),
            cmdline: None,
         }),
         domain: Some("api.github.com".to_owned()),
         also_domains: Vec::new(),
      }
   }

   fn unknown_conn() -> Connection {
      Connection {
         process: Attribution::Unknown,
         ..firefox_conn()
      }
   }

   fn rule(app: AppMatcher, dest: DestMatcher, action: Action, updated_at: u64) -> Rule {
      rule_from_scope(
         RuleId::new_unique(),
         app,
         &ScopeRequest {
            action,
            duration: Duration::Forever,
            dest,
         },
         updated_at,
      )
   }

   fn firefox() -> AppMatcher {
      AppMatcher::Exe(PathBuf::from(FIREFOX))
   }

   fn api_github() -> DestMatcher {
      DestMatcher::Domain {
         host: "api.github.com".to_owned(),
         subdomains: false,
      }
   }

   #[test]
   fn the_precedence_order_is_lexicographic_with_deny_winning_ties() {
      type Case = (&'static str, fn(&str));
      let cases: [Case; 6] = [
         (
            "rank ladder, inserted worst-first so insertion order cannot explain the winner",
            |reason| {
               let mut set = RuleSet::new();
               let any = rule(
                  AppMatcher::Any,
                  DestMatcher::Any,
                  Action::Allow,
                  0,
               );
               let port = rule(
                  AppMatcher::Any,
                  DestMatcher::Port(443),
                  Action::Allow,
                  0,
               );
               let ip = rule(
                  AppMatcher::Any,
                  DestMatcher::Ip("140.82.0.0/16".parse::<IpNet>().unwrap()),
                  Action::Allow,
                  0,
               );
               let subdomains = rule(
                  AppMatcher::Any,
                  DestMatcher::Domain {
                     host: "github.com".to_owned(),
                     subdomains: true,
                  },
                  Action::Allow,
                  0,
               );
               let exact = rule(AppMatcher::Any, api_github(), Action::Allow, 0);

               for candidate in [&any, &port, &ip, &subdomains, &exact] {
                  set.upsert(candidate.clone());
                  assert_eq!(
                     set.evaluate(&firefox_conn()),
                     Outcome::Allow {
                        rule: candidate.id.clone()
                     },
                     "{reason}: rank of {:?} should win",
                     candidate.dest
                  );
               }
            },
         ),
         (
            "app-over-destination: the app rule outranks the destination winner",
            |reason| {
               let mut set = RuleSet::new();
               let app_deny = rule(firefox(), DestMatcher::Any, Action::Deny, 0);
               let global_allow = rule(AppMatcher::Any, api_github(), Action::Allow, 0);
               // Global rule first, so insertion order cannot be what makes the app rule win.
               set.upsert(global_allow.clone());
               set.upsert(app_deny.clone());

               assert_eq!(
                  set.evaluate(&firefox_conn()),
                  Outcome::Deny {
                     rule: app_deny.id.clone()
                  },
                  "{reason}"
               );

               // Sanity check the scenario: the global rule really is the destination winner.
               let mut without_app = RuleSet::new();
               without_app.upsert(global_allow.clone());
               assert_eq!(
                  without_app.evaluate(&firefox_conn()),
                  Outcome::Allow {
                     rule: global_allow.id.clone()
                  },
                  "{reason}: the scenario's destination winner must be the global rule"
               );
            },
         ),
         (
            "deny-wins-ties: deny inserted first wins the action tie",
            |reason| {
               let mut set = RuleSet::new();
               let allow = rule(AppMatcher::Any, api_github(), Action::Allow, 5);
               let deny = rule(AppMatcher::Any, api_github(), Action::Deny, 5);
               set.upsert(deny.clone());
               set.upsert(allow.clone());
               assert_eq!(
                  set.evaluate(&firefox_conn()),
                  Outcome::Deny {
                     rule: deny.id.clone()
                  },
                  "{reason}"
               );
            },
         ),
         (
            "deny-wins-ties: deny inserted second wins the action tie",
            |reason| {
               let mut set = RuleSet::new();
               let allow = rule(AppMatcher::Any, api_github(), Action::Allow, 5);
               let deny = rule(AppMatcher::Any, api_github(), Action::Deny, 5);
               set.upsert(allow.clone());
               set.upsert(deny.clone());
               assert_eq!(
                  set.evaluate(&firefox_conn()),
                  Outcome::Deny {
                     rule: deny.id.clone()
                  },
                  "{reason}"
               );
            },
         ),
         (
            "newer-wins after an action tie, and an older re-insert does not displace it",
            |reason| {
               let mut set = RuleSet::new();
               let old = rule(AppMatcher::Any, api_github(), Action::Allow, 10);
               let new = rule(AppMatcher::Any, api_github(), Action::Allow, 20);
               set.upsert(old.clone());
               set.upsert(new.clone());
               assert_eq!(
                  set.evaluate(&firefox_conn()),
                  Outcome::Allow {
                     rule: new.id.clone()
                  },
                  "{reason}"
               );

               // A later insert with an older timestamp must not displace the incumbent.
               set.upsert(old.clone());
               assert_eq!(
                  set.evaluate(&firefox_conn()),
                  Outcome::Allow {
                     rule: new.id.clone()
                  },
                  "{reason}: the older re-insert must not displace the incumbent"
               );
            },
         ),
         ("first-inserted wins the final tie", |reason| {
            let mut set = RuleSet::new();
            let first = rule(AppMatcher::Any, api_github(), Action::Allow, 10);
            let second = rule(AppMatcher::Any, api_github(), Action::Allow, 10);
            set.upsert(first.clone());
            set.upsert(second.clone());
            assert_eq!(
               set.evaluate(&firefox_conn()),
               Outcome::Allow {
                  rule: first.id.clone()
               },
               "{reason}"
            );
         }),
      ];

      for (reason, case) in cases {
         case(reason);
      }
   }

   #[test]
   fn disabled_rules_are_ignored() {
      let mut set = RuleSet::new();
      let mut disabled = rule(firefox(), api_github(), Action::Deny, 100);
      disabled.enabled = false;
      let enabled = rule(
         AppMatcher::Any,
         DestMatcher::Any,
         Action::Allow,
         0,
      );
      set.upsert(disabled);
      set.upsert(enabled.clone());
      assert_eq!(
         set.evaluate(&firefox_conn()),
         Outcome::Allow {
            rule: enabled.id.clone()
         }
      );
   }

   #[test]
   fn unknown_attribution_matches_only_the_unknown_matcher() {
      let mut set = RuleSet::new();
      let exe_only = rule(firefox(), DestMatcher::Any, Action::Allow, 0);
      set.upsert(exe_only);
      assert_eq!(set.evaluate(&unknown_conn()), Outcome::Ask);

      let unknown = rule(
         AppMatcher::Unknown,
         DestMatcher::Any,
         Action::Deny,
         0,
      );
      set.upsert(unknown.clone());
      assert_eq!(
         set.evaluate(&unknown_conn()),
         Outcome::Deny {
            rule: unknown.id.clone()
         }
      );
      // And the unknown matcher does not fire for a successfully attributed process.
      let mut only_unknown = RuleSet::new();
      only_unknown.upsert(unknown);
      assert_eq!(
         only_unknown.evaluate(&firefox_conn()),
         Outcome::Ask
      );
   }

   #[test]
   fn domain_subdomains_flag_controls_matching() {
      let parent = DestMatcher::Domain {
         host: "github.com".to_owned(),
         subdomains: false,
      };
      let mut exact = RuleSet::new();
      exact.upsert(rule(
         AppMatcher::Any,
         parent.clone(),
         Action::Allow,
         0,
      ));
      assert_eq!(
         exact.evaluate(&firefox_conn()),
         Outcome::Ask,
         "exact host must not match a subdomain"
      );

      let mut wildcard = RuleSet::new();
      wildcard.upsert(rule(
         AppMatcher::Any,
         DestMatcher::Domain {
            host: "github.com".to_owned(),
            subdomains: true,
         },
         Action::Allow,
         0,
      ));
      assert!(
         matches!(
            wildcard.evaluate(&firefox_conn()),
            Outcome::Allow { .. }
         ),
         "subdomains matcher should cover api.github.com"
      );
   }

   #[test]
   fn port_match_and_mismatch() {
      let mut set = RuleSet::new();
      set.upsert(rule(
         AppMatcher::Any,
         DestMatcher::Port(443),
         Action::Deny,
         0,
      ));
      assert!(matches!(
         set.evaluate(&firefox_conn()),
         Outcome::Deny { .. }
      ));

      let mut other = firefox_conn();
      other.remote.port = 80;
      assert_eq!(set.evaluate(&other), Outcome::Ask);
   }

   #[test]
   fn nothing_matching_is_ask() {
      assert_eq!(
         RuleSet::new().evaluate(&firefox_conn()),
         Outcome::Ask
      );
      let mut set = RuleSet::new();
      set.upsert(rule(
         firefox(),
         DestMatcher::Ip("10.0.0.0/8".parse::<IpNet>().unwrap()),
         Action::Allow,
         0,
      ));
      assert_eq!(set.evaluate(&firefox_conn()), Outcome::Ask);
   }

   #[test]
   fn upsert_replaces_by_id_and_returns_previous() {
      let mut set = RuleSet::new();
      let original = rule(
         AppMatcher::Any,
         DestMatcher::Any,
         Action::Allow,
         1,
      );
      assert_eq!(set.upsert(original.clone()), None);

      let mut replacement = original.clone();
      replacement.enabled = false;
      replacement.action = Action::Deny;
      assert_eq!(set.upsert(replacement.clone()), Some(original));
      assert_eq!(set.len(), 1);
      assert_eq!(set.get(&replacement.id), Some(&replacement));
   }

   #[test]
   fn remove_get_len_and_iter() {
      let mut set = RuleSet::new();
      assert!(set.is_empty());
      let first = rule(
         AppMatcher::Any,
         DestMatcher::Any,
         Action::Allow,
         1,
      );
      let second = rule(
         AppMatcher::Any,
         DestMatcher::Port(443),
         Action::Allow,
         2,
      );
      set.upsert(first.clone());
      set.upsert(second.clone());
      assert_eq!(set.len(), 2);
      assert!(!set.is_empty());
      assert_eq!(
         set.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>(),
         vec![first.id.clone(), second.id.clone()],
         "iteration must be insertion order"
      );

      assert_eq!(set.get(&first.id), Some(&first));
      assert!(set.remove(&first.id));
      assert!(!set.remove(&first.id));
      assert_eq!(set.get(&first.id), None);
      assert_eq!(set.len(), 1);
   }

   #[test]
   fn record_hit_increments_and_stamps() {
      let mut set = RuleSet::new();
      let target = rule(
         AppMatcher::Any,
         DestMatcher::Any,
         Action::Allow,
         1,
      );
      set.upsert(target.clone());
      set.record_hit(&target.id, 99);
      set.record_hit(&target.id, 100);

      let hits = set.get(&target.id).expect("rule still present");
      assert_eq!(hits.hits, 2);
      assert_eq!(hits.last_matched, Some(100));

      set.record_hit(&RuleId::new_unique(), 5);
   }

   #[test]
   fn replace_all_swaps_the_whole_set() {
      let mut set = RuleSet::new();
      let old = rule(
         AppMatcher::Any,
         DestMatcher::Any,
         Action::Allow,
         1,
      );
      set.upsert(old);
      let new = rule(
         AppMatcher::Any,
         DestMatcher::Port(443),
         Action::Deny,
         2,
      );
      set.replace_all(vec![new.clone()]);
      assert_eq!(set.len(), 1);
      assert_eq!(set.get(&new.id), Some(&new));
   }

   #[test]
   fn a_set_ranks_by_the_entry_that_matched() {
      let subdomains = rule(
         AppMatcher::Any,
         DestMatcher::Domain {
            host: "github.com".to_owned(),
            subdomains: true,
         },
         Action::Allow,
         0,
      );
      let list = rule(
         AppMatcher::Any,
         DestMatcher::Set(vec![
            DestMatcher::Domain {
               host: "api.github.com".to_owned(),
               subdomains: false,
            },
            DestMatcher::Ip("10.0.0.0/8".parse::<IpNet>().unwrap()),
         ]),
         Action::Deny,
         0,
      );

      let mut set = RuleSet::new();
      set.upsert(subdomains.clone());
      set.upsert(list.clone());
      assert_eq!(
         set.evaluate(&firefox_conn()),
         Outcome::Deny {
            rule: list.id.clone()
         },
         "the list's exact-domain entry outranks the subdomain rule"
      );

      // The same list, judged against a host none of its entries cover: it must not match at
      // all, whatever its best entry ranks.
      let mut other = RuleSet::new();
      other.upsert(list);
      other.upsert(subdomains.clone());
      let gist = Connection {
         domain: Some("gist.github.com".to_owned()),
         ..firefox_conn()
      };
      assert_eq!(
         other.evaluate(&gist),
         Outcome::Allow {
            rule: subdomains.id.clone()
         },
         "a set does not match a host its entries do not cover"
      );
   }
}
