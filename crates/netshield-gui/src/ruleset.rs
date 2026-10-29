//! The rule list as the GUI holds it: the rules, plus the revision that moves whenever they
//! are replaced.
//!
//! The Connections derivation keys on that pair, so the two travel as one value instead of as
//! arguments that can drift apart.

use std::sync::Arc;

use netshield_core::rule::Rule;

/// The rules most recently received from the daemon and how often they have been replaced.
#[derive(Default)]
pub struct Ruleset {
   list: Arc<Vec<Rule>>,
   rev: u64,
}

impl Ruleset {
   /// Replaces the list and moves the revision, so everything keyed on it rebuilds.
   pub fn install(&mut self, rules: Vec<Rule>) {
      self.list = Arc::new(rules);
      self.rev = self.rev.wrapping_add(1);
   }

   /// The rules themselves, for the page that only draws them.
   pub fn as_slice(&self) -> &[Rule] {
      &self.list
   }

   /// The shared list, for a derivation that must outlive the frame that queued it.
   pub fn shared(&self) -> Arc<Vec<Rule>> {
      Arc::clone(&self.list)
   }

   /// How many times the list has been replaced; the Connections cache keys on it.
   pub fn rev(&self) -> u64 {
      self.rev
   }
}
