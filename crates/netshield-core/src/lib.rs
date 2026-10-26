#![forbid(unsafe_code)]
//! Pure domain model for NetShield.
//!
//! Everything in this crate is deterministic and free of I/O on the decision path: the
//! daemon may read `/proc`, parse packets and write the rule store, but it hands the
//! resulting values here and gets a verdict back. Keeping matching pure is what makes the
//! specificity and tie-breaking rules unit-testable without root or a live network.

pub mod config;
pub mod connection;
pub mod dns;
pub mod dns_cache;
pub mod ipc;
pub mod ipnet;
pub mod packet;
pub mod rule;
pub mod ruleset;

pub use config::{Config, ConfigError, DefaultAction, LogLevel};
pub use connection::{Attribution, Connection, Endpoint, Family, FlowKey, L4Proto, ProcessInfo};
pub use ipnet::{IpNet, IpNetError};
pub use rule::{
   Action, AppMatcher, DestMatcher, Duration, Rule, RuleError, RuleId, ScopeRequest,
   normalize_host, rule_from_scope,
};
pub use ruleset::{Outcome, RuleSet};
