//! Pure IPv4/IPv6 → domain correlation cache.
//!
//! The cache is deliberately clock-free: callers pass `now` in unix seconds, so TTL
//! behaviour is unit-testable without a wall clock and the daemon owns the sweep policy.

use std::collections::HashMap;
use std::net::IpAddr;

/// Records are capped at one hour so a reassigned CDN address does not inherit a stale
/// name for longer than a browser session.
pub const MAX_TTL_SECS: u32 = 3600;

/// One name learned for one address.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
   name: String,
   expires_at: u64,
}

impl Entry {
   fn is_live(&self, now: u64) -> bool {
      now < self.expires_at
   }
}

/// Address → names learned from DNS answers, most recently inserted first.
///
/// One address can answer many sites, so each lookup returns all live names and the
/// prompt shows the first; the rest stay available as the prompt's detail.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsCache {
   entries: HashMap<IpAddr, Vec<Entry>>,
}

impl DnsCache {
   /// Creates an empty cache.
   pub fn new() -> Self {
      Self::default()
   }

   /// Records that `name` resolved to `ip` with `ttl` seconds of life.
   ///
   /// The TTL is clamped to `1..=MAX_TTL_SECS`. Re-inserting a name refreshes its expiry
   /// and moves it to the front instead of duplicating it.
   pub fn insert(&mut self, ip: IpAddr, name: &str, ttl: u32, now: u64) {
      let ttl = ttl.clamp(1, MAX_TTL_SECS);
      let expires_at = now.saturating_add(u64::from(ttl));
      let names = self.entries.entry(ip).or_default();
      names.retain(|entry| entry.name != name);
      names.insert(
         0,
         Entry {
            name: name.to_owned(),
            expires_at,
         },
      );
   }

   /// All live names for `ip` at `now`, most recently inserted first.
   ///
   /// Lookups take `&self` and so never remove expired entries; [`DnsCache::expire`] is
   /// the caller's periodic sweep.
   pub fn names_for(&self, ip: IpAddr, now: u64) -> Vec<&str> {
      self
         .entries
         .get(&ip)
         .map(|entries| {
            entries
               .iter()
               .filter(|entry| entry.is_live(now))
               .map(|entry| entry.name.as_str())
               .collect()
         })
         .unwrap_or_default()
   }

   /// The most recently learned live name for `ip`, which is what a prompt displays.
   pub fn primary(&self, ip: IpAddr, now: u64) -> Option<&str> {
      self.names_for(ip, now).into_iter().next()
   }

   /// Drops expired names and empty addresses, returning how many names were removed.
   pub fn expire(&mut self, now: u64) -> usize {
      let mut removed = 0;
      self.entries.retain(|_, entries| {
         let before = entries.len();
         entries.retain(|entry| entry.is_live(now));
         removed += before - entries.len();
         !entries.is_empty()
      });
      removed
   }

   /// The number of cached names across all addresses.
   pub fn len(&self) -> usize {
      self.entries.values().map(Vec::len).sum()
   }

   /// Returns whether no names are cached.
   pub fn is_empty(&self) -> bool {
      self.entries.is_empty()
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::net::{Ipv4Addr, Ipv6Addr};

   fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
      IpAddr::V4(Ipv4Addr::new(a, b, c, d))
   }

   #[test]
   fn names_for_one_address_are_most_recent_first() {
      let primary_ip = v4(93, 184, 216, 34);
      let mut primary = DnsCache::new();
      primary.insert(primary_ip, "example.com", 300, 1_000);
      assert_eq!(
         primary.primary(primary_ip, 1_000),
         Some("example.com"),
         "inserted name is the primary"
      );

      let ip = v4(93, 184, 216, 36);
      let mut cache = DnsCache::new();
      cache.insert(ip, "first.example", 300, 1_000);
      cache.insert(ip, "second.example", 300, 1_001);
      assert_eq!(
         cache.names_for(ip, 1_001),
         vec!["second.example", "first.example"],
         "most recent first"
      );

      let refreshed = v4(93, 184, 216, 35);
      let mut cache = DnsCache::new();
      cache.insert(refreshed, "a.example", 300, 0);
      cache.insert(refreshed, "b.example", 300, 1);
      cache.insert(refreshed, "a.example", 300, 2);
      assert_eq!(cache.len(), 2, "refresh does not duplicate");
      assert_eq!(
         cache.names_for(refreshed, 2),
         vec!["a.example", "b.example"],
         "refreshed entry is most recent"
      );
      // The refreshed entry outlives its original expiry.
      assert_eq!(
         cache.primary(refreshed, 300),
         Some("a.example"),
         "refreshed expiry"
      );
   }

   #[test]
   fn ttl_is_clamped_at_both_ends() {
      let ip = v4(203, 0, 113, 5);
      let mut cache = DnsCache::new();

      cache.insert(ip, "long.example", MAX_TTL_SECS + 600, 0);
      let max = u64::from(MAX_TTL_SECS);
      assert_eq!(cache.primary(ip, max - 1), Some("long.example"));
      assert_eq!(cache.primary(ip, max), None);

      let floor = v4(203, 0, 113, 6);
      cache.insert(floor, "short.example", 0, 0);
      assert_eq!(cache.primary(floor, 0), Some("short.example"));
      assert_eq!(cache.primary(floor, 1), None);
   }

   #[test]
   fn expired_name_is_absent_from_lookups_but_still_counted() {
      let ip = v4(198, 51, 100, 7);
      let mut cache = DnsCache::new();
      cache.insert(ip, "stale.example", 5, 100);
      assert_eq!(cache.names_for(ip, 105), Vec::<&str>::new());
      assert_eq!(cache.primary(ip, 105), None);
      assert_eq!(cache.len(), 1);
   }

   #[test]
   fn expire_removes_expired_names_and_counts_them() {
      let mut cache = DnsCache::new();
      cache.insert(v4(1, 1, 1, 1), "old.example", 5, 0);
      cache.insert(v4(1, 1, 1, 1), "new.example", 60, 0);
      cache.insert(v4(2, 2, 2, 2), "gone.example", 5, 0);
      cache.insert(v4(3, 3, 3, 3), "live.example", 60, 0);

      assert_eq!(cache.expire(10), 2);
      assert_eq!(cache.len(), 2);
      assert_eq!(
         cache.names_for(v4(1, 1, 1, 1), 10),
         vec!["new.example"]
      );
      assert!(cache.names_for(v4(2, 2, 2, 2), 10).is_empty());
      assert_eq!(cache.expire(10), 0);
   }

   #[test]
   fn len_counts_names_not_addresses() {
      let mut cache = DnsCache::new();
      cache.insert(v4(1, 2, 3, 4), "one.example", 60, 0);
      cache.insert(v4(1, 2, 3, 4), "two.example", 60, 0);
      cache.insert(
         IpAddr::V6(Ipv6Addr::LOCALHOST),
         "six.example",
         60,
         0,
      );
      assert_eq!(cache.len(), 3);
      assert!(!cache.is_empty());

      let empty = DnsCache::new();
      assert!(empty.is_empty());
      assert_eq!(empty.len(), 0);
   }
}
