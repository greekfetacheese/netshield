//! The nftables table that hands new flows to the daemon, and that kills the flows it
//! later revokes.
//!
//! One `inet` table covers IPv4 and IPv6. It is always installed in a single
//! `nft -f -` transaction and removed by name, so this module can never disturb another
//! application's firewall: there is no `flush ruleset`, no `iptables` and no shell.
//!
//! The ruleset itself is rendered by [`ruleset_text`], a pure function, because the text
//! is the security-relevant artefact and must be assertable in a unit test — the sandbox
//! this ships from has no `CAP_NET_ADMIN` and no business touching the host firewall.
//!
//! Killing a connection needs two parts. Deleting its conntrack entry only makes the
//! kernel forget it, and the endpoints carry on; the connection ends only when its exact
//! tuple is rejected. The two sets below are that mechanism: [`kill_flows`] adds the
//! tuples of the flows being revoked, the reject rules reset them for the length of the
//! element's timeout, and the `ct state established` match keeps a *new* connection from
//! being rejected, so the app can reconnect and be prompted again.

use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};

use log::{info, warn};

use crate::conntrack::Flow;

/// The one table this daemon owns, and the only one it ever touches.
pub const TABLE: &str = "netshield";

/// Marks this daemon writes into conntrack live in the top two bits, so a flush cannot touch a flow
/// stamped by another tool (Docker and Kubernetes both use conntrack marks).
pub const OWNER_TAG: u32 = 0x4000_0000;
/// The bits that identify an owner at all, as opposed to which one.
pub const OWNER_TAG_MASK: u32 = 0xc000_0000;

/// The IPv4 set of tuples that are being rejected while their timeout lasts.
const KILLED4: &str = "killed4";
/// The IPv6 counterpart of [`KILLED4`].
const KILLED6: &str = "killed6";

/// Why an nftables operation failed.
#[derive(Debug)]
pub enum FirewallError {
   /// The caller is not root, so `nft` would fail with `EPERM`; refuse before spawning.
   NotRoot,
   /// `nft` is not installed or not on `PATH`.
   NftMissing,
   /// `nft` ran and failed, or could not be spawned for a reason other than absence.
   Commands(String),
   /// The installed table does not contain what [`ruleset_text`] rendered.
   Verify(String),
}

impl fmt::Display for FirewallError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::NotRoot => f.write_str(
            "must run as root (CAP_NET_ADMIN is required to install the nftables ruleset)",
         ),
         Self::NftMissing => {
            f.write_str("the nft binary was not found on PATH; nftables is required")
         }
         Self::Commands(reason) => write!(f, "nft command failed: {reason}"),
         Self::Verify(reason) => write!(f, "ruleset verification failed: {reason}"),
      }
   }
}

impl std::error::Error for FirewallError {}

/// Renders the ruleset from ARCHITECTURE §2 with the queue numbers substituted.
///
/// Pure: no I/O, so the exact text — chain layout, rule order, `bypass` and the
/// attribution comments — is unit-tested as a string.
pub fn ruleset_text(queue: u16, dns_queue: u16, filter_loopback: bool) -> String {
   let mut text = String::new();
   text.push_str("table inet netshield {\n");
   // The sets have to be declared at table level, before the chain that references them:
   // nft cannot forward-reference a set, and a set cannot be declared inside a chain.
   text.push_str(&format!(
      "    set {KILLED4} {{ type ipv4_addr . ipv4_addr . inet_service . inet_service; \
       flags timeout; }}\n"
   ));
   text.push_str(&format!(
      "    set {KILLED6} {{ type ipv6_addr . ipv6_addr . inet_service . inet_service; \
       flags timeout; }}\n"
   ));
   text.push_str("    chain output {\n");
   text.push_str("        type filter hook output priority mangle; policy accept;\n");
   if !filter_loopback {
      text.push_str(
         "        oifname \"lo\" return comment \"netshield: loopback is not filtered\"\n",
      );
   }
   // Stamped before either queue rule: a queue verdict does not end chain traversal, but
   // the mark has to be set before any decision is made about the packet.
   text.push_str(&format!(
      "        ct state new ct mark set meta skuid | {OWNER_TAG:#010x} \
       comment \"netshield: record the owner\"\n"
   ));
   // `ct state established` is load-bearing: it keeps a new connection from being
   // rejected, so the app can open a fresh one and be prompted again. Keying on the exact
   // tuple is what kills only the revoked flow.
   text.push_str(&format!(
      "        ct state established ip saddr . ip daddr . tcp sport . tcp dport \
       @{KILLED4} reject with tcp reset\n"
   ));
   text.push_str(&format!(
      "        ct state established ip saddr . ip daddr . udp sport . udp dport \
       @{KILLED4} reject with icmpx type admin-prohibited\n"
   ));
   text.push_str(&format!(
      "        ct state established ip6 saddr . ip6 daddr . tcp sport . tcp dport \
       @{KILLED6} reject with tcp reset\n"
   ));
   text.push_str(&format!(
      "        ct state established ip6 saddr . ip6 daddr . udp sport . udp dport \
       @{KILLED6} reject with icmpx type admin-prohibited\n"
   ));
   text.push_str(&format!(
      "        tcp flags & (fin|syn|rst|ack) == syn queue num {queue} bypass \
       comment \"netshield: tcp syn\"\n"
   ));
   text.push_str(&format!(
      "        ct state new queue num {queue} bypass comment \"netshield: non-tcp new flow\"\n"
   ));
   text.push_str("    }\n");
   text.push_str("    chain dns_in {\n");
   text.push_str("        type filter hook input priority mangle; policy accept;\n");
   text.push_str(&format!(
      "        udp sport 53 queue num {dns_queue} bypass comment \"netshield: dns answers\"\n"
   ));
   text.push_str(&format!(
      "        tcp sport 53 queue num {dns_queue} bypass \
       comment \"netshield: dns answers over tcp\"\n"
   ));
   text.push_str("    }\n");
   text.push_str("}\n");
   text
}

/// Deletes the flows in `flows`: for the length of the timeout, the kernel resets them and
/// the app has to open a new connection, which the daemon will decide again.
///
/// One `nft -f -` invocation adds every element, because a process per flow would be a
/// process per connection. An empty `flows` is a no-op success.
pub fn kill_flows(flows: &[Flow], timeout_secs: u64) -> Result<usize, FirewallError> {
   if flows.is_empty() {
      return Ok(0);
   }
   let script = element_text(flows, timeout_secs);
   nft(&["-f", "-"], Some(&script))?;
   info!(
      "rejecting {} flow(s) for {timeout_secs}s",
      flows.len()
   );
   Ok(flows.len())
}

/// Renders the one `nft -f -` script that adds every flow to its family's set.
///
/// Pure, so the exact element syntax — including the per-element timeout, without which
/// the reject would outlive the revocation — is unit-tested without `nft`.
fn element_text(flows: &[Flow], timeout_secs: u64) -> String {
   let mut v4 = Vec::new();
   let mut v6 = Vec::new();
   for flow in flows {
      match flow {
         Flow::V4(source, source_port, destination, destination_port) => v4.push(format!(
            "{} . {} . {} . {} timeout {timeout_secs}s",
            source, destination, source_port, destination_port
         )),
         Flow::V6(source, source_port, destination, destination_port) => v6.push(format!(
            "{} . {} . {} . {} timeout {timeout_secs}s",
            source, destination, source_port, destination_port
         )),
      }
   }
   let mut script = String::new();
   for (set, elements) in [(KILLED4, v4), (KILLED6, v6)] {
      if elements.is_empty() {
         continue;
      }
      script.push_str(&format!(
         "add element inet {TABLE} {set} {{ {} }}\n",
         elements.join(", ")
      ));
   }
   script
}

/// Installs the table in one `nft -f -` transaction.
///
/// With `force` a stale table of ours is deleted first; without it an existing
/// `inet netshield` table is an error, because that means a second instance. If the
/// transaction fails, [`remove`] is attempted so a partial state cannot survive, and the
/// original error is what the caller sees.
pub fn install(
   queue: u16,
   dns_queue: u16,
   filter_loopback: bool,
   force: bool,
) -> Result<(), FirewallError> {
   if effective_uid() != Some(0) {
      warn!("refusing to install the nftables ruleset: not running as root");
      return Err(FirewallError::NotRoot);
   }

   if force {
      remove()?;
   } else if table_exists()? {
      return Err(FirewallError::Commands(format!(
         "table inet {TABLE} already exists; another instance is running or use --force"
      )));
   }

   let ruleset = ruleset_text(queue, dns_queue, filter_loopback);
   match nft(&["-f", "-"], Some(&ruleset)) {
      Ok(_) => {
         // The transcript should show what the kernel actually holds, not just what we
         // rendered; a listing failure here is not a failed install, but it is not silent.
         match nft(&["list", "table", "inet", TABLE], None) {
            Ok(listing) => info!("installed table inet {TABLE}:\n{listing}"),
            Err(err) => warn!("table inet {TABLE} was installed but could not be listed: {err}"),
         }
         Ok(())
      }
      Err(err) => {
         warn!("installing table inet {TABLE} failed, rolling back: {err}");
         if let Err(rollback) = remove() {
            warn!("rollback of table inet {TABLE} also failed: {rollback}");
         }
         Err(err)
      }
   }
}

/// Deletes only `table inet netshield`; a missing table is success.
pub fn remove() -> Result<(), FirewallError> {
   match nft(&["delete", "table", "inet", TABLE], None) {
      Ok(_) => Ok(()),
      Err(err @ FirewallError::NftMissing) => Err(err),
      Err(delete_err) => {
         // Delete-then-list, never message matching: if the table still lists, the delete
         // genuinely failed; if it does not, it was already absent.
         match nft(&["list", "table", "inet", TABLE], None) {
            Ok(_) => Err(FirewallError::Commands(format!(
               "{delete_err}; table inet {TABLE} is still present"
            ))),
            Err(FirewallError::NftMissing) => Err(FirewallError::NftMissing),
            Err(_) => Ok(()),
         }
      }
   }
}

/// Reads the table back and confirms both chains and both queue numbers are present.
///
/// Failing to list means the table is not installed, as does an `nft` that cannot answer:
/// either way there is no verified table to trust, so the probe must not proceed.
pub fn verify(queue: u16, dns_queue: u16) -> Result<(), FirewallError> {
   let listing = match nft(&["list", "table", "inet", TABLE], None) {
      Ok(listing) => listing,
      Err(err @ FirewallError::NftMissing) => return Err(err),
      Err(err) => {
         return Err(FirewallError::Verify(format!(
            "table inet {TABLE} is not installed ({err})"
         )));
      }
   };

   verify_listing(&listing, queue, dns_queue)?;
   info!("verified table inet {TABLE}: chains output/dns_in, queues {queue}/{dns_queue}");
   Ok(())
}

/// Checks a listing for both chains and both queue numbers.
///
/// Split from [`verify`] so the token-level matching is exercised without running `nft`;
/// this is the same check the live probe performs.
fn verify_listing(listing: &str, queue: u16, dns_queue: u16) -> Result<(), FirewallError> {
   for chain in ["chain output", "chain dns_in"] {
      if !listing.contains(chain) {
         return Err(FirewallError::Verify(format!(
            "table inet {TABLE} has no `{chain}`"
         )));
      }
   }
   let queues = listed_queues(listing);
   for wanted in [queue, dns_queue] {
      if !queues.iter().any(|listed| *listed == wanted.to_string()) {
         return Err(FirewallError::Verify(format!(
            "table inet {TABLE} has no rule queueing to {wanted}"
         )));
      }
   }
   Ok(())
}

/// The effective UID from `/proc/self/status`, or `None` when it cannot be determined.
///
/// Reading the status file keeps this module free of raw libc calls: `geteuid` would not
/// be, and raw calls belong only in `src/netlink/`. An unreadable status file is treated
/// as "not root" — the install is refused rather than attempted blind.
fn effective_uid() -> Option<u32> {
   let status = std::fs::read_to_string("/proc/self/status").ok()?;
   parse_effective_uid(&status)
}

/// Extracts the effective UID from the `Uid:` line (`real`, `effective`, `saved`, `fs`).
fn parse_effective_uid(status: &str) -> Option<u32> {
   status
      .lines()
      .find_map(|line| line.strip_prefix("Uid:"))
      .and_then(|fields| fields.split_whitespace().nth(1))
      .and_then(|effective| effective.parse().ok())
}

/// Whether `inet netshield` already exists. An unlistable table counts as absent.
fn table_exists() -> Result<bool, FirewallError> {
   match nft(&["list", "table", "inet", TABLE], None) {
      Ok(_) => Ok(true),
      Err(err @ FirewallError::NftMissing) => Err(err),
      Err(_) => Ok(false),
   }
}

/// Runs `nft` with `args`, optionally feeding `stdin`, and returns its stdout.
///
/// No shell is involved, so nothing in a queue number or a table name can be interpreted
/// as syntax. A missing binary is [`FirewallError::NftMissing`], never a panic.
fn nft(args: &[&str], stdin: Option<&str>) -> Result<String, FirewallError> {
   let mut command = Command::new("nft");
   command.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
   if stdin.is_some() {
      command.stdin(Stdio::piped());
   } else {
      command.stdin(Stdio::null());
   }
   let mut child = command.spawn().map_err(|err| {
      if err.kind() == std::io::ErrorKind::NotFound {
         FirewallError::NftMissing
      } else {
         FirewallError::Commands(format!("could not spawn nft: {err}"))
      }
   })?;

   if let Some(text) = stdin {
      let mut pipe = child
         .stdin
         .take()
         .ok_or_else(|| FirewallError::Commands("nft stdin was not captured".to_owned()))?;
      if let Err(err) = pipe.write_all(text.as_bytes()) {
         let _ = child.kill();
         let _ = child.wait();
         return Err(FirewallError::Commands(format!(
            "could not write the ruleset to nft: {err}"
         )));
      }
   }

   let output = child
      .wait_with_output()
      .map_err(|err| FirewallError::Commands(format!("could not wait for nft: {err}")))?;
   if !output.status.success() {
      let stderr = String::from_utf8_lossy(&output.stderr);
      return Err(FirewallError::Commands(format!(
         "`nft {}` exited {}: {}",
         args.join(" "),
         output.status,
         stderr.trim()
      )));
   }
   Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Every queue number in an `nft list table` listing, as written.
///
/// nftables echoes the rendered `queue num <n>` as `queue flags bypass to <n>`, so both
/// verdict forms are read. Matching is token-level and comments are stripped first, so a
/// number in a comment or an interface name cannot be mistaken for a queue verdict.
fn listed_queues(listing: &str) -> Vec<String> {
   let mut queues = Vec::new();
   for line in listing.lines() {
      let rule = line.split(" comment ").next().unwrap_or(line);
      let tokens: Vec<&str> = rule.split_whitespace().collect();
      for (index, token) in tokens.iter().enumerate() {
         if *token != "queue" {
            continue;
         }
         let mut cursor = index + 1;
         while let Some(next) = tokens.get(cursor) {
            match *next {
               "num" | "to" => {
                  if let Some(number) = tokens.get(cursor + 1) {
                     queues.push((*number).to_owned());
                  }
                  break;
               }
               "flags" | "bypass" => cursor += 1,
               _ => break,
            }
         }
      }
   }
   queues
}

#[cfg(test)]
mod tests {
   use std::net::{Ipv4Addr, Ipv6Addr};

   use super::*;

   #[test]
   fn ruleset_matches_architecture_section_two() {
      let text = ruleset_text(0, 1, false);
      let lines: Vec<&str> = text.lines().collect();
      assert_eq!(
         lines,
         [
            "table inet netshield {",
            "    set killed4 { type ipv4_addr . ipv4_addr . inet_service . inet_service; \
             flags timeout; }",
            "    set killed6 { type ipv6_addr . ipv6_addr . inet_service . inet_service; \
             flags timeout; }",
            "    chain output {",
            "        type filter hook output priority mangle; policy accept;",
            "        oifname \"lo\" return comment \"netshield: loopback is not filtered\"",
            "        ct state new ct mark set meta skuid | 0x40000000 \
             comment \"netshield: record the owner\"",
            "        ct state established ip saddr . ip daddr . tcp sport . tcp dport \
             @killed4 reject with tcp reset",
            "        ct state established ip saddr . ip daddr . udp sport . udp dport \
             @killed4 reject with icmpx type admin-prohibited",
            "        ct state established ip6 saddr . ip6 daddr . tcp sport . tcp dport \
             @killed6 reject with tcp reset",
            "        ct state established ip6 saddr . ip6 daddr . udp sport . udp dport \
             @killed6 reject with icmpx type admin-prohibited",
            "        tcp flags & (fin|syn|rst|ack) == syn queue num 0 bypass \
             comment \"netshield: tcp syn\"",
            "        ct state new queue num 0 bypass comment \"netshield: non-tcp new flow\"",
            "    }",
            "    chain dns_in {",
            "        type filter hook input priority mangle; policy accept;",
            "        udp sport 53 queue num 1 bypass comment \"netshield: dns answers\"",
            "        tcp sport 53 queue num 1 bypass comment \"netshield: dns answers over tcp\"",
            "    }",
            "}",
         ]
      );
   }

   #[test]
   fn the_reject_sets_are_declared_before_the_chain_that_uses_them() {
      let text = ruleset_text(0, 1, false);
      for set in [KILLED4, KILLED6] {
         let declaration = text
            .find(&format!("set {set} {{"))
            .unwrap_or_else(|| panic!("{set} must be declared"));
         let chain = text.find("chain output {").expect("the output chain exists");
         assert!(
            declaration < chain,
            "{set} must be declared before the chain that references it"
         );
      }
   }

   #[test]
   fn only_established_flows_match_a_reject_rule() {
      // `ct state established` is what lets the app reconnect: without it the handshake
      // of the next connection would be rejected too, and the daemon could never prompt.
      let text = ruleset_text(0, 1, false);
      for line in text.lines().filter(|line| line.contains("@killed")) {
         assert!(
            line.trim_start().starts_with("ct state established "),
            "a reject rule must be gated on established state: {line}"
         );
      }
   }

   #[test]
   fn the_element_file_batches_every_flow() {
      let flows = [
         Flow::V4(
            Ipv4Addr::new(10, 0, 0, 1),
            51234,
            Ipv4Addr::new(1, 2, 3, 4),
            443,
         ),
         Flow::V6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            51235,
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            80,
         ),
      ];
      let script = element_text(&flows, 60);
      assert_eq!(
         script,
         "add element inet netshield killed4 { 10.0.0.1 . 1.2.3.4 . 51234 . 443 timeout 60s }\n\
          add element inet netshield killed6 { 2001:db8::1 . 2606:4700:4700::1111 . 51235 . 80 \
          timeout 60s }\n"
      );
   }

   #[test]
   fn every_element_carries_its_timeout() {
      let flows = [Flow::V4(
         Ipv4Addr::new(10, 0, 0, 1),
         1,
         Ipv4Addr::new(10, 0, 0, 2),
         2,
      )];
      let script = element_text(&flows, 90);
      assert!(script.contains(" timeout 90s"));
      assert_eq!(script.matches("add element").count(), 1);
      assert_eq!(element_text(&[], 60), "");
   }

   #[test]
   fn kill_flows_with_no_flows_is_a_successful_no_op() {
      assert_eq!(
         kill_flows(&[], 60).expect("an empty kill is a success"),
         0
      );
   }

   #[test]
   fn ruleset_substitutes_both_queues() {
      let text = ruleset_text(7, 9, false);
      assert_eq!(text.matches("queue num 7").count(), 2);
      assert_eq!(text.matches("queue num 9").count(), 2);
      assert!(!text.contains("queue num 0"));
      assert!(!text.contains("queue num 1"));
   }

   #[test]
   fn loopback_filtering_is_the_only_conditional_rule() {
      let unfiltered = ruleset_text(0, 1, false);
      assert!(unfiltered.contains("oifname \"lo\" return"));
      let filtered = ruleset_text(0, 1, true);
      assert!(!filtered.contains("oifname"));
      assert_eq!(
         filtered.lines().count(),
         unfiltered.lines().count() - 1,
         "only the loopback rule disappears"
      );
   }

   #[test]
   fn every_rule_is_attributed_and_nothing_else_is_flushed() {
      let text = ruleset_text(3, 4, false);
      // Six commented rules plus the two set declarations, which are not rules.
      assert_eq!(text.matches("comment \"netshield:").count(), 6);
      assert!(!text.contains("flush ruleset"));
      assert!(!text.contains("iptables"));
      assert!(text.starts_with("table inet netshield {\n"));
      assert!(text.ends_with("}\n"));
   }

   #[test]
   fn the_owner_is_stamped_before_any_queue_verdict() {
      let text = ruleset_text(3, 4, false);
      let stamp = text
         .find(&format!(
            "ct mark set meta skuid | {OWNER_TAG:#010x}"
         ))
         .expect("the output chain stamps the owner before any decision");
      let syn = text.find("tcp flags").expect("the tcp syn rule is present");
      let non_tcp = text.find("ct state new queue").expect("the non-tcp rule is present");
      assert!(
         stamp < syn,
         "the stamp must precede the tcp queue rule"
      );
      assert!(
         stamp < non_tcp,
         "the stamp must precede the non-tcp queue rule"
      );
   }

   #[test]
   fn the_reject_rules_come_after_the_stamp_and_before_the_queues() {
      let text = ruleset_text(3, 4, false);
      let stamp = text.find("ct mark set meta skuid").expect("the owner stamp is rendered");
      let first_reject = text.find("@killed4").expect("the v4 reject rules are rendered");
      let first_queue = text.find("queue num 3").expect("the tcp queue rule is rendered");
      assert!(
         stamp < first_reject,
         "the stamp must precede the reject rules"
      );
      assert!(
         first_reject < first_queue,
         "the reject rules must precede the queue rules"
      );
      assert_eq!(text.matches("reject with tcp reset").count(), 2);
      assert_eq!(
         text.matches("reject with icmpx type admin-prohibited").count(),
         2
      );
   }

   #[test]
   fn effective_uid_reads_the_second_uid_field() {
      let status = "Name:\tnetshieldd\nUid:\t1000\t1001\t1002\t1003\nGid:\t1000\t1000\n";
      assert_eq!(parse_effective_uid(status), Some(1001));
      assert_eq!(parse_effective_uid("Name:\tnetshieldd\n"), None);
      assert_eq!(parse_effective_uid("Uid:\troot\n"), None);
   }

   #[test]
   fn listed_queues_reads_exact_numbers() {
      let listing = "queue num 0 bypass\nqueue num 1 bypass\nqueue num 10 bypass";
      assert_eq!(listed_queues(listing), ["0", "1", "10"]);
      assert!(!listed_queues(listing).iter().any(|queue| queue == "2"));
   }

   /// The real `nft list table inet netshield` output captured on nftables 1.0.9.
   /// The indentation is a tab, and the spacing is nft's, not the renderer's.
   const FIXTURE: &str = "table inet netshield {\n\tchain output {\n\t\ttype filter hook output priority mangle; policy accept;\n\t\toifname \"lo\" return comment \"netshield: loopback is not filtered\"\n\t\ttcp flags syn / fin,syn,rst,ack queue flags bypass to 0 comment \"netshield: tcp syn\"\n\t\tct state new queue flags bypass to 0 comment \"netshield: non-tcp new flow\"\n\t}\n\n\tchain dns_in {\n\t\ttype filter hook input priority mangle; policy accept;\n\t\tudp sport 53 queue flags bypass to 1 comment \"netshield: dns answers\"\n\t\ttcp sport 53 queue flags bypass to 1 comment \"netshield: dns answers over tcp\"\n\t}\n}\n";

   #[test]
   fn real_nft_listing_verifies_both_queues() {
      assert!(
         FIXTURE.contains('\t'),
         "the captured fixture is tab-indented"
      );
      assert_eq!(listed_queues(FIXTURE), ["0", "0", "1", "1"]);
      verify_listing(FIXTURE, 0, 1).expect("the table NetShield installed must verify");
   }

   #[test]
   fn real_nft_listing_rejects_a_missing_queue() {
      assert!(verify_listing(FIXTURE, 0, 2).is_err());
   }

   #[test]
   fn chains_without_a_queue_verdict_fail() {
      let listing = "table inet netshield {\n\tchain output {\n\t\tct state new return\n\t}\n\tchain dns_in {\n\t\tudp sport 53 return\n\t}\n}\n";
      assert!(verify_listing(listing, 0, 1).is_err());
   }

   #[test]
   fn a_single_digit_queue_is_not_satisfied_by_a_longer_number() {
      let listing = "\tchain output {\n\t\tct state new queue flags bypass to 10\n\t}\n\tchain dns_in {\n\t\tudp sport 53 queue flags bypass to 10\n\t}\n";
      assert!(verify_listing(listing, 10, 10).is_ok());
      assert!(verify_listing(listing, 1, 10).is_err());
   }

   #[test]
   fn a_number_inside_a_comment_is_not_a_queue_verdict() {
      let listing = "\tchain output {\n\t\tct state new return comment \"queue num 1\"\n\t}\n\tchain dns_in {\n\t\tudp sport 53 queue flags bypass to 0 comment \"queue num 1\"\n\t}\n";
      assert!(verify_listing(listing, 0, 0).is_ok());
      assert!(verify_listing(listing, 0, 1).is_err());
   }

   #[test]
   fn renderer_form_queue_num_also_verifies() {
      let listing = ruleset_text(0, 1, false);
      assert!(listing.contains("queue num 0"));
      assert!(!listing.contains("queue flags bypass to"));
      assert_eq!(listed_queues(&listing), ["0", "0", "1", "1"]);
      verify_listing(&listing, 0, 1).expect("the renderer's own syntax must verify too");
   }

   #[test]
   fn errors_render_loudly() {
      assert!(FirewallError::NotRoot.to_string().contains("root"));
      assert!(FirewallError::NftMissing.to_string().contains("nft"));
      assert!(FirewallError::Commands("boom".to_owned()).to_string().contains("boom"));
      assert!(FirewallError::Verify("missing".to_owned()).to_string().contains("missing"));
   }
}
