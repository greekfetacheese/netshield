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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

use log::{info, warn};

/// One tracked flow, in the shape the firewall's revoke sets need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
   /// Local address, local port, remote address, remote port.
   V4(Ipv4Addr, u16, Ipv4Addr, u16),
   /// Local address, local port, remote address, remote port.
   V6(Ipv6Addr, u16, Ipv6Addr, u16),
}

/// The IPv4 set of tuples that are being rejected while their timeout lasts.
const KILLED4: &str = "killed4";
/// The IPv6 counterpart of [`KILLED4`].
const KILLED6: &str = "killed6";

/// Why an nftables operation failed.
#[derive(Debug)]
pub enum FirewallError {
   /// The caller is not root, so `nft` would fail with `EPERM`; refuse before spawning.
   NotRoot,
   /// `nft` is not installed at any of the absolute candidate paths.
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
            f.write_str("the nft binary was not found at any absolute path; nftables is required")
         }
         Self::Commands(reason) => write!(f, "nft command failed: {reason}"),
         Self::Verify(reason) => write!(f, "ruleset verification failed: {reason}"),
      }
   }
}

impl std::error::Error for FirewallError {}

/// Renders the ruleset from ARCHITECTURE §2 for `table`, with the queue numbers substituted.
///
/// Pure: no I/O, so the exact text — table name, chain layout, rule order, `bypass` and the
/// attribution comments — is unit-tested as a string.
pub fn ruleset_text(table: &str, queue: u16, dns_queue: u16, filter_loopback: bool) -> String {
   let mut text = String::new();
   text.push_str(&format!("table inet {table} {{\n"));
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
pub fn kill_flows(table: &str, flows: &[Flow], timeout_secs: u64) -> Result<usize, FirewallError> {
   if flows.is_empty() {
      return Ok(0);
   }
   let script = element_text(table, flows, timeout_secs);
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
fn element_text(table: &str, flows: &[Flow], timeout_secs: u64) -> String {
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
         "add element inet {table} {set} {{ {} }}\n",
         elements.join(", ")
      ));
   }
   script
}

/// Installs the table in one `nft -f -` transaction.
///
/// With `force` a stale table of the configured name is deleted first; without it an existing
/// table of that name is an error, because that means a second instance owns it. A different
/// name is a different table, so two daemons never share one. If the transaction fails,
/// [`remove`] is attempted so a partial state cannot survive, and the original error is what
/// the caller sees.
pub fn install(
   table: &str,
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
      remove(table)?;
   } else if table_exists(table)? {
      return Err(FirewallError::Commands(format!(
         "table inet {table} already exists; another instance is running or use --force"
      )));
   }

   let ruleset = ruleset_text(table, queue, dns_queue, filter_loopback);
   match nft(&["-f", "-"], Some(&ruleset)) {
      Ok(_) => {
         // The transcript should show what the kernel actually holds, not just what we
         // rendered; a listing failure here is not a failed install, but it is not silent.
         match nft(&["list", "table", "inet", table], None) {
            Ok(listing) => info!("installed table inet {table}:\n{listing}"),
            Err(err) => warn!("table inet {table} was installed but could not be listed: {err}"),
         }
         Ok(())
      }
      Err(err) => {
         warn!("installing table inet {table} failed, rolling back: {err}");
         if let Err(rollback) = remove(table) {
            warn!("rollback of table inet {table} also failed: {rollback}");
         }
         Err(err)
      }
   }
}

/// Deletes only `table inet <table>`; a missing table is success.
pub fn remove(table: &str) -> Result<(), FirewallError> {
   match nft(&["delete", "table", "inet", table], None) {
      Ok(_) => Ok(()),
      Err(err @ FirewallError::NftMissing) => Err(err),
      Err(delete_err) => {
         // Delete-then-list, never message matching: if the table still lists, the delete
         // genuinely failed; if it does not, it was already absent.
         match nft(&["list", "table", "inet", table], None) {
            Ok(_) => Err(FirewallError::Commands(format!(
               "{delete_err}; table inet {table} is still present"
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
pub fn verify(table: &str, queue: u16, dns_queue: u16) -> Result<(), FirewallError> {
   let listing = match nft(&["list", "table", "inet", table], None) {
      Ok(listing) => listing,
      Err(err @ FirewallError::NftMissing) => return Err(err),
      Err(err) => {
         return Err(FirewallError::Verify(format!(
            "table inet {table} is not installed ({err})"
         )));
      }
   };

   verify_listing(table, &listing, queue, dns_queue)?;
   info!("verified table inet {table}: chains output/dns_in, queues {queue}/{dns_queue}");
   Ok(())
}

/// Checks a listing for both chains and both queue numbers.
///
/// Split from [`verify`] so the token-level matching is exercised without running `nft`;
/// this is the same check the live probe performs.
fn verify_listing(
   table: &str,
   listing: &str,
   queue: u16,
   dns_queue: u16,
) -> Result<(), FirewallError> {
   for chain in ["chain output", "chain dns_in"] {
      if !listing.contains(chain) {
         return Err(FirewallError::Verify(format!(
            "table inet {table} has no `{chain}`"
         )));
      }
   }
   let queues = listed_queues(listing);
   for wanted in [queue, dns_queue] {
      if !queues.iter().any(|listed| *listed == wanted.to_string()) {
         return Err(FirewallError::Verify(format!(
            "table inet {table} has no rule queueing to {wanted}"
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

/// Whether `inet <table>` already exists. An unlistable table counts as absent.
fn table_exists(table: &str) -> Result<bool, FirewallError> {
   match nft(&["list", "table", "inet", table], None) {
      Ok(_) => Ok(true),
      Err(err @ FirewallError::NftMissing) => Err(err),
      Err(_) => Ok(false),
   }
}

/// Where `nft` may be installed, most specific first.
///
/// The daemon runs as root and must never take a binary name from `PATH`: a unit or a
/// privileged shell can put an attacker-writable directory there, and resolving the firewall
/// tool through it hands the whole table to that directory. These four are the FHS locations
/// the nftables package installs into; the first that exists is the one used.
const NFT_CANDIDATES: [&str; 4] = ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"];

/// The absolute path of the installed `nft`, or `None` when none of the candidates exists.
///
/// Deliberately no `PATH` fallback: a missing binary is [`FirewallError::NftMissing`], and
/// the error already says nftables is required.
fn nft_binary() -> Option<&'static str> {
   NFT_CANDIDATES
      .iter()
      .copied()
      .find(|candidate| std::path::Path::new(candidate).exists())
}

/// Runs `nft` with `args`, optionally feeding `stdin`, and returns its stdout.
///
/// No shell is involved, so nothing in a queue number or a table name can be interpreted
/// as syntax. The binary is an absolute candidate path, never a `PATH` lookup. A missing
/// binary is [`FirewallError::NftMissing`], never a panic.
fn nft(args: &[&str], stdin: Option<&str>) -> Result<String, FirewallError> {
   let binary = nft_binary().ok_or(FirewallError::NftMissing)?;
   let mut command = Command::new(binary);
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
   use super::*;

   /// The name the tests render by default; the configurable name is tested separately.
   const DEFAULT: &str = "netshield";

   /// The table name is not a constant: the rendered ruleset carries the configured name, so a
   /// second daemon can install into its own table and never touch the real one.
   #[test]
   fn the_ruleset_uses_the_configured_table_and_queues() {
      let config: netshield_core::Config = serde_json::from_str(
         r#"{"table": "netshielddiag", "queue_num": 0, "dns_queue_num": 1,
            "prompt_timeout_secs": 30, "default_action": "prompt", "allowed_uid": null,
            "log_level": "info", "socket_path": "/run/x", "rules_path": "/etc/x"}"#,
      )
      .expect("the config with a table name must load");

      let text = ruleset_text(config.table_name(), 0, 1, false);
      assert!(
         text.starts_with("table inet netshielddiag {\n"),
         "the rendered ruleset must name the configured table, got: {text}"
      );
      assert!(
         !text.contains("table inet netshield {"),
         "the default table must not be rendered alongside it"
      );

      let text = ruleset_text(DEFAULT, 7, 9, false);
      assert_eq!(text.matches("queue num 7").count(), 2);
      assert_eq!(text.matches("queue num 9").count(), 2);
      assert!(!text.contains("queue num 0"));
      assert!(!text.contains("queue num 1"));
   }

   #[test]
   fn only_established_flows_match_a_reject_rule() {
      // `ct state established` is what lets the app reconnect: without it the handshake
      // of the next connection would be rejected too, and the daemon could never prompt.
      let text = ruleset_text(DEFAULT, 0, 1, false);
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
      let script = element_text(DEFAULT, &flows, 60);
      assert_eq!(
         script,
         "add element inet netshield killed4 { 10.0.0.1 . 1.2.3.4 . 51234 . 443 timeout 60s }\n\
          add element inet netshield killed6 { 2001:db8::1 . 2606:4700:4700::1111 . 51235 . 80 \
          timeout 60s }\n"
      );

      for (timeout, expected) in [(60, " timeout 60s"), (90, " timeout 90s")] {
         let one = [Flow::V4(
            Ipv4Addr::new(10, 0, 0, 1),
            1,
            Ipv4Addr::new(10, 0, 0, 2),
            2,
         )];
         let script = element_text(DEFAULT, &one, timeout);
         assert!(script.contains(expected));
         assert_eq!(script.matches("add element").count(), 1);
      }
      assert_eq!(element_text(DEFAULT, &[], 60), "");
   }

   #[test]
   fn kill_flows_with_no_flows_is_a_successful_no_op() {
      assert_eq!(
         kill_flows(DEFAULT, &[], 60).expect("an empty kill is a success"),
         0
      );
   }

   #[test]
   fn loopback_filtering_is_the_only_conditional_rule() {
      let unfiltered = ruleset_text(DEFAULT, 0, 1, false);
      assert!(unfiltered.contains("oifname \"lo\" return"));
      let filtered = ruleset_text(DEFAULT, 0, 1, true);
      assert!(!filtered.contains("oifname"));
      assert_eq!(
         filtered.lines().count(),
         unfiltered.lines().count() - 1,
         "only the loopback rule disappears"
      );
   }

   #[test]
   fn every_rule_is_attributed_and_nothing_else_is_flushed() {
      let text = ruleset_text(DEFAULT, 3, 4, false);
      // Five commented rules plus the two set declarations, which are not rules.
      assert_eq!(text.matches("comment \"netshield:").count(), 5);
      assert!(!text.contains("flush ruleset"));
      assert!(!text.contains("iptables"));
      assert!(text.starts_with("table inet netshield {\n"));
      assert!(text.ends_with("}\n"));
   }

   #[test]
   fn the_ruleset_rejects_before_it_queues() {
      let text = ruleset_text(DEFAULT, 3, 4, false);
      let chain = text.find("chain output {").expect("the output chain exists");
      for set in [KILLED4, KILLED6] {
         let declaration = text
            .find(&format!("set {set} {{"))
            .unwrap_or_else(|| panic!("{set} must be declared"));
         assert!(
            declaration < chain,
            "{set} must be declared before the chain that references it"
         );
      }

      let first_reject = text.find("@killed4").expect("the v4 reject rules are rendered");
      let first_queue = text.find("queue num 3").expect("the tcp queue rule is rendered");
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

   /// The real `nft list table inet netshield` output captured on nftables 1.0.9.
   /// The indentation is a tab, and the spacing is nft's, not the renderer's.
   const FIXTURE: &str = "table inet netshield {\n\tchain output {\n\t\ttype filter hook output priority mangle; policy accept;\n\t\toifname \"lo\" return comment \"netshield: loopback is not filtered\"\n\t\ttcp flags syn / fin,syn,rst,ack queue flags bypass to 0 comment \"netshield: tcp syn\"\n\t\tct state new queue flags bypass to 0 comment \"netshield: non-tcp new flow\"\n\t}\n\n\tchain dns_in {\n\t\ttype filter hook input priority mangle; policy accept;\n\t\tudp sport 53 queue flags bypass to 1 comment \"netshield: dns answers\"\n\t\ttcp sport 53 queue flags bypass to 1 comment \"netshield: dns answers over tcp\"\n\t}\n}\n";

   #[test]
   fn verify_listing_accepts_both_renderings_and_rejects_a_missing_queue() {
      let listing = "queue num 0 bypass\nqueue num 1 bypass\nqueue num 10 bypass";
      assert_eq!(listed_queues(listing), ["0", "1", "10"]);
      assert!(!listed_queues(listing).iter().any(|queue| queue == "2"));

      let renderer = ruleset_text(DEFAULT, 0, 1, false);
      assert!(renderer.contains("queue num 0"));
      assert!(!renderer.contains("queue flags bypass to"));
      assert_eq!(listed_queues(&renderer), ["0", "0", "1", "1"]);

      assert!(
         FIXTURE.contains('\t'),
         "the captured fixture is tab-indented"
      );
      assert_eq!(listed_queues(FIXTURE), ["0", "0", "1", "1"]);

      let no_verdict = "table inet netshield {\n\tchain output {\n\t\tct state new return\n\t}\n\tchain dns_in {\n\t\tudp sport 53 return\n\t}\n}\n";
      let single_digit = "\tchain output {\n\t\tct state new queue flags bypass to 10\n\t}\n\tchain dns_in {\n\t\tudp sport 53 queue flags bypass to 10\n\t}\n";
      let comment_number = "\tchain output {\n\t\tct state new return comment \"queue num 1\"\n\t}\n\tchain dns_in {\n\t\tudp sport 53 queue flags bypass to 0 comment \"queue num 1\"\n\t}\n";

      let cases = [
         ("the fixture verifies", FIXTURE, 0, 1, true),
         (
            "the renderer form verifies",
            &renderer,
            0,
            1,
            true,
         ),
         (
            "a long queue matches itself",
            single_digit,
            10,
            10,
            true,
         ),
         (
            "a comment is not a verdict",
            comment_number,
            0,
            0,
            true,
         ),
         (
            "the fixture lacks the dns queue",
            FIXTURE,
            0,
            2,
            false,
         ),
         ("no queue verdict fails", no_verdict, 0, 1, false),
         (
            "single digit != longer number",
            single_digit,
            1,
            10,
            false,
         ),
         (
            "comment number != queue number",
            comment_number,
            0,
            1,
            false,
         ),
      ];
      for (name, listing, queue, dns_queue, ok) in cases {
         assert_eq!(
            verify_listing(DEFAULT, listing, queue, dns_queue).is_ok(),
            ok,
            "{name}: {listing}"
         );
      }
   }

   #[test]
   fn the_nft_binary_is_never_resolved_through_path() {
      // A root daemon must not take the firewall tool from PATH: every candidate is an
      // absolute path, and the lookup can only ever yield one of them or nothing.
      for candidate in NFT_CANDIDATES {
         assert!(
            std::path::Path::new(candidate).is_absolute(),
            "{candidate} must be an absolute path"
         );
      }
      let resolved = nft_binary();
      assert!(
         resolved.is_none() || NFT_CANDIDATES.contains(&resolved.expect("checked")),
         "nft_binary() must return a candidate or None, got {resolved:?}"
      );
      assert_eq!(
         nft_binary(),
         resolved,
         "the lookup is fixed for one installed set"
      );
   }
}
