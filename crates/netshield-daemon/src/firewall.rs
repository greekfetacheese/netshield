//! The nftables table that hands new flows to the daemon.
//!
//! One `inet` table covers IPv4 and IPv6. It is always installed in a single
//! `nft -f -` transaction and removed by name, so this module can never disturb another
//! application's firewall: there is no `flush ruleset`, no `iptables` and no shell.
//!
//! The ruleset itself is rendered by [`ruleset_text`], a pure function, because the text
//! is the security-relevant artefact and must be assertable in a unit test — the sandbox
//! this ships from has no `CAP_NET_ADMIN` and no business touching the host firewall.

use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};

use log::{info, warn};

/// The one table this daemon owns, and the only one it ever touches.
pub const TABLE: &str = "netshield";

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
   text.push_str("    chain output {\n");
   text.push_str("        type filter hook output priority mangle; policy accept;\n");
   if !filter_loopback {
      text.push_str(
         "        oifname \"lo\" return comment \"netshield: loopback is not filtered\"\n",
      );
   }
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

   for chain in ["chain output", "chain dns_in"] {
      if !listing.contains(chain) {
         return Err(FirewallError::Verify(format!(
            "table inet {TABLE} has no `{chain}`"
         )));
      }
   }
   let queues = listed_queues(&listing);
   for wanted in [queue, dns_queue] {
      if !queues.iter().any(|listed| *listed == wanted.to_string()) {
         return Err(FirewallError::Verify(format!(
            "table inet {TABLE} has no rule queueing to {wanted}"
         )));
      }
   }
   info!("verified table inet {TABLE}: chains output/dns_in, queues {queue}/{dns_queue}");
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

/// Every `queue num <n>` value in an `nft list table` listing, as written.
fn listed_queues(listing: &str) -> Vec<String> {
   let tokens: Vec<&str> = listing.split_whitespace().collect();
   tokens
      .windows(3)
      .filter(|window| window[0] == "queue" && window[1] == "num")
      .map(|window| window[2].to_owned())
      .collect()
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn ruleset_matches_architecture_section_two() {
      let text = ruleset_text(0, 1, false);
      let lines: Vec<&str> = text.lines().collect();
      assert_eq!(
         lines,
         [
            "table inet netshield {",
            "    chain output {",
            "        type filter hook output priority mangle; policy accept;",
            "        oifname \"lo\" return comment \"netshield: loopback is not filtered\"",
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
      assert_eq!(text.matches("comment \"netshield:").count(), 5);
      assert!(!text.contains("flush ruleset"));
      assert!(!text.contains("iptables"));
      assert!(text.starts_with("table inet netshield {\n"));
      assert!(text.ends_with("}\n"));
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

   #[test]
   fn errors_render_loudly() {
      assert!(FirewallError::NotRoot.to_string().contains("root"));
      assert!(FirewallError::NftMissing.to_string().contains("nft"));
      assert!(FirewallError::Commands("boom".to_owned()).to_string().contains("boom"));
      assert!(FirewallError::Verify("missing".to_owned()).to_string().contains("missing"));
   }
}
