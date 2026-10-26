//! `netshieldd`: CLI, and the `--probe` harness that proves interception on a live host.
//!
//! The probe is deliberately small: install the table from ARCHITECTURE §2, verify the
//! kernel holds it, then read the connection queue and answer every packet with `Accept`
//! while printing what arrived. It exists so the orchestrator can watch a real packet
//! traverse nftables → nfnetlink → this process, on the real machine, without guessing.

use std::process::ExitCode;

use log::{error, info};
use netshield_daemon::firewall::{self, FirewallError};
use netshield_daemon::logging;
use netshield_daemon::netlink::nfqueue::{NfQueue, NfqError, Packet, Verdict};

const USAGE: &str = "\
netshieldd — NetShield's root firewall daemon

USAGE:
    netshieldd                     run the daemon (not implemented yet; prints this)
    netshieldd --probe [OPTIONS]   install the ruleset and prove packet interception
    netshieldd --help
    netshieldd --version

OPTIONS (--probe):
    --queue N            NFQUEUE number for new-flow connection packets (default 0)
    --dns-queue N        NFQUEUE number for DNS answer packets (default 1)
    --filter-loopback    also queue loopback traffic (off by default; ARCHITECTURE §2)
    --count N            exit after N connection packets (default: run until interrupted)

The probe prints the rendered ruleset, installs it in one nft transaction, verifies the
installed table, then logs every queued packet and accepts it. The table is removed on
every clean exit path, and on a panic a guard removes it during unwinding.
";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
struct Args {
   mode: Mode,
   queue: u16,
   dns_queue: u16,
   filter_loopback: bool,
   count: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
   /// No arguments: the real daemon loop arrives in the next task.
   Usage,
   Help,
   Version,
   Probe,
}

impl Default for Args {
   fn default() -> Self {
      Self {
         mode: Mode::Usage,
         queue: 0,
         dns_queue: 1,
         filter_loopback: false,
         count: None,
      }
   }
}

/// Why the command line was rejected.
#[derive(Debug)]
enum ArgError {
   UnknownOption(String),
   MissingValue(&'static str),
   BadNumber { option: &'static str, value: String },
   OutOfRange { option: &'static str, value: String },
   UnexpectedPositional(String),
}

impl std::fmt::Display for ArgError {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self {
         Self::UnknownOption(option) => write!(f, "unknown option `{option}`"),
         Self::MissingValue(option) => write!(f, "option `{option}` needs a value"),
         Self::BadNumber { option, value } => {
            write!(
               f,
               "option `{option}` expects a number, got `{value}`"
            )
         }
         Self::OutOfRange { option, value } => {
            write!(
               f,
               "option `{option}` value `{value}` is out of range"
            )
         }
         Self::UnexpectedPositional(arg) => write!(f, "unexpected argument `{arg}`"),
      }
   }
}

/// Parses the process arguments (without the program name).
fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Args, ArgError> {
   let mut parsed = Args::default();
   let mut iter = args.into_iter();
   while let Some(arg) = iter.next() {
      match arg.as_str() {
         "--help" | "-h" => parsed.mode = Mode::Help,
         "--version" | "-V" => parsed.mode = Mode::Version,
         "--probe" => parsed.mode = Mode::Probe,
         "--filter-loopback" => parsed.filter_loopback = true,
         "--queue" => {
            let value = iter.next().ok_or(ArgError::MissingValue("--queue"))?;
            parsed.queue = parse_u16("--queue", value)?;
         }
         "--dns-queue" => {
            let value = iter.next().ok_or(ArgError::MissingValue("--dns-queue"))?;
            parsed.dns_queue = parse_u16("--dns-queue", value)?;
         }
         "--count" => {
            let value = iter.next().ok_or(ArgError::MissingValue("--count"))?;
            parsed.count = Some(parse_count(value)?);
         }
         other => {
            return Err(if other.starts_with('-') {
               ArgError::UnknownOption(other.to_owned())
            } else {
               ArgError::UnexpectedPositional(other.to_owned())
            });
         }
      }
   }
   Ok(parsed)
}

fn parse_u16(option: &'static str, value: String) -> Result<u16, ArgError> {
   value.parse().map_err(|_| ArgError::BadNumber { option, value })
}

fn parse_count(value: String) -> Result<u64, ArgError> {
   let parsed: u64 = value.parse().map_err(|_| ArgError::BadNumber {
      option: "--count",
      value: value.clone(),
   })?;
   if parsed == 0 {
      return Err(ArgError::OutOfRange {
         option: "--count",
         value,
      });
   }
   Ok(parsed)
}

/// Why a probe run stopped.
#[derive(Debug)]
enum ProbeError {
   Firewall(FirewallError),
   Queue { queue: u16, reason: NfqError },
}

impl std::fmt::Display for ProbeError {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self {
         Self::Firewall(err) => write!(f, "{err}"),
         Self::Queue { queue, reason } => write!(f, "NFQUEUE {queue}: {reason}"),
      }
   }
}

impl From<FirewallError> for ProbeError {
   fn from(err: FirewallError) -> Self {
      Self::Firewall(err)
   }
}

/// Removes the table on drop, so a panic or an early return still cleans up.
struct FirewallGuard {
   armed: bool,
}

impl FirewallGuard {
   /// Arms cleanup for a table that has just been installed.
   fn new() -> Self {
      Self { armed: true }
   }

   /// Disarms after an explicit [`firewall::remove`] succeeded.
   fn disarm(&mut self) {
      self.armed = false;
   }
}

impl Drop for FirewallGuard {
   fn drop(&mut self) {
      if !self.armed {
         return;
      }
      match firewall::remove() {
         Ok(()) => info!("removed table inet {}", firewall::TABLE),
         Err(err) => error!(
            "could not remove table inet {} during cleanup: {err}",
            firewall::TABLE
         ),
      }
   }
}

fn main() -> ExitCode {
   let args = match parse_args(std::env::args().skip(1)) {
      Ok(args) => args,
      Err(err) => {
         eprintln!("netshieldd: {err}\n\n{USAGE}");
         return ExitCode::from(2);
      }
   };

   logging::init(log::LevelFilter::Info);

   match args.mode {
      Mode::Usage => {
         eprintln!("{USAGE}");
         ExitCode::from(2)
      }
      Mode::Help => {
         println!("{USAGE}");
         ExitCode::SUCCESS
      }
      Mode::Version => {
         println!("netshieldd {}", env!("CARGO_PKG_VERSION"));
         ExitCode::SUCCESS
      }
      Mode::Probe => match probe(&args) {
         Ok(()) => ExitCode::SUCCESS,
         Err(err) => {
            error!("{err}");
            ExitCode::FAILURE
         }
      },
   }
}

/// The `--probe` flow: render, install, verify, then answer packets until `--count`.
///
/// The guard is armed only once the transaction succeeded, so a refused install (not
/// root, missing `nft`, an existing table) reports the original error and nothing else;
/// from then on every exit path — including a panic while reading packets — removes the
/// table.
fn probe(args: &Args) -> Result<(), ProbeError> {
   let ruleset = firewall::ruleset_text(args.queue, args.dns_queue, args.filter_loopback);
   info!("rendered ruleset:\n{ruleset}");

   firewall::install(
      args.queue,
      args.dns_queue,
      args.filter_loopback,
      false,
   )?;
   let mut guard = FirewallGuard::new();
   firewall::verify(args.queue, args.dns_queue)?;

   read_connections(args)?;

   firewall::remove()?;
   guard.disarm();
   Ok(())
}

/// Reads the connection queue, printing and accepting every packet.
///
/// Only the connection queue is opened here. Queue 1 is left unbound on purpose: the DNS
/// reader thread arrives with the daemon loop, and the rules' `bypass` means the kernel
/// accepts DNS answers while no one is listening on that queue. Opening it without a
/// reader would instead *hold* DNS answers in the queue, which is the one thing a probe
/// on a live machine must not do.
fn read_connections(args: &Args) -> Result<(), ProbeError> {
   let mut conn = NfQueue::open(args.queue).map_err(|reason| ProbeError::Queue {
      queue: args.queue,
      reason,
   })?;
   info!(
      "opened NFQUEUE {} for new flows; awaiting packets",
      args.queue
   );

   let mut packets = Vec::new();
   let mut answered = 0u64;
   loop {
      let count = conn.recv(&mut packets).map_err(|reason| ProbeError::Queue {
         queue: args.queue,
         reason,
      })?;
      if count == 0 {
         // An ACK or other nfnetlink traffic: no packet owes a verdict.
         continue;
      }
      for packet in packets.drain(..) {
         info!("{}", packet_line(&packet));
         conn.verdict(packet.id, Verdict::Accept).map_err(|reason| ProbeError::Queue {
            queue: args.queue,
            reason,
         })?;
         answered += 1;
         if args.count.is_some_and(|limit| answered >= limit) {
            info!("reached --count {answered}; stopping");
            return Ok(());
         }
      }
   }
}

/// One transcript line for a queued packet: `pkt id=… fam=… … head=<hex>`.
fn packet_line(packet: &Packet) -> String {
   format!(
      "pkt id={} fam={} hook={} uid={} gid={} len={} outdev={} head={}",
      packet.id,
      family_label(packet.family),
      packet.hook,
      option(packet.uid),
      option(packet.gid),
      packet.payload.len(),
      option(packet.out_ifindex),
      hex_head(&packet.payload),
   )
}

/// The `family` byte as the transcript shows it: 2 is IPv4, 10 is IPv6.
///
/// Any other value is printed as its number rather than guessed into a family.
fn family_label(family: u8) -> String {
   match family {
      2 => "4".to_owned(),
      10 => "6".to_owned(),
      other => other.to_string(),
   }
}

fn option(value: Option<u32>) -> String {
   value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

/// The first 20 payload bytes as lowercase hex, as the transcript shows them.
fn hex_head(payload: &[u8]) -> String {
   payload.iter().take(20).map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
   use super::*;

   fn args(list: &[&str]) -> Result<Args, ArgError> {
      parse_args(list.iter().map(|arg| (*arg).to_owned()))
   }

   #[test]
   fn bare_invocation_is_usage() {
      assert_eq!(args(&[]).unwrap().mode, Mode::Usage);
   }

   #[test]
   fn probe_defaults_match_the_architecture() {
      let parsed = args(&["--probe"]).unwrap();
      assert_eq!(parsed.mode, Mode::Probe);
      assert_eq!((parsed.queue, parsed.dns_queue), (0, 1));
      assert!(!parsed.filter_loopback);
      assert_eq!(parsed.count, None);
   }

   #[test]
   fn probe_takes_every_documented_option() {
      let parsed = args(&[
         "--probe",
         "--queue",
         "7",
         "--dns-queue",
         "8",
         "--filter-loopback",
         "--count",
         "3",
      ])
      .unwrap();
      assert_eq!(parsed.queue, 7);
      assert_eq!(parsed.dns_queue, 8);
      assert!(parsed.filter_loopback);
      assert_eq!(parsed.count, Some(3));
   }

   #[test]
   fn help_and_version_stand_alone() {
      assert_eq!(args(&["--help"]).unwrap().mode, Mode::Help);
      assert_eq!(args(&["--version"]).unwrap().mode, Mode::Version);
   }

   #[test]
   fn bad_arguments_are_rejected() {
      assert!(matches!(
         args(&["--nope"]),
         Err(ArgError::UnknownOption(_))
      ));
      assert!(matches!(
         args(&["stray"]),
         Err(ArgError::UnexpectedPositional(_))
      ));
      assert!(matches!(
         args(&["--queue"]),
         Err(ArgError::MissingValue("--queue"))
      ));
      assert!(matches!(
         args(&["--probe", "--queue", "x"]),
         Err(ArgError::BadNumber { .. })
      ));
      assert!(matches!(
         args(&["--probe", "--queue", "70000"]),
         Err(ArgError::BadNumber { .. })
      ));
      assert!(matches!(
         args(&["--probe", "--count", "0"]),
         Err(ArgError::OutOfRange { .. })
      ));
   }

   #[test]
   fn packet_line_renders_the_transcript_format() {
      let packet = Packet {
         id: 42,
         family: 2,
         hook: 3,
         payload: (0..30u8).collect(),
         mark: None,
         uid: Some(1000),
         gid: None,
         out_ifindex: Some(2),
         hw_addr: None,
         timestamp: None,
      };
      assert_eq!(
         packet_line(&packet),
         "pkt id=42 fam=4 hook=3 uid=1000 gid=- len=30 outdev=2 \
          head=000102030405060708090a0b0c0d0e0f10111213"
      );

      let mut v6 = packet;
      v6.family = 10;
      v6.uid = None;
      v6.out_ifindex = None;
      let line = packet_line(&v6);
      assert!(line.starts_with("pkt id=42 fam=6 hook=3 uid=- gid=- len=30 outdev=- head="));
      assert!(
         !line.contains(" fam=10"),
         "IPv6 is rendered as family 6"
      );
   }

   #[test]
   fn unknown_family_is_printed_as_its_number() {
      assert_eq!(family_label(2), "4");
      assert_eq!(family_label(10), "6");
      assert_eq!(family_label(7), "7");
   }

   #[test]
   fn hex_head_is_bounded_for_short_and_empty_payloads() {
      assert_eq!(hex_head(&[]), "");
      assert_eq!(hex_head(&[0xde, 0xad]), "dead");
      let line = hex_head(&[0u8; 64]);
      assert_eq!(
         line.len(),
         40,
         "only the first 20 bytes are shown"
      );
   }
}
