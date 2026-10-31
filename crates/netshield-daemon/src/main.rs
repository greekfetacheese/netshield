//! `netshieldd`: the CLI, the daemon entry point, `--check`, and the `--probe` harness.
//!
//! A bare invocation runs the daemon; `--check` validates the machine without leaving the
//! table behind. The probe is deliberately small: install the table from ARCHITECTURE §2,
//! verify the kernel holds it, then read the connection queue and answer every packet with
//! `Accept` while printing what arrived. It exists so the orchestrator can watch a real
//! packet traverse nftables → nfnetlink → this process, on the real machine, without
//! guessing.

use std::path::PathBuf;
use std::process::ExitCode;

use log::{error, info};
use netshield_core::Config;
use netshield_core::config::LogLevel;
use netshield_daemon::daemon;
use netshield_daemon::firewall::{self, FirewallError};
use netshield_daemon::ipc_server;
use netshield_daemon::logging;
use netshield_daemon::netlink::nfqueue::{NfQueue, NfqError, Packet, Verdict};

const USAGE: &str = "\
netshieldd — NetShield's root firewall daemon

USAGE:
    netshieldd                     run the daemon
    netshieldd --check             validate the machine and exit
    netshieldd --probe [OPTIONS]   install the ruleset and prove packet interception
    netshieldd --help
    netshieldd --version

OPTIONS (daemon and --check):
    --config PATH        daemon configuration (default /etc/netshield/config.json)
    --rules PATH         rule database (default /etc/netshield/rules.db)
    --socket PATH        control socket (default from the configuration)

OPTIONS (--probe):
    --queue N            NFQUEUE number for new-flow connection packets (default 0)
    --dns-queue N        NFQUEUE number for DNS answer packets (default 1)
    --filter-loopback    also queue loopback traffic (off by default; ARCHITECTURE §2)
    --count N            exit after N connection packets (default: run until interrupted)

The daemon loads the rule store, adopts a verified table or installs one, then answers
every queued connection: a matching rule decides at once, an unmatched flow prompts until
the timeout denies it. SIGTERM/SIGINT remove the table and the socket.

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
   /// `--config`, or the documented default.
   config: PathBuf,
   /// `--rules`; `None` keeps the path the configuration names.
   rules: Option<PathBuf>,
   /// `--socket`; `None` keeps the path the configuration names.
   socket: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
   /// No arguments: run the daemon.
   Daemon,
   /// `--check`: validate the machine, then leave it as it was found.
   Check,
   Help,
   Version,
   Probe,
}

impl Default for Args {
   fn default() -> Self {
      Self {
         mode: Mode::Daemon,
         queue: 0,
         dns_queue: 1,
         filter_loopback: false,
         count: None,
         config: PathBuf::from("/etc/netshield/config.json"),
         rules: None,
         socket: None,
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
         "--check" => parsed.mode = Mode::Check,
         "--filter-loopback" => parsed.filter_loopback = true,
         "--config" => {
            let value = iter.next().ok_or(ArgError::MissingValue("--config"))?;
            parsed.config = PathBuf::from(value);
         }
         "--rules" => {
            let value = iter.next().ok_or(ArgError::MissingValue("--rules"))?;
            parsed.rules = Some(PathBuf::from(value));
         }
         "--socket" => {
            let value = iter.next().ok_or(ArgError::MissingValue("--socket"))?;
            parsed.socket = Some(PathBuf::from(value));
         }
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
   table: String,
   armed: bool,
}

impl FirewallGuard {
   /// Arms cleanup for the table that has just been installed.
   fn new(table: &str) -> Self {
      Self {
         table: table.to_owned(),
         armed: true,
      }
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
      match firewall::remove(&self.table) {
         Ok(()) => info!("removed table inet {}", self.table),
         Err(err) => error!(
            "could not remove table inet {} during cleanup: {err}",
            self.table
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

   // The logger has to be installed before anything can be logged, but every mode that
   // has a configuration installs it at the configured level: a daemon that only ever
   // logged at Info hid the debug-level DNS parse failure behind a setting it recorded
   // and never applied. `--help` and `--version` load no configuration and only print.
   let level = match args.mode {
      Mode::Help | Mode::Version => LogLevel::Info,
      Mode::Probe | Mode::Daemon | Mode::Check => config_level(&args.config),
   };
   logging::init(logging::level_filter(level));

   match args.mode {
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
      Mode::Daemon | Mode::Check => {
         if !is_root() {
            // Reuse the firewall's message verbatim: it is the same refusal the probe has
            // always produced, and it names the capability the caller is missing.
            eprintln!("netshieldd: {}", FirewallError::NotRoot);
            return ExitCode::FAILURE;
         }
         match load_and_run(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
               eprintln!("netshieldd: {err}");
               ExitCode::FAILURE
            }
         }
      }
   }
}

/// The configured verbosity, or the default when no configuration could be read.
///
/// A configuration that does not parse is reported by the mode itself, in the mode's own
/// error format; guessing a level here must not pre-empt that message.
fn config_level(path: &std::path::Path) -> LogLevel {
   Config::load(path).map(|config| config.log_level).unwrap_or_default()
}

/// Whether the process holds root, read from `/proc` so no raw syscall is needed here.
fn is_root() -> bool {
   ipc_server::effective_uid() == Some(0)
}

/// Applies the flags that override a configuration value.
///
/// `--filter-loopback` is a plain flag, so it cannot distinguish "not given" from "given false";
/// assigning it unconditionally would make the configuration key inert, which is what an earlier
/// version did.
fn apply_cli_overrides(config: &mut Config, args: &Args) {
   if args.filter_loopback {
      config.filter_loopback = true;
   }
}

/// Loads the configuration and dispatches to the daemon or to `--check`.
fn load_and_run(args: &Args) -> Result<(), String> {
   let mut config = Config::load(&args.config).map_err(|err| err.to_string())?;
   apply_cli_overrides(&mut config, args);
   let rules = args.rules.clone().unwrap_or_else(|| config.rules_path.clone());
   let socket = args.socket.clone().unwrap_or_else(|| config.socket_path.clone());

   match args.mode {
      Mode::Check => daemon::check(config, &rules).map_err(|err| err.to_string()),
      _ => daemon::run(config, &rules, &socket).map_err(|err| err.to_string()),
   }
}

/// The `--probe` flow: render, install, verify, then answer packets until `--count`.
///
/// The guard is armed only once the transaction succeeded, so a refused install (not
/// root, missing `nft`, an existing table) reports the original error and nothing else;
/// from then on every exit path — including a panic while reading packets — removes the
/// table.
fn probe(args: &Args) -> Result<(), ProbeError> {
   // The probe installs into the configured table, so it never collides with another
   // daemon's; a missing config file takes the default name, exactly as before.
   let table = Config::load(&args.config)
      .map_err(|err| FirewallError::Commands(err.to_string()))?
      .table_name()
      .to_owned();
   let ruleset = firewall::ruleset_text(
      &table,
      args.queue,
      args.dns_queue,
      args.filter_loopback,
   );
   info!("rendered ruleset:\n{ruleset}");

   firewall::install(
      &table,
      args.queue,
      args.dns_queue,
      args.filter_loopback,
      false,
   )?;
   let mut guard = FirewallGuard::new(&table);
   firewall::verify(&table, args.queue, args.dns_queue)?;

   read_connections(args)?;

   firewall::remove(&table)?;
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
   fn bare_invocation_runs_the_daemon() {
      assert_eq!(args(&[]).unwrap().mode, Mode::Daemon);
   }

   #[test]
   fn check_and_paths_are_parsed() {
      let parsed = args(&[
         "--check",
         "--config",
         "/tmp/config.json",
         "--rules",
         "/tmp/rules.db",
         "--socket",
         "/tmp/control.sock",
      ])
      .unwrap();
      assert_eq!(parsed.mode, Mode::Check);
      assert_eq!(parsed.config, PathBuf::from("/tmp/config.json"));
      assert_eq!(parsed.rules, Some(PathBuf::from("/tmp/rules.db")));
      assert_eq!(
         parsed.socket,
         Some(PathBuf::from("/tmp/control.sock"))
      );
   }

   #[test]
   fn daemon_paths_default_to_the_documented_locations() {
      let parsed = args(&[]).unwrap();
      assert_eq!(
         parsed.config,
         PathBuf::from("/etc/netshield/config.json")
      );
      assert_eq!(parsed.rules, None);
      assert_eq!(parsed.socket, None);
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

      // Bare `--probe` takes the architecture's defaults for every option above.
      let parsed = args(&["--probe"]).unwrap();
      assert_eq!(parsed.mode, Mode::Probe);
      assert_eq!((parsed.queue, parsed.dns_queue), (0, 1));
      assert!(!parsed.filter_loopback);
      assert_eq!(parsed.count, None);
   }

   #[test]
   fn the_loopback_flag_only_raises_the_configured_value() {
      let mut config = Config {
         filter_loopback: true,
         ..Config::default()
      };
      apply_cli_overrides(&mut config, &args(&[]).expect("defaults"));
      assert!(
         config.filter_loopback,
         "an absent flag must not clear the configured value"
      );

      let mut config = Config::default();
      apply_cli_overrides(
         &mut config,
         &args(&["--filter-loopback"]).expect("flag"),
      );
      assert!(config.filter_loopback, "a passed flag raises it");

      let mut config = Config::default();
      apply_cli_overrides(&mut config, &args(&[]).expect("defaults"));
      assert!(!config.filter_loopback, "the default stays off");
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
      assert!(matches!(
         args(&["--config"]),
         Err(ArgError::MissingValue("--config"))
      ));
      assert!(matches!(
         args(&["--rules"]),
         Err(ArgError::MissingValue("--rules"))
      ));
      assert!(matches!(
         args(&["--socket"]),
         Err(ArgError::MissingValue("--socket"))
      ));
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
