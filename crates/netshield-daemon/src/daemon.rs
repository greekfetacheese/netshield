//! The daemon loop: rule store, nftables table, NFQUEUE readers, prompts and control socket.
//!
//! Two entry points exist. [`check`] performs the root-only half — load the store, adopt or
//! install the table, verify it, open both queues — and then removes the table again, so an
//! operator can prove the machine is ready without leaving enforcement half-configured.
//! [`run`] is the daemon itself: it keeps both queues, sweeps prompt deadlines and grants,
//! drains the control socket and stays responsive to SIGTERM/SIGINT.
//!
//! The loop never blocks for longer than the queue receive timeout (200 ms). That timeout
//! is what lets one thread notice three unrelated things — a packet, a prompt deadline and
//! a signal — without an async runtime, timers or a second supervisor thread. The signal
//! handler is a single `extern "C" fn` that stores to an `AtomicBool`; everything else
//! (removing the table, deleting the socket) happens on the normal path once the flag is
//! seen, so a `systemctl stop` really does undo the enforcement.
//!
//! The DNS reader is the one thread whose failure mode is "never drop an answer": a parse
//! error, a malformed datagram or a cache miss all end in [`Verdict::Accept`], because a
//! dropped DNS answer looks like a broken network and is not something a firewall may do.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};
use netshield_core::config::{ClosedFlowAction, Config, IcmpAction, UnmatchedTransport};
use netshield_core::connection::{Attribution, Connection, Endpoint, L4Proto};
use netshield_core::dns::{DnsRecord, RecordKind, Target, parse_response, parse_tcp_response};
use netshield_core::dns_cache::DnsCache;
use netshield_core::ipc::{
   ConnectionEvent, ConnectionView, DecideRequest, Mode, PromptRequest, Request, Resolution,
   Response, ScopeChoice, StatusInfo,
};
use netshield_core::packet::{L4Payload, ParsedPacket, parse};
use netshield_core::rule::{Action, AppMatcher, Duration as RuleDuration, Rule, RuleId};
use netshield_core::{DestMatcher, Family, IpNet, ProcessInfo, ScopeRequest, rule_from_scope};

use crate::ebpf;
use crate::firewall::{self, FirewallError, Flow};
use crate::ipc_server::{self, IpcError, IpcHandle, IpcServer};
use crate::netlink::nfqueue::{NfQueue, NfqError, Packet, Verdict};
use crate::netlink::proc_connector::{ProcConnector, ProcEvent};
use crate::pending::{self, DestRemoval, Opened, PendingPrompts, PromptDest, PromptRecord};
use crate::policy::{Applied, Decision, Policy};
use crate::proc::{Attributor, FlowOwner, LiveFlow, Missing, ProcessCache, live_flows};
use crate::store::RuleStore;

/// How often the installed table is read back and re-verified.
///
/// A table can disappear or be rewritten by anything else on the machine (an operator, another
/// firewall manager), and a daemon that never looks again keeps deciding packets while nothing
/// enforces the verdicts. One `nft list` per 30 s is the price of noticing that; it never runs
/// per packet.
const TABLE_VERIFY_INTERVAL: Duration = Duration::from_secs(30);

/// Minimum gap between `prompt limit reached` lines.
///
/// One line per packet would turn the very flood the cap exists for into a journal flood; the
/// packet is still denied, only the line is rate-limited.
const PROMPT_LIMIT_LOG_GAP: Duration = Duration::from_secs(60);

/// How long a queue receive may block before the loop checks deadlines and signals.
const RECV_TIMEOUT: Duration = Duration::from_millis(200);

/// Minimum gap between `dns: no name` debug lines for one address.
const DNS_MISS_LOG_GAP: Duration = Duration::from_secs(1);

/// Minimum gap between denial lines for one unmodelled transport and ICMP type.
///
/// A ping flood or an SCTP association would otherwise put one line per packet in the
/// journal; the packet is still dropped, only the line is rate-limited.
const TRANSPORT_LOG_GAP: Duration = Duration::from_secs(60);

/// Upper bound on the transport keys the denial limiter remembers.
const TRANSPORT_LOG_LIMIT: usize = 256;

/// Upper bound on the addresses the DNS miss limiter remembers.
const DNS_MISS_LIMIT: usize = 1024;

/// Upper bound on the applications the multicast log line remembers.
///
/// A desktop session rarely has more than a few dozen applications talking to a multicast
/// destination; past the bound the line is skipped and the packet is still allowed.
const MAX_MULTICAST_APPS: usize = 64;

/// How many prompts may be open before a single warning reports the storm.
///
/// Only a warning: the set itself is bounded by [`pending::MAX_PROMPTS`], and nothing silently
/// denies a flow the user was never shown. A pathological burst is made visible instead,
/// because every one of those prompts now has its own clock.
const MAX_OPEN_PROMPTS: usize = 6;

/// How long the proc connector receive may block before the shutdown flag is checked.
///
/// Matches the packet loop's receive bound: a kernel without `CONFIG_PROC_EVENTS` must not
/// leave a thread that blocks forever on a descriptor the daemon cannot use.
const PROC_CONNECTOR_RECV_TIMEOUT: Duration = RECV_TIMEOUT;

/// Minimum gap between proc connector failure warnings, so a broken feed cannot flood the
/// journal while attribution quietly falls back to `/proc`.
const PROC_CONNECTOR_WARN_GAP: Duration = Duration::from_secs(60);

/// How long the firewall keeps rejecting a revoked flow's exact tuples.
///
/// The connection itself dies immediately: the first packet after the reject rule is
/// installed is reset. The window exists only so the same tuple cannot be silently
/// resurrected right away by the next in-flight packet, which would let the old socket
/// keep riding a verdict that has just been revoked. A fresh connection uses a new local
/// port, gets a new decision, and is unaffected.
const REVOKE_TIMEOUT_SECS: u64 = 60;

/// Which flows a decision change revokes.
#[derive(Debug, PartialEq, Eq)]
enum Revoke {
   Nothing,
   /// The flows held by processes running one executable — the same evidence the rule's own
   /// `AppMatcher::Exe` is matched against, never the uid, which every application of a
   /// desktop session shares.
   Exe(PathBuf),
   All,
   /// Every flow the policy does not allow. A flow an enabled rule allows keeps running: a mode
   /// change must not reset what a rule still permits, and a restart must not drop the connection
   /// of an application the owner already allowed.
   Mismatched {
      /// Also reset a flow the policy would now prompt for — true for a mode change (a flow
      /// silently allowed must not outlive the move to prompting) and false at startup (the flow
      /// was established before this daemon could decide it, and the app is asked again the next
      /// time it connects).
      kill_prompted: bool,
   },
}

/// What a rule change revokes.
///
/// A rule names an executable, so the flows to revoke are the ones held by processes running that
/// executable right now. The enumeration is the socket table's ([`live_flows`]), not the daemon's
/// attribution cache: a flow established while the daemon was not running was never attributed by
/// it, and a revocation that cannot see such a flow leaves the app holding the access the deleted
/// rule granted.
fn rule_revoke(rule: &Rule) -> Revoke {
   match &rule.app {
      AppMatcher::Exe(path) => Revoke::Exe(path.clone()),
      AppMatcher::Any => Revoke::All,
      // Unattributable flows have no executable to look them up by, and they are governed by
      // the closed-flow policy, so an `Unknown` rule has nothing it could revoke.
      AppMatcher::Unknown => Revoke::Nothing,
   }
}

/// What an upserted rule revokes.
///
/// A deny must reach running traffic, because a connection that survives the rule would keep
/// its old verdict for the life of the socket. An allow is not a revocation: it grants rather
/// than withdraws, so nothing running is reset.
fn upsert_revoke(rule: &Rule) -> Revoke {
   if rule.action == Action::Deny {
      rule_revoke(rule)
   } else {
      Revoke::Nothing
   }
}

/// Why the daemon or `--check` could not run.
#[derive(Debug)]
pub enum DaemonError {
   Firewall(FirewallError),
   Ipc(IpcError),
   Queue {
      queue: u16,
      reason: NfqError,
   },
   /// A background thread or a signal handler could not be installed.
   Thread(std::io::Error),
}

impl fmt::Display for DaemonError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Firewall(err) => write!(f, "{err}"),
         Self::Ipc(err) => write!(f, "{err}"),
         Self::Queue { queue, reason } => write!(f, "NFQUEUE {queue}: {reason}"),
         Self::Thread(err) => write!(f, "could not start a daemon thread: {err}"),
      }
   }
}

impl std::error::Error for DaemonError {}

impl From<FirewallError> for DaemonError {
   fn from(err: FirewallError) -> Self {
      Self::Firewall(err)
   }
}

impl From<IpcError> for DaemonError {
   fn from(err: IpcError) -> Self {
      Self::Ipc(err)
   }
}

/// The SIGTERM/SIGINT flag. Only a store, never a policy decision.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// `extern "C"` signal handler: storing to an `AtomicBool` is async-signal-safe, which is
/// the entire reason the handler does not remove the table itself.
extern "C" fn on_shutdown_signal(_signal: libc::c_int) {
   SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Installs the SIGTERM/SIGINT handlers.
fn install_signal_handlers() -> std::io::Result<()> {
   for signal in [libc::SIGTERM, libc::SIGINT] {
      let handler = on_shutdown_signal as *const () as libc::sighandler_t;
      // SAFETY: `on_shutdown_signal` is an `extern "C" fn(i32)` whose body only stores to
      // an atomic, so it is async-signal-safe; the pointer is a valid handler and the
      // signal number is one this process may install.
      let previous = unsafe { libc::signal(signal, handler) };
      if previous == libc::SIG_ERR {
         return Err(std::io::Error::last_os_error());
      }
   }
   Ok(())
}

/// Brings the nftables table up: adopt, replace or install, then verify it.
///
/// Returns whether [`firewall::verify`] confirmed the table at startup, which is what
/// [`StatusInfo::table_verified`] publishes. There is no state in which the table failed
/// the check: that is an error, not a status.
fn adopt_or_install(config: &Config) -> Result<bool, DaemonError> {
   // Verify is the only reliable existence check: it fails both when the table is absent
   // and when it exists but is not the table this configuration describes.
   let table = config.table_name();
   if firewall::verify(table, config.queue_num, config.dns_queue_num).is_ok() {
      info!(
         "adopting the installed table inet {table} (queues {}/{})",
         config.queue_num, config.dns_queue_num
      );
      return Ok(true);
   }

   info!("table inet {table} is absent or does not verify; installing it");
   firewall::install(
      table,
      config.queue_num,
      config.dns_queue_num,
      false,
      true,
   )?;
   firewall::verify(table, config.queue_num, config.dns_queue_num)?;
   Ok(true)
}

/// The warning emitted when a prompt is raised with no GUI attached.
///
/// The GUI is started by the session's XDG autostart entry; the daemon never spawns one,
/// because a root-owned GUI on the user's display would run with full privileges. A
/// prompt that nobody can answer therefore ends in the timeout denial, which the warning
/// states up front.
fn missing_client_warning(id: u64, app: &str, dest: &str, timeout_secs: u64) -> String {
   format!(
      "no GUI is connected; prompt {id} for {app} -> {dest} will be denied in {timeout_secs}s \
       unless a GUI attaches"
   )
}

/// The daemon's runtime state, owned by the main loop.
struct Daemon {
   config: Config,
   store: RuleStore,
   policy: Policy,
   pending: PendingPrompts,
   dns_cache: Arc<Mutex<DnsCache>>,
   attributor: Attributor,
   ipc: IpcHandle,
   queue: NfQueue,
   mode: Mode,
   started_at: u64,
   queue_drops: u64,
   silent_warned: bool,
   table_verified: bool,
   verify_schedule: VerifySchedule,
   dns_misses: MissLimiter,
   closed_flows: MissLimiter,
   prompt_limit: MissLimiter,
   transport_denials: KeyLimiter<(u8, Option<u8>)>,
   multicast_logged: HashSet<String>,
}

impl Daemon {
   /// Builds the daemon around the already-open connection queue.
   fn start(
      config: Config,
      store: RuleStore,
      ipc: IpcHandle,
      queue: NfQueue,
      dns_cache: Arc<Mutex<DnsCache>>,
      process_cache: Arc<Mutex<ProcessCache>>,
      table_verified: bool,
   ) -> Self {
      let policy = Policy::new(ruleset_from_store(&store), config.default_action);
      let started_at = now_secs();
      Self {
         config,
         store,
         policy,
         pending: PendingPrompts::new(),
         dns_cache,
         attributor: match ebpf::SendRegistry::open() {
            Ok(registry) => {
               Attributor::with_process_cache(process_cache).with_senders(Box::new(registry))
            }
            // `open` has already logged why; `/proc` attribution is what the daemon had before.
            Err(_) => Attributor::with_process_cache(process_cache),
         },
         ipc,
         queue,
         mode: Mode::Alert,
         started_at,
         queue_drops: 0,
         silent_warned: false,
         table_verified,
         verify_schedule: VerifySchedule::new(Instant::now(), TABLE_VERIFY_INTERVAL),
         dns_misses: MissLimiter::new(),
         closed_flows: MissLimiter::new(),
         prompt_limit: MissLimiter::with_gap(PROMPT_LIMIT_LOG_GAP),
         transport_denials: KeyLimiter::new(TRANSPORT_LOG_GAP, TRANSPORT_LOG_LIMIT),
         multicast_logged: HashSet::new(),
      }
   }

   fn publish_rules(&self) {
      let rules: Vec<Rule> = self.policy.ruleset().iter().cloned().collect();
      self.ipc.set_rules(&rules);
   }

   fn publish_status(&self) {
      self.ipc.set_status(self.status());
   }

   fn status(&self) -> StatusInfo {
      StatusInfo {
         daemon_pid: std::process::id(),
         mode: self.mode,
         rule_count: self.policy.ruleset().len(),
         pending_prompts: self.pending.len(),
         queue_num: self.config.queue_num,
         queue_drops: self.queue_drops,
         table_verified: self.table_verified,
         mutation_gated: self.config.gui_path.is_some(),
         started_at: self.started_at,
      }
   }

   /// Kills the flows a decision change just affected, so their owner has to reconnect.
   ///
   /// The next packet on a killed flow is rejected rather than queued, so the app sees a reset
   /// and opens a new connection, which the output chain queues and the policy decides again.
   /// `Nothing` revokes nothing: a rule that governs no live process, or one that was never an
   /// application rule, must not touch a running flow.
   fn revoke_flows(&mut self, who: Revoke, reason: &str) {
      let flows: Vec<Flow> = match who {
         Revoke::Nothing => return,
         Revoke::Exe(path) => {
            live_flows(FlowOwner::Exe(&path)).into_iter().map(|live| live.flow).collect()
         }
         Revoke::All => live_flows(FlowOwner::All).into_iter().map(|live| live.flow).collect(),
         Revoke::Mismatched { kill_prompted } => self.mismatched_flows(kill_prompted),
      };
      match firewall::kill_flows(
         self.config.table_name(),
         &flows,
         REVOKE_TIMEOUT_SECS,
      ) {
         Ok(count) => info!("revoked {count} flow(s): {reason}"),
         Err(err) => warn!("could not revoke the flows for {reason}: {err}"),
      }
   }

   /// The live flows the policy does not allow.
   ///
   /// Each flow is judged by [`Policy::decide`], the same decision a packet takes, so the rules and
   /// any live `Once` grant apply unchanged.
   fn mismatched_flows(&mut self, kill_prompted: bool) -> Vec<Flow> {
      let now = now_secs();
      let mut flows = Vec::new();
      for live in live_flows(FlowOwner::All) {
         let connection = self.socket_connection(&live);
         let decision = self.policy.decide(&connection, now);
         if revokes(&decision, kill_prompted) {
            flows.push(live.flow);
         }
      }
      flows
   }

   /// A [`Connection`] for a socket the socket table already described.
   ///
   /// This is the connection the packet path builds, from the same facts: the holder's identity (a
   /// rule is matched on `exe`), the endpoints, the protocol and the name the DNS cache learned for
   /// the address.
   fn socket_connection(&mut self, live: &LiveFlow) -> Connection {
      let (local, remote) = match &live.flow {
         Flow::V4(from, from_port, to, to_port) => (
            Endpoint {
               addr: IpAddr::V4(*from),
               port: *from_port,
            },
            Endpoint {
               addr: IpAddr::V4(*to),
               port: *to_port,
            },
         ),
         Flow::V6(from, from_port, to, to_port) => (
            Endpoint {
               addr: IpAddr::V6(*from),
               port: *from_port,
            },
            Endpoint {
               addr: IpAddr::V6(*to),
               port: *to_port,
            },
         ),
      };
      let (domain, also_domains) = self.domain_names(remote.addr);
      Connection {
         family: match live.flow {
            Flow::V4(..) => Family::V4,
            Flow::V6(..) => Family::V6,
         },
         proto: live.proto,
         local,
         remote,
         process: Attribution::Process(ProcessInfo {
            pid: live.pid,
            uid: live.identity.uid,
            exe: live.identity.exe.clone(),
            comm: Some(live.identity.comm.clone()).filter(|comm| !comm.is_empty()),
            cmdline: None,
         }),
         domain,
         also_domains,
      }
   }
}

/// One prompt a new rule already decides, ready to be answered.
struct SweptPrompt {
   /// The settled prompt. Only the destinations the rule decided are left in `dests`; a
   /// group keeps the destinations that still need the user, with the same prompt id.
   record: PromptRecord,
   verdict: Verdict,
   resolution: Resolution,
}

/// Whether a connection decided by policy allows or denies it, or still needs the user.
fn decided(decision: &Decision) -> Option<(Verdict, Resolution)> {
   match decision {
      Decision::Allow { .. } => Some((Verdict::Accept, Resolution::Allowed)),
      Decision::Deny { .. } => Some((Verdict::Drop, Resolution::Denied)),
      Decision::Prompt => None,
   }
}

/// Whether a decision change must reset a flow the policy just judged.
fn revokes(decision: &Decision, kill_prompted: bool) -> bool {
   match decision {
      Decision::Deny { .. } => true,
      Decision::Prompt => kill_prompted,
      Decision::Allow { .. } => false,
   }
}

/// The destinations of one prompt that the policy already decides, and what their removal
/// left of the prompt.
struct SweptDests {
   dests: Vec<PromptDest>,
   verdict: Verdict,
   resolution: Resolution,
   removal: DestRemoval,
}

/// Splits the destinations of a prompt the policy already decides from the ones still
/// waiting on the user.
///
/// One prompt can list several destinations and a rule may cover only some of them: the
/// covered destinations are answered by the sweep, the rest stay on the prompt the user
/// sees, so a decision on a group never answers a destination the click did not cover.
fn sweep_dests(
   pending: &mut PendingPrompts,
   policy: &mut Policy,
   id: u64,
   now: u64,
) -> Option<SweptDests> {
   let record = pending.get(id)?;
   let mut flows = Vec::new();
   let mut verdict = None;
   for dest in &record.dests {
      let Some((covered, resolution)) = decided(&policy.decide(&dest.connection, now)) else {
         continue;
      };
      if verdict.is_some_and(|(held, _)| held != covered) {
         // One verdict cannot drop some destinations and accept others; leave the whole
         // prompt to the user rather than answering half of it with the wrong verdict.
         return None;
      }
      verdict = Some((covered, resolution));
      flows.push(dest.connection.flow_key());
   }
   let (verdict, resolution) = verdict?;
   let taken = pending.take_dests(id, &flows)?;
   Some(SweptDests {
      dests: taken.dests,
      verdict,
      resolution,
      removal: taken.outcome,
   })
}

/// The prompts a sweep settled, and the open prompts it shrank.
struct PromptSweep {
   /// The settled prompts in arrival order, with only the destinations the rule decided.
   swept: Vec<SweptPrompt>,
   /// Open prompts that lost destinations to the sweep, so the clients' list is refreshed
   /// with the smaller group.
   updated: Vec<PromptRecord>,
}

/// Removes every destination the policy already decides from every open prompt.
///
/// The prompts are visited in arrival order, so the oldest is settled first. Every prompt is
/// live from the moment it is opened, so a sweep no longer has to walk a queue or announce a
/// successor: each record it touched is either closed or refreshed by the caller, and the
/// records it could not decide stay exactly as they are. A record a previous iteration
/// removed is skipped by [`sweep_dests`] returning `None`.
///
/// Split from [`Daemon::sweep_decided_prompts`] so the prompt and rule interaction is
/// unit-tested without a root-owned netlink queue to answer packets on. The caller owns the
/// side effects: the packet verdicts, the broadcast and the log line, in that order.
fn sweep_decided(pending: &mut PendingPrompts, policy: &mut Policy, now: u64) -> PromptSweep {
   let mut swept = Vec::new();
   let mut updated = Vec::new();
   for record in pending.queued_records() {
      let Some(swept_dests) = sweep_dests(pending, policy, record.id, now) else {
         continue;
      };
      match swept_dests.removal {
         DestRemoval::Resolved(resolved) => {
            swept.push(SweptPrompt {
               record: resolved.record.with_dests(swept_dests.dests),
               verdict: swept_dests.verdict,
               resolution: swept_dests.resolution,
            });
         }
         DestRemoval::Remaining(_) => {
            // A destination the policy does not decide keeps the group — and its prompt —
            // alive and on screen, so the clients are sent the smaller list.
            if let Some(remaining) = pending.get(record.id) {
               updated.push(remaining.clone());
            }
            swept.push(SweptPrompt {
               record: record.with_dests(swept_dests.dests),
               verdict: swept_dests.verdict,
               resolution: swept_dests.resolution,
            });
         }
      }
   }
   PromptSweep { swept, updated }
}

/// A rule set view of the store, in insertion order so the tie-break is preserved.
fn ruleset_from_store(store: &RuleStore) -> netshield_core::RuleSet {
   let mut set = netshield_core::RuleSet::new();
   for rule in store.rules() {
      set.upsert(rule.clone());
   }
   set
}

/// Seconds since the Unix epoch, or 0 when the clock is before it.
fn now_secs() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs())
}

/// Runs the daemon until SIGTERM/SIGINT.
pub fn run(config: Config, rules_path: &Path, socket_path: &Path) -> Result<(), DaemonError> {
   let config = Config {
      rules_path: rules_path.to_path_buf(),
      socket_path: socket_path.to_path_buf(),
      ..config
   };

   // Handlers first: a SIGTERM during startup must not leave a table behind, so the flag
   // is installed before anything can be installed.
   SHUTDOWN.store(false, Ordering::SeqCst);
   install_signal_handlers().map_err(DaemonError::Thread)?;

   let (store, _seeded) = RuleStore::load_or_seed(&config.rules_path);
   info!(
      "loaded {} rule(s) from {}",
      store.rules().len(),
      config.rules_path.display()
   );
   let table_verified = adopt_or_install(&config)?;

   let (ipc, queue, dns_queue) = match start_runtime(&config) {
      Ok(started) => started,
      Err(err) => {
         remove_table_quietly(config.table_name());
         if let Err(remove_err) = ipc_server::remove_socket_file(&config.socket_path) {
            warn!("could not remove the control socket after a startup failure: {remove_err}");
         }
         return Err(err);
      }
   };

   let cache = Arc::new(Mutex::new(DnsCache::new()));
   if let Err(err) = spawn_dns_reader(
      dns_queue,
      Arc::clone(&cache),
      config.dns_queue_num,
   ) {
      remove_table_quietly(config.table_name());
      if let Err(remove_err) = ipc_server::remove_socket_file(&config.socket_path) {
         warn!("could not remove the control socket at startup failure: {remove_err}");
      }
      return Err(err);
   }

   let process_cache = Arc::new(Mutex::new(ProcessCache::new()));
   spawn_proc_connector(Arc::clone(&process_cache));

   let mut daemon = Daemon::start(
      config,
      store,
      ipc,
      queue,
      cache,
      process_cache,
      table_verified,
   );
   daemon.publish_rules();
   daemon.publish_status();
   // Before any packet is served: every live flow on the machine was established while the daemon
   // was not running and was never checked by it, so a denied flow must not outlive the restart. The
   // table is already installed, without which the kill would have nothing to reject against. The
   // flows the policy allows or would only prompt for are left alone: a restart must not drop the
   // connection of an application the owner already allowed.
   daemon.revoke_flows(
      Revoke::Mismatched {
         kill_prompted: false,
      },
      "the daemon started",
   );
   info!(
      "netshieldd running: queue {} for flows, queue {} for DNS, control {}",
      daemon.config.queue_num,
      daemon.config.dns_queue_num,
      daemon.config.socket_path.display()
   );

   daemon.tick_loop();

   let socket_path = daemon.config.socket_path.clone();
   let table = daemon.config.table_name();
   if let Err(err) = firewall::remove(table) {
      error!("could not remove table inet {table} at shutdown: {err}");
   } else {
      info!("removed table inet {table} at shutdown");
   }
   if let Err(err) = ipc_server::remove_socket_file(&socket_path) {
      warn!("could not remove the control socket {socket_path:?}: {err}");
   } else {
      info!(
         "removed the control socket {}",
         socket_path.display()
      );
   }
   Ok(())
}

/// Binds the control socket and opens both queues with the loop's receive timeout.
fn start_runtime(config: &Config) -> Result<(IpcHandle, NfQueue, NfQueue), DaemonError> {
   let server = IpcServer::bind(
      &config.socket_path,
      config.allowed_uid,
      config.gui_path.clone(),
   )?;
   let ipc = server.spawn();

   let queue = open_queue(config.queue_num)?;
   let dns_queue = open_queue(config.dns_queue_num)?;
   Ok((ipc, queue, dns_queue))
}

/// Opens one queue and bounds its receive, so the main loop stays responsive.
fn open_queue(queue: u16) -> Result<NfQueue, DaemonError> {
   let handle = NfQueue::open(queue).map_err(|reason| DaemonError::Queue { queue, reason })?;
   handle.set_recv_timeout(RECV_TIMEOUT).map_err(|reason| DaemonError::Queue {
      queue,
      reason: NfqError::Io(reason),
   })?;
   Ok(handle)
}

/// Removes the table without turning a startup failure into a cleanup failure.
fn remove_table_quietly(table: &str) {
   if let Err(err) = firewall::remove(table) {
      error!("could not roll back table inet {table} after a startup failure: {err}");
   }
}

impl Daemon {
   /// The main loop: one iteration per receive timeout at most.
   ///
   /// A failed receive is logged and counted rather than fatal: taking the daemon down
   /// because one datagram was malformed would turn a bad packet into an outage.
   fn tick_loop(&mut self) {
      let mut packets = Vec::new();
      loop {
         if SHUTDOWN.load(Ordering::SeqCst) {
            info!("shutdown signal received; stopping");
            let stats = self.attributor.stats();
            info!(
               "attribution: the send registry named a sender for {} flows without changing the \
                verdict ({} misses, {} refused), {} scans still found nothing",
               stats.registry_hits, stats.registry_misses, stats.registry_refusals, stats.misses
            );
            return;
         }

         self.drain_ipc();
         self.apply_mode();

         match self.queue.recv(&mut packets) {
            Ok(0) => {}
            Ok(_) => {
               let received = std::mem::take(&mut packets);
               for packet in received {
                  self.handle_packet(packet);
               }
               self.publish_status();
            }
            Err(NfqError::Io(err)) if would_block(&err) => {}
            Err(err) => {
               warn!(
                  "NFQUEUE {} receive failed: {err}",
                  self.config.queue_num
               );
               self.queue_drops = self.queue_drops.saturating_add(1);
            }
         }

         let now = Instant::now();
         self.sweep(now);
         self.verify_table(now);
      }
   }

   /// Reads the installed table back on the schedule and publishes whether it still verifies.
   ///
   /// A table removed or rewritten by anything else would otherwise leave the daemon logging
   /// decisions while nothing enforces them. The failure is logged once per transition, never
   /// once per interval, and `StatusInfo::table_verified` carries the current state; the next
   /// success restores it and says so once.
   fn verify_table(&mut self, now: Instant) {
      if !self.verify_schedule.due(now) {
         return;
      }
      match firewall::verify(
         self.config.table_name(),
         self.config.queue_num,
         self.config.dns_queue_num,
      ) {
         Ok(()) => {
            if !self.table_verified {
               self.table_verified = true;
               info!(
                  "table inet {} verifies again; enforcement resumed",
                  self.config.table_name()
               );
               self.publish_status();
            }
         }
         Err(err) => {
            if self.table_verified {
               self.table_verified = false;
               error!(
                  "table inet {} no longer verifies, so nothing is enforced until it does: \
                   {err}",
                  self.config.table_name()
               );
               self.publish_status();
            }
         }
      }
   }

   /// Answers whatever the control socket queued since the last iteration.
   fn drain_ipc(&mut self) {
      while let Some((client, request)) = self.ipc.try_recv() {
         self.handle_request(client, request);
      }
   }

   /// Applies a mode change the control server already published in its snapshot.
   fn apply_mode(&mut self) {
      let requested = self.ipc.mode();
      if requested == self.mode {
         return;
      }
      self.mode = requested;
      // Either direction between silent and alert is a decision change for every live flow on the
      // machine, so the denied ones and the ones the policy would now prompt for are reset and the
      // apps reconnect into the mode now in effect. This is the point of the switch: a flow silently
      // allowed must not outlive the move to prompting, and one allowed under a prompt must not keep
      // running unanswered if the mode goes silent. What a rule still allows keeps running. It runs
      // once per change, not per flow.
      self.revoke_flows(
         Revoke::Mismatched {
            kill_prompted: true,
         },
         "the mode changed",
      );
      match self.mode {
         Mode::Silent => {
            if !self.silent_warned {
               self.silent_warned = true;
               warn!("silent mode: unmatched connections are now allowed without prompting");
            }
            // Prompts already on screen are answered by the mode switch rather than left
            // to time out and deny a connection the user has just stopped being asked
            // about. `take_all` also empties the set, so a silent switch has nothing left
            // for a policy sweep; every open prompt gets `SilentAutoAllowed` right here.
            for record in self.pending.take_all() {
               for dest in &record.dests {
                  if let Err(err) = self.answer_packets(&dest.packet_ids, Verdict::Accept) {
                     warn!(
                        "could not release prompt {}'s packets: {err}",
                        record.id
                     );
                  }
               }
               self.ipc.broadcast(&Response::PromptClosed {
                  id: record.id,
                  resolution: Resolution::SilentAutoAllowed,
               });
               for dest in &record.dests {
                  self.broadcast_connection(&dest.connection, Action::Allow, None, true);
               }
            }
         }
         Mode::Alert => info!("alert mode: unmatched connections prompt again"),
      }
      self.publish_status();
   }

   /// Handles one control request that reached the daemon loop.
   fn handle_request(&mut self, client: u64, request: Request) {
      match request {
         Request::Decide(decide) => self.decide(client, decide),
         Request::UpsertRule { rule } => {
            let mut rule = rule;
            rule.updated_at = now_secs();
            // The rule's app has to be read before the change, and only a deny revokes.
            let revoke = upsert_revoke(&rule);
            self.policy.upsert_rule(rule.clone());
            if let Err(err) = self.store.upsert(rule) {
               error!("could not persist a rule from the control socket: {err}");
            }
            self.publish_rules();
            self.revoke_flows(revoke, "a deny rule was upserted");
            self.sweep_decided_prompts();
            self.publish_status();
         }
         Request::DeleteRule { id } => {
            // Copied first: removing it from the policy forgets which app it governed, and that
            // app is exactly what the revocation needs.
            let rule = self.policy.ruleset().get(&id).cloned();
            match self.store.remove(&id) {
               Ok(true) => info!("deleted rule {}", id),
               Ok(false) => debug!("delete for unknown rule {}", id),
               Err(err) => error!("could not persist the deletion of rule {id}: {err}"),
            }
            self.policy.remove_rule(&id);
            self.publish_rules();
            if let Some(rule) = rule {
               let revoke = rule_revoke(&rule);
               self.revoke_flows(revoke, "a rule was deleted");
            }
            self.publish_status();
         }
         Request::SetRuleEnabled { id, enabled } => {
            if let Some(mut rule) = self.policy.ruleset().get(&id).cloned() {
               rule.enabled = enabled;
               rule.updated_at = now_secs();
               self.policy.upsert_rule(rule.clone());
               if let Err(err) = self.store.upsert(rule.clone()) {
                  error!("could not persist a rule toggle from the control socket: {err}");
               }
               self.publish_rules();
               // Disabling withdraws a decision; enabling only widens what is allowed, so it is
               // not a revocation and must not reset a running flow.
               if !enabled {
                  let revoke = rule_revoke(&rule);
                  self.revoke_flows(revoke, "a rule was disabled");
               }
               self.publish_status();
            } else {
               debug!("toggle for unknown rule {id}");
            }
         }
         other => {
            debug!("control client {client} sent a request with no daemon-side handler: {other:?}")
         }
      }
   }

   /// Answers one prompt.
   ///
   /// The answer covers exactly the destinations the prompt listed. `Once` grants each of
   /// them once; a timed answer creates the rules [`rules_for`] derives from the requested
   /// scope, which is the user's choice and never a consequence of how many destinations
   /// the prompt listed. A rule equivalent to one already present is refreshed instead of
   /// added a second time.
   fn decide(&mut self, _client: u64, decide: DecideRequest) {
      let Some(record) = self.pending.get(decide.prompt_id).cloned() else {
         // A GUI click can arrive after the prompt expired; the user believes a rule was
         // created, so the discarded choice must be visible at the operator's log level.
         warn!(
            "prompt {} is no longer open; discarding the decision and creating no rule",
            decide.prompt_id
         );
         return;
      };

      let verdict = match decide.action {
         Action::Allow => Verdict::Accept,
         Action::Deny => Verdict::Drop,
      };
      let packets: Vec<u32> = record.packet_ids().collect();
      if let Err(err) = self.answer_packets(&packets, verdict) {
         warn!(
            "could not answer prompt {}'s packets: {err}",
            record.id
         );
      }

      // The rule is in place before the prompt is resolved, because the prompts opened
      // alongside it must already be judged by the rule the user just created. The answered
      // prompt is settled here with the user's own verdict, so an older rule cannot override
      // an explicit answer.
      let now = now_secs();
      let app = record.app_name();
      let dest = match record.dests.as_slice() {
         [dest] => dest_label(&dest.connection),
         dests => format!("{} destinations", dests.len()),
      };
      let Some(first) = record.first() else {
         // A prompt is never empty; answering nothing creates no rule either.
         warn!(
            "prompt {} has no destination; discarding the decision",
            record.id
         );
         return;
      };
      let app_kind = match &first.connection.process {
         Attribution::Process(process) if process.exe.is_some() => "exe",
         Attribution::Unknown => "unknown",
         Attribution::Process(_) => "any",
      };
      let rule_dest = match &decide.scope {
         ScopeChoice::AnyConnection => "any".to_owned(),
         ScopeChoice::Domain {
            host,
            subdomains: true,
         } => format!("{host} (+subdomains)"),
         ScopeChoice::Domain { host, .. } => host.clone(),
         ScopeChoice::Address => first.connection.remote.addr.to_string(),
         ScopeChoice::TheseDestinations => format!("{} destinations", record.dests.len()),
      };
      let (mechanism, created, updated) = match decide.duration {
         RuleDuration::Once => {
            for dest in &record.dests {
               self.policy.grant(
                  dest.connection.flow_key(),
                  decide.action,
                  now.saturating_add(crate::policy::GRANT_TTL_SECS),
               );
            }
            (
               format!("created a once flow grant for {app}"),
               0, // a grant is not a rule
               0,
            )
         }
         RuleDuration::Session => {
            let (created, updated) = self.apply_rules(&record, &decide, now);
            self.publish_rules();
            (
               format!("created an in-memory {app_kind} rule for {app}"),
               created,
               updated,
            )
         }
         RuleDuration::Forever => {
            let (created, updated) = self.apply_rules(&record, &decide, now);
            self.publish_rules();
            (
               format!("created and persisted a forever {app_kind} rule for {app}"),
               created,
               updated,
            )
         }
      };
      let scope = scope_label(&decide.scope);
      let line = decision_line(record.id, &app, &dest, &decide, &scope);
      info!("{line}");
      info!(
         "answer for prompt {}: {created} rules created, {updated} refreshed",
         record.id
      );

      let Some(resolved) = self.pending.resolve(record.id) else {
         // A `None` here means the prompt was already settled; answering its packets twice
         // would be a double verdict.
         warn!(
            "prompt {} was settled while its decision was applied; not broadcasting it again",
            record.id
         );
         self.publish_status();
         return;
      };
      let resolution = match decide.action {
         Action::Allow => Resolution::Allowed,
         Action::Deny => Resolution::Denied,
      };
      self.ipc.broadcast(&Response::PromptClosed {
         id: resolved.record.id,
         resolution,
      });
      for dest in &record.dests {
         self.broadcast_connection(&dest.connection, decide.action, None, true);
      }

      // Another flow from the same app, or from an app the new rule covers, may already have
      // its own open prompt; the new rule already decides it, so the sweep settles every
      // prompt it can and refreshes the ones it shrank. The answered prompt is already
      // resolved, so it can never be swept here.
      let swept = self.sweep_decided_prompts();
      debug!(
         "prompt {}: {} (dest {}); {} open prompt(s) swept",
         record.id, mechanism, rule_dest, swept
      );
      self.publish_status();
   }

   /// Applies the rules a prompt's answer implies, refreshing equivalents instead of
   /// duplicating them, and persists each rule whose duration is `Forever`.
   ///
   /// Returns how many rules were created and how many already-present rules were
   /// refreshed, so the decision log can say which happened.
   fn apply_rules(
      &mut self,
      record: &PromptRecord,
      decide: &DecideRequest,
      now: u64,
   ) -> (usize, usize) {
      let mut created = 0;
      let mut updated = 0;
      let mut forever = Vec::new();
      for rule in rules_for(record, decide, now) {
         // Read before the move: `policy.apply` takes the rule by value.
         let persist = rule.duration == RuleDuration::Forever;
         let (rule, applied) = self.policy.apply(rule);
         match applied {
            Applied::Created => created += 1,
            Applied::Refreshed => updated += 1,
         }
         if persist {
            forever.push(rule);
         }
      }
      // One answer can create a rule per destination; one transaction instead of one commit each.
      if !forever.is_empty()
         && let Err(err) = self.store.upsert_many(&forever)
      {
         error!(
            "could not persist {} forever rule(s): {err}",
            forever.len()
         );
      }
      (created, updated)
   }

   /// Answers the open prompts that the current policy already decides, so the user is not
   /// asked about a flow a rule they just created covers.
   ///
   /// Every prompt is live from the moment it is opened, so this sweep visits all of them in
   /// arrival order and needs no head loop: a prompt the policy decides is answered, one it
   /// partly decides is refreshed with the destinations still waiting.
   fn sweep_decided_prompts(&mut self) -> usize {
      let PromptSweep { swept, updated } =
         sweep_decided(&mut self.pending, &mut self.policy, now_secs());
      let count = swept.len();
      for swept in swept {
         self.settle_swept(swept);
      }
      for record in updated {
         self.update_prompt(&record);
      }
      count
   }

   /// Answers a swept prompt's packets, closes it for the clients and logs why it was not
   /// shown.
   ///
   /// `record.dests` holds only the destinations this sweep decided. When the prompt was a
   /// group the policy covered in full, the whole prompt is closed; a group that kept a
   /// destination stays open under the same id and is refreshed by [`Daemon::update_prompt`].
   fn settle_swept(&mut self, swept: SweptPrompt) {
      let packets: Vec<u32> = swept.record.packet_ids().collect();
      if let Err(err) = self.answer_packets(&packets, swept.verdict) {
         warn!(
            "could not answer swept prompt {}'s packets: {err}",
            swept.record.id
         );
      }
      let action = match swept.verdict {
         Verdict::Accept => "allow",
         Verdict::Drop => "deny",
      };
      debug!(
         "prompt {} for {} resolved by policy as {action}; {} destination(s) not shown",
         swept.record.id,
         swept.record.app_name(),
         swept.record.dests.len()
      );
      if self.pending.get(swept.record.id).is_none() {
         self.ipc.broadcast(&Response::PromptClosed {
            id: swept.record.id,
            resolution: swept.resolution,
         });
      }
   }

   /// The wire request for `record`: every destination its answer covers, plus the count of
   /// other prompts open right now.
   fn prompt_request(&self, record: &PromptRecord) -> Option<PromptRequest> {
      Some(PromptRequest {
         id: record.id,
         connection: self.view(&record.first()?.connection),
         dests: self.views(record),
         timeout_secs: self.config.prompt_timeout_secs,
         domain_scope_available: record.dests.iter().any(|dest| dest.connection.domain.is_some()),
         pending: self.pending.others_open(record.id),
      })
   }

   /// Makes a prompt visible: broadcasts it with the number of other prompts open alongside
   /// it, and repeats the timeout warning when no client is attached.
   fn announce_prompt(&mut self, record: &PromptRecord) {
      let Some(request) = self.prompt_request(record) else {
         warn!(
            "prompt {} has no destination; not broadcasting it",
            record.id
         );
         return;
      };
      let timeout_secs = request.timeout_secs;
      let pending = request.pending;
      let open = self.pending.len();
      self.ipc.broadcast(&Response::Prompt(request));
      let packets: usize = record.dests.iter().map(|dest| dest.packet_ids.len()).sum();
      match record.dests.as_slice() {
         [dest] => info!(
            "prompt {} for {} -> {}:{} ({} packet(s) held, {} open)",
            record.id,
            dest.connection.app_name(),
            dest.connection.remote.addr,
            dest.connection.remote.port,
            packets,
            pending
         ),
         dests => info!(
            "prompt {} for {} -> {} destinations ({} packet(s) held, {} open)",
            record.id,
            record.app_name(),
            dests.len(),
            packets,
            pending
         ),
      }
      // A prompt storm is not capped, because a cap would silently deny a flow the user was
      // never shown; it is made visible instead, once per prompt that crosses the line.
      if open > MAX_OPEN_PROMPTS {
         warn!("{open} prompts open at once");
      }

      if !self.ipc.is_subscribed() {
         let dest = record.first().map_or_else(
            || "?".to_owned(),
            |dest| {
               format!(
                  "{}:{}",
                  dest.connection.remote.addr, dest.connection.remote.port
               )
            },
         );
         warn!(
            "{}",
            missing_client_warning(record.id, &record.app_name(), &dest, timeout_secs,)
         );
      }
   }

   /// Re-broadcasts a prompt the sweep shrank, so the clients list only the destinations
   /// that still need an answer. The prompt id and its deadline stand.
   fn update_prompt(&mut self, record: &PromptRecord) {
      let Some(request) = self.prompt_request(record) else {
         warn!(
            "prompt {} has no destination; not broadcasting it",
            record.id
         );
         return;
      };
      let pending = request.pending;
      self.ipc.broadcast(&Response::Prompt(request));
      info!(
         "prompt {} for {} -> {} destinations after a policy sweep ({} still open)",
         record.id,
         record.app_name(),
         record.dests.len(),
         pending
      );
   }

   /// Every destination of a prompt as a client displays it, in arrival order.
   fn views(&self, record: &PromptRecord) -> Vec<ConnectionView> {
      record.dests.iter().map(|dest| self.view(&dest.connection)).collect()
   }

   /// Answers every packet id of a prompt in one pass.
   fn answer_packets(&mut self, ids: &[u32], verdict: Verdict) -> Result<(), NfqError> {
      // One failed verdict must not leave the rest of the prompt's packet ids unanswered:
      // those ids are held by the kernel and would block the flow until the queue is torn
      // down.
      let mut failure = None;
      for id in ids {
         if let Err(err) = self.queue.verdict(*id, verdict)
            && failure.is_none()
         {
            failure = Some(err);
         }
      }
      match failure {
         Some(err) => Err(err),
         None => Ok(()),
      }
   }

   /// Handles one queued connection packet.
   fn handle_packet(&mut self, packet: Packet) {
      let parsed = match parse(&packet.payload) {
         Ok(parsed) => parsed,
         Err(err) => {
            warn!(
               "dropping packet id={} that could not be parsed: {err:?}",
               packet.id
            );
            if let Err(verdict_err) = self.queue.verdict(packet.id, Verdict::Drop) {
               warn!(
                  "could not drop packet id={}: {verdict_err}",
                  packet.id
               );
            }
            return;
         }
      };

      let Some((connection, missing)) = self.connection_for(&parsed, &packet) else {
         self.handle_unmodelled(&parsed, &packet);
         return;
      };

      let (allow, rule) = match self.policy.decide(&connection, now_secs()) {
         Decision::Allow { rule } => (Some(true), rule),
         Decision::Deny { rule } => (Some(false), rule),
         Decision::Prompt => (None, None),
      };

      match allow {
         Some(true) => {
            if let Some(id) = &rule {
               self.policy.record_hit(id, now_secs());
            }
            self.accept(packet.id);
            self.broadcast_connection(&connection, Action::Allow, rule, false);
         }
         Some(false) => {
            if let Some(id) = &rule {
               self.policy.record_hit(id, now_secs());
            }
            self.drop_packet(packet.id);
            self.broadcast_connection(&connection, Action::Deny, rule, false);
         }
         None => match unmatched(&connection, missing, &self.config, self.mode) {
            Unmatched::Prompt => self.prompt(&connection, packet.id),
            Unmatched::DropClosed => self.closed_flow_dropped(&connection, packet.id),
            Unmatched::AllowClosed => self.closed_flow_allowed(&connection, packet.id),
            Unmatched::AllowMulticast => self.multicast_allowed(&connection, packet.id),
         },
      }
   }

   /// Decides a queued packet the policy model cannot express a flow for.
   ///
   /// [`connection_for`](Self::connection_for) returns `None` for three unrelated reasons and
   /// they must not share a verdict: an established TCP packet is not a policy question, a
   /// transport without ports (and an ICMP echo) has no rule that could govern it, and a
   /// family mismatch is a packet the model reads but cannot place. Only the middle case is
   /// an accept the owner asked to close; the other two keep the historical accept.
   fn handle_unmodelled(&mut self, parsed: &ParsedPacket, packet: &Packet) {
      // The protocol number the kernel put on the wire. `L4Payload` carries no protocol
      // field, so it is read from the IP header the parser already validated.
      let protocol = packet_protocol(&packet.payload);
      match transport_verdict(&parsed.l4, &self.config) {
         TransportAction::Ignore => {
            // Not a flow the policy governs (an established TCP segment, a family
            // mismatch, or a packet whose header no longer carries a protocol). Accept
            // rather than invent a decision for a packet the model cannot express.
            self.accept(packet.id);
         }
         TransportAction::Drop => {
            self.drop_packet(packet.id);
            self.queue_drops = self.queue_drops.saturating_add(1);
            self.log_transport_denial(parsed, protocol, packet.uid);
         }
         TransportAction::Allow => self.accept(packet.id),
      }
   }

   /// Logs a transport denial once per (protocol, ICMP type) per [`TRANSPORT_LOG_GAP`].
   fn log_transport_denial(
      &mut self,
      parsed: &ParsedPacket,
      protocol: Option<u8>,
      uid: Option<u32>,
   ) {
      let key = (
         protocol.unwrap_or(0),
         match parsed.l4 {
            L4Payload::Icmp { icmp_type, .. } => Some(icmp_type),
            _ => None,
         },
      );
      if !self.transport_denials.record(key, Instant::now()) {
         return;
      }
      let family = match parsed.family {
         Family::V4 => "ipv4",
         Family::V6 => "ipv6",
      };
      let uid = uid.map_or_else(|| "unknown".to_owned(), |uid| uid.to_string());
      match parsed.l4 {
         L4Payload::Icmp { icmp_type, .. } => warn!(
            "denied icmp echo (type {icmp_type}, {family}, protocol {}) from uid {uid}: set \
             icmp_echo to allow to permit it",
            protocol.unwrap_or(0)
         ),
         _ => warn!(
            "denied transport {} ({family}, protocol has no policy) from uid {uid}: set \
             unmatched_transport to allow to permit it",
            protocol.map_or_else(
               || "unknown".to_owned(),
               |protocol| protocol.to_string()
            )
         ),
      }
   }

   fn accept(&mut self, id: u32) {
      if let Err(err) = self.queue.verdict(id, Verdict::Accept) {
         warn!("could not accept packet id={id}: {err}");
      }
   }

   fn drop_packet(&mut self, id: u32) {
      if let Err(err) = self.queue.verdict(id, Verdict::Drop) {
         warn!("could not drop packet id={id}: {err}");
      }
   }

   /// Registers the packet with an open prompt for its flow, or opens one.
   fn prompt(&mut self, connection: &Connection, packet_id: u32) {
      let flow = connection.flow_key();
      if let Some(id) = self.pending.attach(&flow, packet_id) {
         debug!("packet id={packet_id} joined open prompt {id}");
         return;
      }

      if self.mode == Mode::Silent {
         self.accept(packet_id);
         // No prompt was opened, so there is no id to close; `0` is the protocol's "no
         // prompt" marker and the resolution tells the client why the flow was allowed.
         self.ipc.broadcast(&Response::PromptClosed {
            id: 0,
            resolution: Resolution::SilentAutoAllowed,
         });
         self.ipc.broadcast(&Response::Connection(ConnectionEvent {
            at: now_secs(),
            connection: self.view(connection),
            allowed: true,
            matched_rule: None,
            via_prompt: false,
         }));
         if !self.silent_warned {
            self.silent_warned = true;
            warn!("silent mode: allowed an unmatched connection without prompting");
         }
         return;
      }

      let timeout = Duration::from_secs(self.config.prompt_timeout_secs);
      let opened = self.pending.open(
         connection.clone(),
         packet_id,
         timeout,
         Instant::now(),
      );
      match opened {
         // The set is at `MAX_PROMPTS`: the flood is denied rather than queued, and the line
         // is rate-limited so the denial itself cannot become the flood. The prompt set is
         // never grown past the cap and no prompt is opened for this packet.
         Opened::Full => {
            self.drop_packet(packet_id);
            let remote = connection.remote.addr;
            if self.prompt_limit.record(remote, Instant::now()) {
               warn!(
                  "prompt limit ({}) reached; denying {} -> {}:{}; existing prompts must be \
                   answered first",
                  pending::MAX_PROMPTS,
                  connection.app_name(),
                  connection.remote.addr,
                  connection.remote.port
               );
            }
         }
         Opened::Attached(id) => {
            // `prompt` already attached the packet above, so this is only reachable if the
            // two lookups ever disagree; the packet is answered with the prompt all the same.
            debug!("packet id={packet_id} joined open prompt {id}");
         }
         Opened::Joined(id) => {
            // A second destination of an app whose prompt is already open: the group is
            // already on screen, so the clients get the longer list and the deadline stands.
            debug!(
               "prompt {id} for {} -> {}:{} joined the open group",
               connection.app_name(),
               connection.remote.addr,
               connection.remote.port
            );
            if let Some(record) = self.pending.get(id).cloned() {
               self.announce_prompt(&record);
            }
         }
         Opened::Created(id) => {
            // Every prompt is live from the moment it is created, so it is broadcast at once
            // with its own deadline; nothing waits behind anything else.
            let record = self.pending.get(id).expect("just opened").clone();
            self.announce_prompt(&record);
         }
      }
      self.publish_status();
   }

   /// Drops a flow whose socket is already gone and records it in the connection log.
   fn closed_flow_dropped(&mut self, connection: &Connection, packet_id: u32) {
      self.drop_packet(packet_id);
      self.broadcast_connection(connection, Action::Deny, None, false);
      if self.closed_flows.record(connection.remote.addr, Instant::now()) {
         warn!(
            "dropped a flow whose socket was already closed: {} -> {}:{} ({}); \
             nothing is waiting for it, see unattributable_closed_flow",
            connection.app_name(),
            connection.remote.addr,
            connection.remote.port,
            connection.proto
         );
      }
   }

   /// Allows a flow whose socket is already gone, because the owner asked for fail-open.
   fn closed_flow_allowed(&mut self, connection: &Connection, packet_id: u32) {
      self.accept(packet_id);
      self.broadcast_connection(connection, Action::Allow, None, false);
      if self.closed_flows.record(connection.remote.addr, Instant::now()) {
         info!(
            "allowed a flow whose socket was already closed: {} -> {}:{} ({}); \
             unattributable_closed_flow is allow",
            connection.app_name(),
            connection.remote.addr,
            connection.remote.port,
            connection.proto
         );
      }
   }

   /// Allows an unmatched multicast destination once per app.
   fn multicast_allowed(&mut self, connection: &Connection, packet_id: u32) {
      self.accept(packet_id);
      self.broadcast_connection(connection, Action::Allow, None, false);
      let app = connection.app_name();
      // The bound only keeps the one-per-app line from growing without limit on a machine
      // that runs an unusual number of multicast speakers; the packet is still allowed.
      if self.multicast_logged.contains(&app) || self.multicast_logged.len() >= MAX_MULTICAST_APPS {
         return;
      }
      self.multicast_logged.insert(app.clone());
      info!(
         "allowing multicast traffic from {app} without a prompt: {} cannot be attributed \
          (the local port is shared with other uids), and it cannot leave the link",
         connection.remote.addr
      );
   }

   /// Times out every due prompt, expires grants and prunes the DNS cache.
   fn sweep(&mut self, now: Instant) {
      let expired = self.pending.expired_all(now);
      let any = !expired.is_empty();
      for resolved in expired {
         let record = resolved.record;
         let dest = match record.dests.as_slice() {
            [dest] => dest_label(&dest.connection),
            dests => format!("{} destinations", dests.len()),
         };
         for dest in &record.dests {
            if let Err(err) = self.answer_packets(&dest.packet_ids, Verdict::Drop) {
               warn!(
                  "could not deny prompt {}'s packets: {err}",
                  record.id
               );
            }
         }
         let local = record.first().map_or_else(
            || "-".to_owned(),
            |dest| dest.connection.local.addr.to_string(),
         );
         warn!(
            "prompt {} timed out after {}s; denied {} from {} to {}",
            record.id,
            self.config.prompt_timeout_secs,
            record.app_name(),
            local,
            dest
         );
         self.ipc.broadcast(&Response::PromptClosed {
            id: record.id,
            resolution: Resolution::TimedOut,
         });
         for dest in &record.dests {
            self.broadcast_connection(&dest.connection, Action::Deny, None, true);
         }
      }
      if any {
         self.publish_status();
      }

      let epoch = now_secs();
      let removed = self.policy.expire_grants(epoch);
      if removed > 0 {
         debug!("expired {removed} flow grant(s)");
      }
      self.dns_cache.lock().expect("dns cache").expire(epoch);
   }

   /// Builds the [`Connection`] for a parsed packet and, when it has no owner, why — or
   /// `None` when the transport has no endpoints to govern.
   fn connection_for(
      &mut self,
      parsed: &ParsedPacket,
      packet: &Packet,
   ) -> Option<(Connection, Option<Missing>)> {
      let (proto, local_port, remote_port) = match parsed.l4 {
         L4Payload::Tcp {
            src_port,
            dst_port,
            flags,
         } => {
            // Only the opening SYN is a policy question. Whatever follows in an established
            // flow has already been answered, and queueing a second SYN-ACK or a FIN would
            // stack a second prompt for a connection the user already decided.
            if !flags.syn() || flags.ack() {
               return None;
            }
            (L4Proto::Tcp, src_port, dst_port)
         }
         L4Payload::Udp { src_port, dst_port } => (L4Proto::Udp, src_port, dst_port),
         L4Payload::Icmp { .. } | L4Payload::Other => return None,
      };

      let local = Endpoint {
         addr: parsed.src,
         port: local_port,
      };
      let remote = Endpoint {
         addr: parsed.dst,
         port: remote_port,
      };
      let attributed = self.attributor.attribute(
         (local.addr, local.port),
         (remote.addr, remote.port),
         proto,
         packet.uid,
      );
      let missing = attributed.missing;

      let (domain, also_domains) = self.domain_names(remote.addr);
      let connection = Connection {
         family: parsed.family,
         proto,
         local,
         remote,
         process: attributed.attribution,
         domain,
         also_domains,
      };
      Some((connection, missing))
   }

   /// Splits the live names for `addr` into the primary — the one a prompt shows — and every
   /// alternate live name, in the cache's order.
   ///
   /// A miss is logged at most once per [`DNS_MISS_LOG_GAP`] per address: a busy machine
   /// looks up a lot of uncached addresses, and each line would otherwise flood the
   /// journal. Hits are never logged.
   fn domain_names(&mut self, addr: IpAddr) -> (Option<String>, Vec<String>) {
      let mut names = self.live_domains(addr);
      let domain = (!names.is_empty()).then(|| names.remove(0));
      if domain.is_none() && self.dns_misses.record(addr, Instant::now()) {
         debug!("dns: no name for {addr}");
      }
      (domain, names)
   }

   /// Every live name the DNS cache holds for `addr`, most recently learned first.
   ///
   /// The first is what a prompt displays; the rest are names a domain rule must also match,
   /// because several names can share one address.
   fn live_domains(&self, addr: IpAddr) -> Vec<String> {
      self
         .dns_cache
         .lock()
         .expect("dns cache")
         .names_for(addr, now_secs())
         .into_iter()
         .map(str::to_owned)
         .collect()
   }

   /// A display snapshot of one connection.
   fn view(&self, connection: &Connection) -> ConnectionView {
      let candidates = self.domain_candidates(connection);
      ConnectionView::from_connection(connection, &candidates)
   }

   fn domain_candidates(&self, connection: &Connection) -> Vec<String> {
      self.live_domains(connection.remote.addr)
   }

   fn broadcast_connection(
      &self,
      connection: &Connection,
      action: Action,
      rule: Option<RuleId>,
      via_prompt: bool,
   ) {
      let event = ConnectionEvent {
         at: now_secs(),
         connection: self.view(connection),
         allowed: action == Action::Allow,
         matched_rule: rule,
         via_prompt,
      };
      self.ipc.broadcast(&Response::Connection(event));
   }
}

/// A short human label for the scope the user chose, for the decision log line.
fn scope_label(scope: &ScopeChoice) -> String {
   match scope {
      ScopeChoice::AnyConnection => "any connection by this app".to_owned(),
      ScopeChoice::Domain {
         host,
         subdomains: false,
      } => format!("domain {host}"),
      ScopeChoice::Domain {
         host,
         subdomains: true,
      } => format!("domain {host} (+subdomains)"),
      ScopeChoice::Address => "this address".to_owned(),
      ScopeChoice::TheseDestinations => "these destinations".to_owned(),
   }
}

/// The one-line record of a decision: which action, for how long, and at what scope.
fn decision_line(id: u64, app: &str, dest: &str, decide: &DecideRequest, scope: &str) -> String {
   let action = match decide.action {
      Action::Allow => "allow",
      Action::Deny => "deny",
   };
   let duration = match decide.duration {
      RuleDuration::Once => "once",
      RuleDuration::Session => "until restart",
      RuleDuration::Forever => "forever",
   };
   format!("prompt {id} for {app} -> {dest}: {action}, {duration}, scope {scope}")
}

/// The destination as the prompt logs it: the learned domain when there is one, otherwise
/// `addr:port`.
fn dest_label(connection: &Connection) -> String {
   match connection.domain.as_deref() {
      Some(domain) => domain.to_owned(),
      None => format!(
         "{}:{}",
         connection.remote.addr, connection.remote.port
      ),
   }
}

/// What happens to a flow the policy declined to decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unmatched {
   /// Open a prompt, which is also what silent mode wants: `prompt` then auto-allows.
   Prompt,
   /// The socket is already gone and the owner asked for fail-closed.
   DropClosed,
   /// The socket is already gone and the owner asked for fail-open.
   AllowClosed,
   /// A multicast destination: never attributable, and it cannot leave the link.
   AllowMulticast,
}

/// Decides an unmatched flow from what attribution learned and the owner's settings.
fn unmatched(
   connection: &Connection,
   missing: Option<Missing>,
   config: &Config,
   mode: Mode,
) -> Unmatched {
   // Silent mode allows unmatched traffic by contract, closed socket or not.
   if mode == Mode::Silent {
      return Unmatched::Prompt;
   }
   if connection.remote.addr.is_multicast() {
      return Unmatched::AllowMulticast;
   }
   match (missing, config.unattributable_closed_flow) {
      (Some(Missing::SocketGone), ClosedFlowAction::Drop) => Unmatched::DropClosed,
      (Some(Missing::SocketGone), ClosedFlowAction::Allow) => Unmatched::AllowClosed,
      _ => Unmatched::Prompt,
   }
}

/// The IP next-header byte of a packet the parser already validated.
///
/// The parsed payload carries no protocol number, and the denial line must name the real
/// one, so it is read from the same header the parser used: byte 9 of an IPv4 header, byte 6
/// of an IPv6 header. `None` only for a buffer too short to be either, which `parse` has
/// already rejected.
fn packet_protocol(payload: &[u8]) -> Option<u8> {
   match payload.first().map(|first| first >> 4) {
      Some(4) => payload.get(9).copied(),
      Some(6) => payload.get(6).copied(),
      _ => None,
   }
}

/// What happens to a queued packet no [`Connection`] can be built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportAction {
   /// Not a transport the policy model declines for a reason of its own: an established
   /// TCP or UDP packet, or a family mismatch, keeps the historical accept.
   Ignore,
   /// An unmodelled transport or an ICMP echo the owner has not allowed.
   Drop,
   /// An allowed ICMP echo, an allowed port-less transport, or an ICMP error.
   Allow,
}

/// Decides a packet the flow model cannot express, from its transport and the owner's
/// settings.
///
/// This is deliberately a pure function on the parsed payload: the packet never reaches a
/// [`Connection`], so the decision cannot depend on attribution and can be unit-tested
/// without a queue. The family needs no parameter because the ambiguous ICMP types are
/// already distinct on the wire (v4 echo is 8, v6 echo is 128).
fn transport_verdict(l4: &L4Payload, config: &Config) -> TransportAction {
   match l4 {
      // ICMP echo request (v4 type 8) and ICMPv6 echo request (type 128) are the outbound
      // half of a ping, and an ICMP tunnel rides on them, so the owner's setting decides.
      L4Payload::Icmp {
         icmp_type: 8 | 128, ..
      } => match config.icmp_echo {
         IcmpAction::Deny => TransportAction::Drop,
         IcmpAction::Allow => TransportAction::Allow,
      },
      // Everything else in ICMP is a diagnostic the kernel or a well-behaved peer emits:
      // destination unreachable (v4 3, v6 1), packet too big (v6 2), time exceeded (v4 11,
      // v6 3) and parameter problem (v4 12, v6 4). Dropping those breaks path-MTU discovery
      // and ordinary TCP, so this is the one deliberate allow.
      L4Payload::Icmp { .. } => TransportAction::Allow,
      // SCTP, DCCP, GRE, ESP and IP-in-IP carry no port pair, so no rule can express a
      // decision: the owner's setting, denying by default, is the only decision available.
      L4Payload::Other => match config.unmatched_transport {
         UnmatchedTransport::Deny => TransportAction::Drop,
         UnmatchedTransport::Allow => TransportAction::Allow,
      },
      // Only an opening TCP SYN reaches here as a `None` from `connection_for`; every
      // other TCP segment, and a family the model cannot place, is not a policy question.
      L4Payload::Tcp { .. } | L4Payload::Udp { .. } => TransportAction::Ignore,
   }
}

/// A per-key one-line-per-gap log limiter.
///
/// Same shape and contract as [`MissLimiter`], keyed by the transport a denial names
/// instead of an address: a ping flood or an SCTP association must not put one line per
/// packet in the journal, while still recording that the drop happened.
struct KeyLimiter<K> {
   last: HashMap<K, Instant>,
   gap: Duration,
   limit: usize,
}

impl<K: Eq + Hash> KeyLimiter<K> {
   fn new(gap: Duration, limit: usize) -> Self {
      Self {
         last: HashMap::new(),
         gap,
         limit,
      }
   }

   /// Whether an event for `key` at `now` should be logged.
   fn record(&mut self, key: K, now: Instant) -> bool {
      if let Some(at) = self.last.get(&key) {
         if now.duration_since(*at) < self.gap {
            return false;
         }
      } else if self.last.len() >= self.limit {
         self.last.retain(|_, at| now.duration_since(*at) < self.gap);
         if self.last.len() >= self.limit {
            return false;
         }
      }
      self.last.insert(key, now);
      true
   }
}

/// A per-address one-line-per-gap log limiter.
///
/// It keeps a repeated line cheap on a machine that touches many addresses the cache or a
/// scan never saw, without changing the fact that the condition happened. The gap is a
/// field so the prompt-limit line can reuse the same shape at its own rate.
struct MissLimiter {
   last: HashMap<IpAddr, Instant>,
   gap: Duration,
}

impl MissLimiter {
   fn new() -> Self {
      Self::with_gap(DNS_MISS_LOG_GAP)
   }

   /// A limiter that emits at most one line per address per `gap`.
   fn with_gap(gap: Duration) -> Self {
      Self {
         last: HashMap::new(),
         gap,
      }
   }

   /// Whether a miss for `addr` at `now` should be logged. The entry is added or refreshed
   /// only when it is, so a repeatedly missing address costs one hash lookup per gap.
   fn record(&mut self, addr: IpAddr, now: Instant) -> bool {
      if let Some(at) = self.last.get(&addr) {
         if now.duration_since(*at) < self.gap {
            return false;
         }
      } else if self.last.len() >= DNS_MISS_LIMIT {
         self.last.retain(|_, at| now.duration_since(*at) < self.gap);
         if self.last.len() >= DNS_MISS_LIMIT {
            return false;
         }
      }
      self.last.insert(addr, now);
      true
   }
}

/// The clock a periodic table re-verify runs on.
///
/// It carries its own `Instant` and advances only when asked, so the decision is unit-testable
/// without sleeping, without `nft` and without root. The first deadline is one interval after
/// construction: the table was just verified at startup, so there is nothing to re-check yet.
struct VerifySchedule {
   /// The instant the next re-verify is due.
   next: Instant,
   /// How far `due` advances the deadline every time it fires.
   interval: Duration,
}

impl VerifySchedule {
   /// Schedules the first re-verify one `interval` after `now`.
   fn new(now: Instant, interval: Duration) -> Self {
      Self {
         next: now.checked_add(interval).unwrap_or(now),
         interval,
      }
   }

   /// Whether a re-verify is due at `now`, advancing the deadline when it is.
   ///
   /// A late call advances by exactly one interval, never by zero: leaving the deadline at
   /// `now` would make every later call fire, while jumping it past `now` would swallow the
   /// intervals a stalled loop missed. A long stall therefore catches up one interval per
   /// call, and a call on the same instant keeps advancing instead of spinning in place.
   fn due(&mut self, now: Instant) -> bool {
      if now < self.next {
         return false;
      }
      self.next = self.next.checked_add(self.interval).unwrap_or(now);
      true
   }
}

/// Whether an error is the receive timeout rather than a failure.
fn would_block(err: &std::io::Error) -> bool {
   matches!(
      err.kind(),
      std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
   )
}

/// Builds the rules a prompt's answer creates.
///
/// The scope decides the rule, never the number of destinations the prompt happened to
/// list: `AnyConnection` is one rule for the app whatever was on screen, `Domain` and
/// `Address` are one rule at that scope, and `TheseDestinations` is one rule per listed
/// destination, each scoped to itself. Only an explicit `TheseDestinations` may produce a
/// per-destination answer, and only an explicit `AnyConnection` may produce
/// `DestMatcher::Any`.
fn rules_for(record: &PromptRecord, decide: &DecideRequest, now: u64) -> Vec<Rule> {
   match &decide.scope {
      ScopeChoice::TheseDestinations => record
         .dests
         .iter()
         .map(|dest| {
            let scope = group_scope(&dest.connection);
            rule_for(
               &dest.connection,
               &DecideRequest {
                  scope,
                  ..decide.clone()
               },
               now,
            )
         })
         .collect(),
      // A group that sends `Domain` or `Address` is honoured as one rule: the client asked
      // for it explicitly, and a single-destination prompt must keep its old shape.
      _ => match record.first() {
         Some(dest) => vec![rule_for(&dest.connection, decide, now)],
         None => Vec::new(),
      },
   }
}

/// The scope one destination of a `TheseDestinations` answer uses: its learned domain when
/// it has one, otherwise the one address it actually reached.
fn group_scope(connection: &Connection) -> ScopeChoice {
   match &connection.domain {
      Some(host) => ScopeChoice::Domain {
         host: host.to_ascii_lowercase(),
         subdomains: false,
      },
      None => ScopeChoice::Address,
   }
}

/// Builds the rule a prompt's answer creates.
fn rule_for(connection: &Connection, decide: &DecideRequest, now: u64) -> Rule {
   let app = match &connection.process {
      Attribution::Process(process) => match process.exe.clone() {
         Some(path) => AppMatcher::Exe(path),
         None => AppMatcher::Any,
      },
      Attribution::Unknown => AppMatcher::Unknown,
   };
   let scope = ScopeRequest {
      action: decide.action,
      duration: decide.duration,
      dest: dest_matcher(connection, &decide.scope),
   };
   rule_from_scope(RuleId::new_unique(), app, &scope, now)
}

/// The destination matcher a scope asks for, relative to `connection`.
fn dest_matcher(connection: &Connection, scope: &ScopeChoice) -> DestMatcher {
   match scope {
      ScopeChoice::AnyConnection => DestMatcher::Any,
      ScopeChoice::Domain { host, subdomains } => DestMatcher::Domain {
         host: host.to_ascii_lowercase(),
         subdomains: *subdomains,
      },
      ScopeChoice::Address => match single_host_net(connection.remote.addr) {
         Some(net) => DestMatcher::Ip(net),
         None => {
            // Unreachable: the prefix is the family's own width. The alert only offers
            // `AnyConnection` for an attributed app, so widening here cannot turn an
            // unattributed answer into a rule for every unattributed flow.
            warn!(
               "could not build a single-host network for {}; scoping to any destination",
               connection.remote.addr
            );
            DestMatcher::Any
         }
      },
      // `rules_for` expands this scope into one call per destination; a direct call scopes
      // to the destination itself.
      ScopeChoice::TheseDestinations => dest_matcher(connection, &group_scope(connection)),
   }
}

/// The network containing exactly `addr`: prefix 32 for IPv4, 128 for IPv6.
///
/// `None` means the prefix was wider than the address family, which cannot happen for the
/// width chosen from the address itself; the caller handles it instead of unwrapping.
fn single_host_net(addr: IpAddr) -> Option<IpNet> {
   let prefix = match addr {
      IpAddr::V4(_) => 32,
      IpAddr::V6(_) => 128,
   };
   IpNet::new(addr, prefix).ok()
}

/// Spawns the proc connector reader: seed the identity cache, then apply every event.
///
/// A kernel without `CONFIG_PROC_EVENTS` cannot be distinguished from a transient socket
/// error, so a failure is logged at `warn` and retried no more often than once a minute;
/// attribution keeps working through `/proc`, only without the race fix. This thread is
/// never fatal to the daemon: it is an optimisation of identity lookup, not the enforcement
/// path.
fn spawn_proc_connector(cache: Arc<Mutex<ProcessCache>>) {
   let _ = thread::Builder::new().name("netshield-procmon".to_owned()).spawn(move || {
      // Seeding before LISTEN closes the window: a process that exec'd before the
      // connector was open is still in `/proc` now, and one that exits after the seed
      // is reported by the connector.
      if let Ok(mut cache) = cache.lock() {
         cache.seed();
      }

      let mut connector = match ProcConnector::open() {
         Ok(connector) => connector,
         Err(err) => {
            warn!(
               "proc connector unavailable: {err}; process identity falls back to /proc and \
                may miss processes that exit mid-scan"
            );
            return;
         }
      };
      if let Err(err) = connector.set_recv_timeout(PROC_CONNECTOR_RECV_TIMEOUT) {
         warn!("proc connector receive timeout could not be set: {err}");
      }

      let mut events = Vec::new();
      let mut last_warn: Option<Instant> = None;
      loop {
         if SHUTDOWN.load(Ordering::SeqCst) {
            return;
         }
         match connector.recv(&mut events) {
            Ok(_) => {
               if let Ok(mut cache) = cache.lock() {
                  for event in events.drain(..) {
                     match event {
                        ProcEvent::Exec { pid } => cache.record_exec(pid),
                        ProcEvent::Exit { pid } => cache.forget(pid),
                     }
                  }
               } else {
                  events.clear();
               }
            }
            Err(err) if would_block(&err) => {}
            Err(err) => {
               // Rate-limited: a missing kernel feature answers every receive with the
               // same error, and one line a minute still names the cause.
               let now = Instant::now();
               if last_warn.is_none_or(|last| now.duration_since(last) >= PROC_CONNECTOR_WARN_GAP) {
                  warn!(
                     "proc connector receive failed: {err}; identities may fall back to \
                         /proc until it recovers"
                  );
                  last_warn = Some(now);
               }
            }
         }
      }
   });
}

/// Spawns the DNS reader: parse every answer into the cache, always accept.
fn spawn_dns_reader(
   mut queue: NfQueue,
   cache: Arc<Mutex<DnsCache>>,
   queue_num: u16,
) -> Result<(), DaemonError> {
   thread::Builder::new()
      .name("netshield-dns".to_owned())
      .spawn(move || {
         let mut packets = Vec::new();
         loop {
            match queue.recv(&mut packets) {
               Ok(0) => continue,
               Ok(_) => {}
               Err(NfqError::Io(err)) if would_block(&err) => {
                  if SHUTDOWN.load(Ordering::SeqCst) {
                     return;
                  }
                  continue;
               }
               Err(err) => {
                  warn!("DNS queue {queue_num} receive failed: {err}");
                  if SHUTDOWN.load(Ordering::SeqCst) {
                     return;
                  }
                  continue;
               }
            }

            for packet in packets.drain(..) {
               // The one line that distinguishes "the queue delivered nothing" from the
               // parser or the cache dropping the answer further down this path.
               let from = parse(&packet.payload)
                  .map(|parsed| parsed.src.to_string())
                  .unwrap_or_else(|_| "?".to_owned());
               debug!(
                  "dns queue: id={} family={} len={} from={from}",
                  packet.id,
                  packet.family,
                  packet.payload.len()
               );
               cache_answer(&cache, &packet.payload);
               // Nothing on the DNS path may ever drop an answer: a parse failure is
               // logged at debug and the packet is still accepted.
               if let Err(err) = queue.verdict(packet.id, Verdict::Accept) {
                  warn!(
                     "could not accept DNS packet id={}: {err}",
                     packet.id
                  );
               }
            }
         }
      })
      .map(|_| ())
      .map_err(DaemonError::Thread)
}

/// How many CNAME edges the cache will walk backwards before giving up.
///
/// Eight is far beyond any legitimate chain (`www.iana.org` uses one), and the cap is what
/// makes a hostile or broken answer terminate; the cache still records what it reached.
const MAX_CNAME_HOPS: usize = 8;

/// Recovers the name the application asked for by walking CNAME edges backwards.
///
/// An answer's `A`/`AAAA` record is owned by the *canonical* name, so the address points at
/// the CNAME target rather than the query. Every edge is `owner -> target`, and the walk
/// follows the edge whose target is the current name until no edge matches, at most
/// [`MAX_CNAME_HOPS`] times, stopping early if a name repeats so a cycle cannot spin.
fn queried_name(owner: &str, edges: &[(String, String)]) -> String {
   let mut current = owner.to_owned();
   let mut seen = vec![current.clone()];
   for _ in 0..MAX_CNAME_HOPS {
      let Some((parent, _)) = edges.iter().find(|(_, target)| *target == current) else {
         break;
      };
      if seen.iter().any(|name| name == parent) {
         break;
      }
      current = parent.clone();
      seen.push(current.clone());
   }
   current
}

/// Parses one DNS answer and inserts every usable record into the cache.
fn cache_answer(cache: &Mutex<DnsCache>, payload: &[u8]) {
   let family = payload.first().map(|first| first >> 4);
   let Some((body, tcp)) = transport_payload(payload) else {
      debug!(
         "DNS payload has no TCP/UDP transport; ignoring it (len={}, family={family:?})",
         payload.len()
      );
      return;
   };

   let records = if tcp {
      parse_tcp_response(body)
   } else {
      parse_response(body)
   };

   let records: Vec<DnsRecord> = match records {
      Ok(records) => records,
      Err(err) => {
         debug!(
            "DNS answer could not be parsed: {err:?} (len={}, family={family:?})",
            payload.len()
         );
         return;
      }
   };

   let now = now_secs();
   let mut cache = cache.lock().expect("dns cache");

   // The edges that link every address back to the name the application queried. They are
   // collected first because a CNAME may follow the address it points at in the answer.
   let mut edges = Vec::new();
   for record in &records {
      if record.kind == RecordKind::Cname
         && let Target::Name(target) = &record.target
      {
         edges.push((record.name.clone(), target.clone()));
      }
   }

   for record in records {
      if let Target::Address(addr) = record.target {
         let root = queried_name(&record.name, &edges);
         // The record's own name is inserted first so the recovered root, which the prompt
         // should display, ends up as the most recently inserted name.
         if root != record.name {
            cache.insert(addr, &record.name, record.ttl, now);
         }
         cache.insert(addr, &root, record.ttl, now);
         debug!(
            "dns: {} -> {} ttl={}",
            record.name, addr, record.ttl
         );
      }
   }
}

/// The transport payload of one captured IP packet, and whether it is TCP.
///
/// `packet::parse` reports the addresses and ports but not where the transport payload
/// starts, and the DNS parsers need exactly those bytes; a DNS message read from the
/// start of the IP header would decode the IP header as a DNS header, which is how the
/// first live run managed to parse nothing at all. The returned slice starts after the
/// UDP header's fixed eight bytes, or after the variable-length TCP header.
///
/// Every offset is checked, so a truncated or hostile datagram yields `None` rather than
/// a panic; a transport header with no payload (an eight-byte UDP datagram, a bare TCP
/// header) is `None` too, because there is no DNS message to hand to the parser.
pub(crate) fn transport_payload(payload: &[u8]) -> Option<(&[u8], bool)> {
   let first = *payload.first()?;
   let (transport, end, proto) = match first >> 4 {
      4 => {
         let ihl = usize::from(first & 0x0f);
         if ihl < 5 {
            return None;
         }
         let header = ihl * 4;
         let total = usize::from(u16::from_be_bytes([
            *payload.get(2)?,
            *payload.get(3)?,
         ]));
         if total < header || total > payload.len() {
            return None;
         }
         (header, total, *payload.get(9)?)
      }
      6 => {
         let declared = usize::from(u16::from_be_bytes([
            *payload.get(4)?,
            *payload.get(5)?,
         ]));
         let end = if declared == 0 {
            payload.len()
         } else {
            40usize.checked_add(declared)?
         };
         if end > payload.len() {
            return None;
         }

         let mut next = *payload.get(6)?;
         let mut offset = 40usize;
         let mut extensions = 0u8;
         loop {
            match next {
               6 | 17 => break,
               0 | 43 | 60 => {
                  extensions += 1;
                  if extensions > 8 {
                     return None;
                  }
                  let len = usize::from(*payload.get(offset.checked_add(1)?)?);
                  next = *payload.get(offset)?;
                  offset = offset.checked_add((len + 1) * 8)?;
               }
               51 => {
                  extensions += 1;
                  if extensions > 8 {
                     return None;
                  }
                  let len = usize::from(*payload.get(offset.checked_add(1)?)?);
                  next = *payload.get(offset)?;
                  offset = offset.checked_add((len + 2) * 4)?;
               }
               44 => {
                  extensions += 1;
                  if extensions > 8 {
                     return None;
                  }
                  next = *payload.get(offset)?;
                  offset = offset.checked_add(8)?;
               }
               _ => return None,
            }
            if offset > end {
               return None;
            }
         }
         (offset, end, next)
      }
      _ => return None,
   };

   let start = match proto {
      // TCP's data offset is the high nibble of byte 12 of its header, in 32-bit words;
      // five words (20 bytes) is the minimum a header can be.
      6 => {
         let data_offset = usize::from(*payload.get(transport.checked_add(12)?)? >> 4) * 4;
         if data_offset < 20 {
            return None;
         }
         transport.checked_add(data_offset)?
      }
      // The UDP header is always exactly eight bytes.
      17 => transport.checked_add(8)?,
      _ => return None,
   };

   // A header that claims more bytes than the datagram holds, and a transport header
   // with no payload at all, both leave nothing for the DNS parser.
   if start >= end {
      return None;
   }
   let body = payload.get(start..end)?;
   Some((body, proto == 6))
}

/// Validates the machine is ready to run the daemon, then leaves it as it was found.
///
/// Safe to run repeatedly: the table is removed on success and the store is only created
/// on a genuine first run. It needs root, so it doubles as the refusal path for a normal
/// user.
pub fn check(config: Config, rules_path: &Path) -> Result<(), DaemonError> {
   let config = Config {
      rules_path: rules_path.to_path_buf(),
      ..config
   };

   let (store, seeded) = RuleStore::load_or_seed(&config.rules_path);
   adopt_or_install(&config)?;

   let queues = (|| {
      let queue = NfQueue::open(config.queue_num).map_err(|reason| DaemonError::Queue {
         queue: config.queue_num,
         reason,
      })?;
      let dns_queue = NfQueue::open(config.dns_queue_num).map_err(|reason| DaemonError::Queue {
         queue: config.dns_queue_num,
         reason,
      })?;
      Ok::<_, DaemonError>((queue, dns_queue))
   })();

   let table = config.table_name();
   let removed = firewall::remove(table);
   match (queues, removed) {
      (Ok(_), Ok(())) => {
         println!(
            "netshieldd --check: table inet {table} verified (queues {}/{}), {} rule(s) loaded{}, \
             DNS queue open; table removed",
            config.queue_num,
            config.dns_queue_num,
            store.rules().len(),
            if seeded { " (seeded)" } else { "" }
         );
         Ok(())
      }
      (Ok(_), Err(err)) => Err(DaemonError::Firewall(err)),
      (Err(err), Ok(())) => Err(err),
      (Err(err), Err(remove_err)) => {
         error!("--check could not remove table inet {table}: {remove_err}");
         Err(err)
      }
   }
}

#[cfg(test)]
mod tests {
   use std::net::Ipv4Addr;

   use netshield_core::connection::Family;
   use netshield_core::rule::Duration as RuleDuration;

   use super::*;

   #[test]
   fn would_block_covers_a_receive_timeout() {
      let timed_out = std::io::Error::from(std::io::ErrorKind::WouldBlock);
      let again = std::io::Error::from(std::io::ErrorKind::TimedOut);
      let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
      assert!(would_block(&timed_out));
      assert!(would_block(&again));
      assert!(!would_block(&denied));
   }

   #[test]
   fn signals_set_the_shutdown_flag() {
      SHUTDOWN.store(false, Ordering::SeqCst);
      on_shutdown_signal(libc::SIGTERM);
      assert!(SHUTDOWN.load(Ordering::SeqCst));
      SHUTDOWN.store(false, Ordering::SeqCst);
   }

   /// A policy-aware revocation spares what the policy allows and resets what it denies.
   #[test]
   fn a_mismatched_revoke_spares_what_the_policy_allows() {
      let allowed = Decision::Allow { rule: None };
      let denied = Decision::Deny { rule: None };
      assert!(!revokes(&allowed, false));
      assert!(!revokes(&allowed, true));
      assert!(revokes(&denied, false));
      assert!(revokes(&denied, true));
      // A flow the policy would now prompt for: a mode change resets it, a fresh start leaves it.
      assert!(revokes(&Decision::Prompt, true));
      assert!(!revokes(&Decision::Prompt, false));
   }

   #[test]
   fn dns_miss_limiter_suppresses_a_repeat_within_the_gap() {
      let mut limiter = MissLimiter::new();
      let addr: IpAddr = "192.0.2.10".parse().expect("an IPv4 address");
      let other: IpAddr = "192.0.2.11".parse().expect("another IPv4 address");
      let start = Instant::now();

      assert!(
         limiter.record(addr, start),
         "the first miss is emitted"
      );
      assert!(
         !limiter.record(addr, start + Duration::from_millis(500)),
         "a second miss inside the gap is suppressed"
      );
      assert!(
         limiter.record(other, start + Duration::from_millis(500)),
         "a different address is emitted immediately"
      );
      assert!(
         limiter.record(addr, start + DNS_MISS_LOG_GAP),
         "a miss after the gap is emitted again"
      );
   }

   #[test]
   fn the_verify_schedule_fires_once_per_interval() {
      let interval = Duration::from_secs(30);
      let start = Instant::now();
      let mut schedule = VerifySchedule::new(start, interval);

      assert!(
         !schedule.due(start),
         "not due before the first deadline"
      );
      assert!(
         !schedule.due(start + interval - Duration::from_millis(1)),
         "still not due a millisecond early"
      );
      assert!(
         schedule.due(start + interval),
         "due at the first deadline"
      );
      assert!(
         !schedule.due(start + interval),
         "not due again on the same instant"
      );
      assert!(
         !schedule.due(start + interval + Duration::from_millis(1)),
         "not due immediately after"
      );
      assert!(
         schedule.due(start + 2 * interval),
         "due again a full interval later"
      );

      // A large jump advances by exactly one interval per call, never by zero: a loop that
      // stalled for an hour catches up over its next iterations, one interval at a time.
      let mut schedule = VerifySchedule::new(start, interval);
      let stalled = start + Duration::from_secs(60 * 60);
      let mut calls = 0u32;
      while schedule.due(stalled) {
         calls += 1;
         assert_eq!(
            schedule.next,
            start + interval * (calls + 1),
            "each catch-up call advances exactly one interval, never zero"
         );
      }
      assert_eq!(
         calls, 120,
         "one call per missed interval, not one for the whole jump"
      );
      assert!(
         !schedule.due(stalled),
         "once caught up, the same instant is no longer due"
      );
   }

   /// A rule for `ScopeChoice::Address` covers the flow's exact remote address, on both
   /// families, and never a neighbouring one: this is the narrow scope that replaces the
   /// broad, unattributable one.
   #[test]
   fn address_scope_covers_only_the_flows_remote_address() {
      for (remote, neighbour) in [
         ("198.51.100.20", "198.51.100.21"),
         ("2001:db8::1", "2001:db8::2"),
      ] {
         let remote: IpAddr = remote.parse().expect("a remote address");
         let neighbour: IpAddr = neighbour.parse().expect("a neighbouring address");
         let connection = Connection {
            family: match remote {
               IpAddr::V4(_) => Family::V4,
               IpAddr::V6(_) => Family::V6,
            },
            proto: L4Proto::Tcp,
            local: Endpoint {
               addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
               port: 51_234,
            },
            remote: Endpoint {
               addr: remote,
               port: 443,
            },
            process: Attribution::Unknown,
            domain: None,
            also_domains: Vec::new(),
         };
         let decide = DecideRequest {
            prompt_id: 7,
            action: Action::Allow,
            duration: RuleDuration::Session,
            scope: ScopeChoice::Address,
         };

         let rule = rule_for(&connection, &decide, 100);
         let DestMatcher::Ip(net) = &rule.dest else {
            panic!(
               "address scope must write an IP matcher, got {:?}",
               rule.dest
            );
         };
         assert!(
            net.contains(remote),
            "{net:?} must cover the flow's remote address {remote}"
         );
         assert!(
            !net.contains(neighbour),
            "{net:?} must not cover the neighbouring address {neighbour}"
         );
      }
   }

   /// A connection to `remote:port`, for the unmatched-flow decision tests.
   fn unmatched_connection(remote: &str, port: u16) -> Connection {
      let remote: IpAddr = remote.parse().expect("a remote address");
      Connection {
         family: match remote {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
         },
         proto: L4Proto::Udp,
         local: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 51_234,
         },
         remote: Endpoint { addr: remote, port },
         process: Attribution::Unknown,
         domain: None,
         also_domains: Vec::new(),
      }
   }

   /// What happens to a flow no rule and no process owner decided: the socket's state, the
   /// owner's setting, the mode and the destination's reachability each pick the verdict.
   #[test]
   fn the_unmatched_flow_policy() {
      for (remote, port, missing, config, mode, expected) in [
         (
            "93.184.216.34",
            443,
            Some(Missing::SocketGone),
            Config::default(),
            Mode::Alert,
            Unmatched::DropClosed,
         ),
         (
            "93.184.216.34",
            443,
            Some(Missing::SocketGone),
            Config {
               unattributable_closed_flow: ClosedFlowAction::Allow,
               ..Config::default()
            },
            Mode::Alert,
            Unmatched::AllowClosed,
         ),
         (
            "93.184.216.34",
            443,
            Some(Missing::SocketGone),
            Config {
               unattributable_closed_flow: ClosedFlowAction::Prompt,
               ..Config::default()
            },
            Mode::Alert,
            Unmatched::Prompt,
         ),
         // A row existed but could not be resolved: the socket may still be alive, so the
         // default must ask rather than drop.
         (
            "93.184.216.34",
            443,
            Some(Missing::NotOurs),
            Config::default(),
            Mode::Alert,
            Unmatched::Prompt,
         ),
         // No reason at all is not a closed socket either.
         (
            "93.184.216.34",
            443,
            None,
            Config::default(),
            Mode::Alert,
            Unmatched::Prompt,
         ),
         // Even with the socket gone and the fail-closed default: a multicast destination is
         // unattributable in principle and cannot leave the link.
         (
            "224.0.0.251",
            5353,
            Some(Missing::SocketGone),
            Config::default(),
            Mode::Alert,
            Unmatched::AllowMulticast,
         ),
         (
            "ff02::fb",
            5353,
            Some(Missing::SocketGone),
            Config::default(),
            Mode::Alert,
            Unmatched::AllowMulticast,
         ),
         // `Prompt` is what auto-allows in silent mode, so the closed-flow default must not
         // bypass silent mode's contract.
         (
            "93.184.216.34",
            443,
            Some(Missing::SocketGone),
            Config::default(),
            Mode::Silent,
            Unmatched::Prompt,
         ),
      ] {
         assert_eq!(
            unmatched(
               &unmatched_connection(remote, port),
               missing,
               &config,
               mode,
            ),
            expected,
            "{remote}:{port} with {missing:?} in {mode:?} must be {expected:?}"
         );
      }
   }

   /// A queued packet no flow can be built for: an ICMP echo and a port-less transport are
   /// denied unless the owner allows them, while an ICMP error always passes and an
   /// established TCP/UDP segment keeps the historical accept.
   #[test]
   fn the_transport_verdict_for_unmodelled_flows() {
      let icmp = |icmp_type: u8| L4Payload::Icmp {
         icmp_type,
         icmp_code: 0,
      };
      let allow_icmp = Config {
         icmp_echo: IcmpAction::Allow,
         ..Config::default()
      };
      let allow_transport = Config {
         unmatched_transport: UnmatchedTransport::Allow,
         ..Config::default()
      };

      for (l4, config, expected) in [
         // An echo request is an outbound attempt: denied by default, allowed on request.
         (icmp(8), Config::default(), TransportAction::Drop),
         (
            icmp(8),
            allow_icmp.clone(),
            TransportAction::Allow,
         ),
         (
            icmp(128),
            Config::default(),
            TransportAction::Drop,
         ),
         (
            icmp(128),
            allow_icmp.clone(),
            TransportAction::Allow,
         ),
         // An ICMP error is the kernel's own diagnostic: dropping it breaks path MTU and
         // ordinary TCP, so it passes whatever the owner set.
         (icmp(3), Config::default(), TransportAction::Allow),
         (icmp(3), allow_icmp, TransportAction::Allow),
         (icmp(2), Config::default(), TransportAction::Allow),
         // SCTP (132) carries no ports: no rule can express it, so the owner's setting is
         // the whole decision, and it denies by default.
         (
            L4Payload::Other,
            Config::default(),
            TransportAction::Drop,
         ),
         (
            L4Payload::Other,
            allow_transport,
            TransportAction::Allow,
         ),
      ] {
         assert_eq!(
            transport_verdict(&l4, &config),
            expected,
            "{l4:?} must be {expected:?}"
         );
      }

      // A TCP segment that is not an opening SYN never reaches this decision; if it did, the
      // model has no new flow to judge and keeps the historical accept.
      let established = parse(&tcp_packet(0x10)).expect("an ACK parses").l4;
      assert_eq!(
         transport_verdict(&established, &Config::default()),
         TransportAction::Ignore
      );
   }

   /// A hand-built IPv4/TCP packet, so the SYN filter is tested on real parsed flags.
   fn tcp_packet(flags: u8) -> Vec<u8> {
      let mut bytes = vec![0u8; 40];
      bytes[0] = 0x45;
      bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
      bytes[8] = 64;
      bytes[9] = 6;
      bytes[12..16].copy_from_slice(&[192, 0, 2, 10]);
      bytes[16..20].copy_from_slice(&[198, 51, 100, 20]);
      bytes[20..22].copy_from_slice(&51_234u16.to_be_bytes());
      bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
      bytes[33] = flags;
      bytes
   }

   #[test]
   fn only_a_bare_syn_is_a_new_flow() {
      let bare_syn = parse(&tcp_packet(0x02)).expect("a SYN parses");
      assert!(matches!(
         bare_syn.l4,
         L4Payload::Tcp { flags, .. } if flags.syn() && !flags.ack()
      ));

      let syn_ack = parse(&tcp_packet(0x12)).expect("a SYN-ACK parses");
      assert!(
         matches!(
            syn_ack.l4,
            L4Payload::Tcp { flags, .. } if flags.syn() && flags.ack()
         ),
         "a SYN-ACK is a reply, not an opening"
      );

      let data = parse(&tcp_packet(0x10)).expect("an ACK parses");
      assert!(matches!(
         data.l4,
         L4Payload::Tcp { flags, .. } if !flags.syn()
      ));
   }

   /// The DNS transaction id the fixtures below carry.
   const DNS_ID: u16 = 0x4242;

   /// The client port a DNS answer is delivered to, chosen so its high byte has `QR`
   /// clear: a parser handed the UDP header instead of the message would read the
   /// destination port as the DNS flags and report [`DnsError::NotResponse`].
   const CLIENT_PORT: u16 = 20_001;

   /// The address the fixture's `A` record points at.
   const ANSWER: [u8; 4] = [93, 184, 216, 34];

   fn labels(name: &str) -> Vec<u8> {
      let mut bytes = Vec::new();
      for label in name.split('.') {
         bytes.push(label.len() as u8);
         bytes.extend_from_slice(label.as_bytes());
      }
      bytes.push(0);
      bytes
   }

   /// A real `example.com A 93.184.216.34` response, transaction id [`DNS_ID`].
   fn a_record_response() -> Vec<u8> {
      let mut msg = vec![0u8; 12];
      msg[0..2].copy_from_slice(&DNS_ID.to_be_bytes());
      msg[2] = 0x81; // QR set, recursion desired
      msg[3] = 0x80; // recursion available
      msg[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount
      msg[6..8].copy_from_slice(&1u16.to_be_bytes()); // ancount
      msg.extend_from_slice(&labels("example.com"));
      msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
      msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
      msg.extend_from_slice(&[0xc0, 0x0c]); // the question's name, compressed
      msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
      msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
      msg.extend_from_slice(&300u32.to_be_bytes()); // TTL
      msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
      msg.extend_from_slice(&ANSWER);
      msg
   }

   /// One answer in a fixture response: owner name, wire type code and RDATA.
   struct FixtureRecord<'a> {
      owner: &'a str,
      kind: u16,
      rdata: Vec<u8>,
   }

   /// A `CNAME` answer from `owner` to `target`.
   fn cname_record<'a>(owner: &'a str, target: &str) -> FixtureRecord<'a> {
      FixtureRecord {
         owner,
         kind: 5,
         rdata: labels(target),
      }
   }

   /// An `A` answer owned by `owner` carrying `addr`.
   fn address_record<'a>(owner: &'a str, addr: [u8; 4]) -> FixtureRecord<'a> {
      FixtureRecord {
         owner,
         kind: 1,
         rdata: addr.to_vec(),
      }
   }

   /// A response to `question` carrying `answers` in the order given.
   fn dns_response(question: &str, answers: &[FixtureRecord<'_>]) -> Vec<u8> {
      let mut msg = vec![0u8; 12];
      msg[0..2].copy_from_slice(&DNS_ID.to_be_bytes());
      msg[2] = 0x81; // QR set, recursion desired
      msg[3] = 0x80; // recursion available
      msg[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount
      msg[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
      msg.extend_from_slice(&labels(question));
      msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
      msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
      for answer in answers {
         msg.extend_from_slice(&labels(answer.owner));
         msg.extend_from_slice(&answer.kind.to_be_bytes());
         msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
         msg.extend_from_slice(&300u32.to_be_bytes()); // TTL
         msg.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
         msg.extend_from_slice(&answer.rdata);
      }
      msg
   }

   /// The address may belong to a CNAME target, but the prompt must offer the name the
   /// application actually asked for, however many hops and cycles the chain has; a chain
   /// with no address record behind it must not invent an address mapping.
   #[test]
   fn a_cname_chain_is_walked_back_to_the_queried_name() {
      for (question, answers, answer, expected, detail) in [
         (
            "www.example.com",
            vec![
               cname_record("www.example.com", "cdn.example.net"),
               address_record("cdn.example.net", [93, 184, 216, 34]),
            ],
            Some([93, 184, 216, 34]),
            Some("www.example.com"),
            Some("cdn.example.net"),
         ),
         // A two-hop chain must walk every edge, not just the last one.
         (
            "a.example",
            vec![
               cname_record("a.example", "b.example"),
               cname_record("b.example", "c.example"),
               address_record("c.example", [93, 184, 216, 35]),
            ],
            Some([93, 184, 216, 35]),
            Some("a.example"),
            None,
         ),
         // A cycle must terminate and still cache the address under a stable name.
         (
            "x.example",
            vec![
               cname_record("x.example", "y.example"),
               cname_record("y.example", "x.example"),
               address_record("y.example", [93, 184, 216, 36]),
            ],
            Some([93, 184, 216, 36]),
            Some("x.example"),
            None,
         ),
         (
            "www.example.com",
            vec![cname_record("www.example.com", "cdn.example.net")],
            None,
            None,
            None,
         ),
      ] {
         let dns = dns_response(question, &answers);
         let packet = ipv4_packet(17, &udp_datagram(&dns), 0);

         let cache = Mutex::new(DnsCache::new());
         cache_answer(&cache, &packet);
         let Some(answer) = answer else {
            assert!(
               cache.lock().expect("dns cache").is_empty(),
               "a name alone is not an address mapping"
            );
            continue;
         };
         let addr = IpAddr::V4(std::net::Ipv4Addr::from(answer));
         let now = now_secs();
         assert_eq!(
            cache.lock().expect("dns cache").primary(addr, now),
            expected,
            "the queried name is what the prompt displays for {question}"
         );
         if let Some(detail) = detail {
            assert!(
               cache.lock().expect("dns cache").names_for(addr, now).contains(&detail),
               "the CNAME target stays available as detail"
            );
         }

         // The walk stops at the repeated name, so the same answer always lands on the same
         // root instead of ping-ponging between the owners.
         cache_answer(&cache, &packet);
         assert_eq!(
            cache.lock().expect("dns cache").primary(addr, now),
            expected,
            "a repeated answer lands on the same name for {question}"
         );
      }
   }

   /// An IPv4 packet with `options` bytes of IP options and `proto` as its transport.
   fn ipv4_packet(proto: u8, transport: &[u8], options: usize) -> Vec<u8> {
      assert_eq!(
         options % 4,
         0,
         "IP options are padded to 32-bit words"
      );
      let header = 20 + options;
      let total = header + transport.len();
      let mut bytes = vec![0u8; header];
      bytes[0] = 0x40 | (header / 4) as u8;
      bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
      bytes[8] = 64;
      bytes[9] = proto;
      bytes[12..16].copy_from_slice(&[192, 0, 2, 53]);
      bytes[16..20].copy_from_slice(&[192, 0, 2, 10]);
      // IP options are padding (option 0, end of list).
      bytes.extend_from_slice(transport);
      bytes
   }

   /// A UDP datagram carrying `dns`, source port 53 to the fixture's client port.
   fn udp_datagram(dns: &[u8]) -> Vec<u8> {
      let mut bytes = vec![0u8; 8];
      bytes[0..2].copy_from_slice(&53u16.to_be_bytes());
      bytes[2..4].copy_from_slice(&CLIENT_PORT.to_be_bytes());
      bytes[4..6].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
      bytes.extend_from_slice(dns);
      bytes
   }

   /// A TCP segment with `data_offset` words of header (`options` fills the rest) that
   /// carries `dns` behind the two-byte length prefix DNS over TCP requires.
   fn tcp_segment(dns: &[u8], data_offset: u8, options: &[u8]) -> Vec<u8> {
      let header = usize::from(data_offset) * 4;
      assert_eq!(header, 20 + options.len());
      let mut bytes = vec![0u8; header];
      bytes[0..2].copy_from_slice(&53u16.to_be_bytes());
      bytes[2..4].copy_from_slice(&CLIENT_PORT.to_be_bytes());
      bytes[12] = data_offset << 4;
      bytes[20..].copy_from_slice(options);
      bytes.extend_from_slice(&(dns.len() as u16).to_be_bytes());
      bytes.extend_from_slice(dns);
      bytes
   }

   fn ipv6_packet(next_header: u8, transport: &[u8]) -> Vec<u8> {
      let mut bytes = vec![0u8; 40];
      bytes[0] = 0x60;
      bytes[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
      bytes[6] = next_header;
      bytes[7] = 64;
      bytes[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53]);
      bytes[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10]);
      bytes.extend_from_slice(transport);
      bytes
   }

   /// The payload must start at the DNS message on both families and both transports, even
   /// with IP options or TCP options in the way; an empty datagram has no payload at all.
   #[test]
   fn transport_payload_finds_the_dns_payload() {
      // The exact case that would have caught the live defect: an IPv4/UDP answer whose
      // payload must start at the DNS message, not at the UDP header.
      let dns = a_record_response();
      let packet = ipv4_packet(17, &udp_datagram(&dns), 0);
      let (body, tcp) = transport_payload(&packet).expect("the UDP payload is found");
      assert!(!tcp, "UDP is not TCP");
      assert_eq!(
         body.get(0..2),
         Some(DNS_ID.to_be_bytes().as_slice()),
         "the payload starts at the DNS transaction id, not the UDP header"
      );
      let records = parse_response(body).expect("the answer parses");
      assert_eq!(records.len(), 1);
      assert_eq!(records[0].name, "example.com");
      assert_eq!(
         records[0].kind,
         netshield_core::dns::RecordKind::A
      );
      assert_eq!(
         records[0].target,
         Target::Address(IpAddr::V4(std::net::Ipv4Addr::from(ANSWER)))
      );

      // And the daemon's own caching path learns the name for that address, which is what
      // a prompt needs to offer a domain scope.
      let cache = Mutex::new(DnsCache::new());
      cache_answer(&cache, &packet);
      let addr = IpAddr::V4(std::net::Ipv4Addr::from(ANSWER));
      assert_eq!(
         cache.lock().expect("dns cache").primary(addr, now_secs()),
         Some("example.com")
      );

      // The same answer over IPv6 reaches the same parser.
      let packet = ipv6_packet(17, &udp_datagram(&dns));
      let (body, tcp) = transport_payload(&packet).expect("the UDP payload is found");
      assert!(!tcp);
      assert_eq!(
         body.get(0..2),
         Some(DNS_ID.to_be_bytes().as_slice())
      );
      let records = parse_response(body).expect("the answer parses");
      assert_eq!(records.len(), 1);
      assert_eq!(
         records[0].target,
         Target::Address(IpAddr::V4(std::net::Ipv4Addr::from(ANSWER)))
      );

      // DNS over TCP behind options: the data offset is honoured, and the two-byte length
      // prefix belongs to the payload.
      let options = [0x01, 0x01, 0x08, 0x0a, 0, 0, 0, 1, 0, 0, 0, 2];
      let segment = tcp_segment(&dns, 8, &options);
      let packet = ipv4_packet(6, &segment, 0);
      let (body, tcp) = transport_payload(&packet).expect("the TCP payload is found");
      assert!(tcp, "the transport is TCP");
      assert_eq!(
         usize::from(u16::from_be_bytes([body[0], body[1]])),
         dns.len(),
         "the two-byte length prefix belongs to the payload"
      );
      let records = parse_tcp_response(body).expect("the TCP answer parses");
      assert_eq!(records.len(), 1);
      assert_eq!(records[0].name, "example.com");

      // Twenty bytes of IP options, so the transport header starts at 40, not 20.
      let packet = ipv4_packet(17, &udp_datagram(&dns), 20);
      assert_eq!(
         packet[0] & 0x0f,
         10,
         "the fixture has a 40-byte IP header"
      );
      let (body, _) = transport_payload(&packet).expect("the payload is found");
      assert_eq!(
         body.get(0..2),
         Some(DNS_ID.to_be_bytes().as_slice())
      );
      assert!(parse_response(body).is_ok());

      // An 8-byte UDP header and nothing behind it is not a payload.
      let packet = ipv4_packet(17, &udp_datagram(&[]), 0);
      assert_eq!(
         packet.len(),
         28,
         "20-byte IP header plus 8-byte UDP header"
      );
      assert!(transport_payload(&packet).is_none());
   }

   #[test]
   fn claimed_lengths_past_the_buffer_are_none() {
      let dns = a_record_response();

      // The IP total length claims bytes the capture does not hold.
      let mut overlong = ipv4_packet(17, &udp_datagram(&dns), 0);
      overlong[2..4].copy_from_slice(&2000u16.to_be_bytes());
      assert!(transport_payload(&overlong).is_none());

      // The IPv6 payload length makes the same claim.
      let mut overlong_v6 = ipv6_packet(17, &udp_datagram(&dns));
      overlong_v6[4..6].copy_from_slice(&2000u16.to_be_bytes());
      assert!(transport_payload(&overlong_v6).is_none());

      // IPv6 with the fixed 40-byte header as the whole datagram: the buffer is shorter
      // than the header it claims.
      let mut truncated_v6 = ipv6_packet(17, &udp_datagram(&dns));
      truncated_v6.truncate(30);
      truncated_v6[4..6].copy_from_slice(&(udp_datagram(&dns).len() as u16).to_be_bytes());
      assert!(transport_payload(&truncated_v6).is_none());

      // A TCP header that claims eight words (32 bytes) while only 24 bytes of segment
      // were captured, so the payload would start past the end of the datagram.
      let segment = tcp_segment(&dns, 8, &[0x01; 12]);
      let mut short_tcp = ipv4_packet(6, &segment[..24], 0);
      short_tcp[20 + 12] = 8 << 4;
      assert!(transport_payload(&short_tcp).is_none());
   }

   #[test]
   fn every_prefix_of_a_valid_packet_is_ok_or_none_and_never_panics() {
      let dns = a_record_response();
      for packet in [
         ipv4_packet(17, &udp_datagram(&dns), 0),
         ipv4_packet(6, &tcp_segment(&dns, 8, &[0x01; 12]), 0),
         ipv6_packet(17, &udp_datagram(&dns)),
      ] {
         for len in 0..=packet.len() {
            if let Some((body, tcp)) = transport_payload(&packet[..len]) {
               assert!(
                  !body.is_empty(),
                  "a returned payload is never empty"
               );
               let _ = if tcp {
                  parse_tcp_response(body)
               } else {
                  parse_response(body)
               };
            }
         }
      }
   }

   /// A connection for `exe` to `remote:port`, attributed to a live process.
   fn app_conn(exe: &str, remote: &str, port: u16) -> Connection {
      let remote: IpAddr = remote.parse().expect("a remote address");
      Connection {
         family: match remote {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
         },
         proto: L4Proto::Tcp,
         local: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 51_234,
         },
         remote: Endpoint { addr: remote, port },
         process: Attribution::Process(netshield_core::connection::ProcessInfo {
            pid: 4242,
            uid: 1000,
            exe: Some(std::path::PathBuf::from(exe)),
            comm: None,
            cmdline: None,
         }),
         domain: None,
         also_domains: Vec::new(),
      }
   }

   /// A session allow rule for the exact executable `exe`, on any destination.
   fn allow_rule_for(exe: &str) -> Rule {
      Rule {
         id: RuleId::new_unique(),
         enabled: true,
         app: AppMatcher::Exe(std::path::PathBuf::from(exe)),
         dest: DestMatcher::Any,
         action: Action::Allow,
         duration: RuleDuration::Session,
         note: None,
         created_at: 1,
         updated_at: 1,
         last_matched: None,
         hits: 0,
      }
   }

   /// An alert-mode policy that prompts for anything no rule decides.
   fn prompting_policy() -> Policy {
      Policy::new(
         netshield_core::RuleSet::new(),
         netshield_core::DefaultAction::Prompt,
      )
   }

   /// A browser opens three destinations and another app opens one; both apps have a live
   /// prompt from the moment they are opened.
   fn queue_two_apps(pending: &mut PendingPrompts, start: Instant) -> (u64, u64) {
      let timeout = Duration::from_secs(30);
      let browser = pending
         .open(
            app_conn("/usr/lib/firefox/firefox", "198.51.100.20", 443),
            10,
            timeout,
            start,
         )
         .id();
      pending.open(
         app_conn("/usr/lib/firefox/firefox", "198.51.100.21", 443),
         11,
         timeout,
         start,
      );
      pending.open(
         app_conn("/usr/lib/firefox/firefox", "198.51.100.22", 443),
         12,
         timeout,
         start,
      );
      let other = pending
         .open(
            app_conn("/usr/bin/curl", "198.51.100.23", 443),
            20,
            timeout,
            start,
         )
         .id();
      (browser, other)
   }

   /// Three apps, three live prompts in arrival order.
   fn queue_three_apps(pending: &mut PendingPrompts, start: Instant) -> (u64, u64, u64) {
      let timeout = Duration::from_secs(30);
      let first = pending
         .open(
            app_conn("/usr/lib/firefox/firefox", "198.51.100.20", 443),
            10,
            timeout,
            start,
         )
         .id();
      let second = pending
         .open(
            app_conn("/usr/bin/curl", "198.51.100.21", 443),
            20,
            timeout,
            start,
         )
         .id();
      let third = pending
         .open(
            app_conn("/usr/bin/wget", "198.51.100.22", 443),
            30,
            timeout,
            start,
         )
         .id();
      (first, second, third)
   }

   /// A new app rule settles every destination of that app's group in one pass, whether or not
   /// it is the oldest prompt, and leaves every other prompt live on its own deadline without
   /// announcing anyone.
   #[test]
   fn an_allow_rule_sweeps_every_decided_group() {
      for with_head in [true, false] {
         let start = Instant::now();
         let mut pending = PendingPrompts::new();
         let head = if with_head {
            Some(
               pending
                  .open(
                     app_conn("/usr/bin/ssh", "198.51.100.24", 22),
                     30,
                     Duration::from_secs(30),
                     start,
                  )
                  .id(),
            )
         } else {
            None
         };
         let (browser, other) = queue_two_apps(&mut pending, start);
         let mut policy = prompting_policy();
         policy.upsert_rule(allow_rule_for("/usr/lib/firefox/firefox"));

         let sweep = sweep_decided(&mut pending, &mut policy, now_secs());

         assert_eq!(
            sweep.swept.iter().map(|swept| swept.record.id).collect::<Vec<_>>(),
            vec![browser],
            "the open browser prompt is settled as a whole, oldest or not"
         );
         assert_eq!(
            sweep.swept[0]
               .record
               .dests
               .iter()
               .flat_map(|dest| dest.packet_ids.iter().copied())
               .collect::<Vec<_>>(),
            vec![10, 11, 12],
            "every destination of the group is answered"
         );
         assert_eq!(
            sweep.swept[0].verdict,
            Verdict::Accept,
            "the rule allows every destination"
         );
         assert_eq!(
            pending.len(),
            if with_head { 2 } else { 1 },
            "no browser prompt is left open"
         );
         assert!(
            pending.get(other).is_some(),
            "the other app is untouched and was already announced when it was opened"
         );
         assert_eq!(
            pending.get(other).expect("open").deadline,
            Some(start + Duration::from_secs(30)),
            "it kept the clock it was opened with"
         );
         assert!(sweep.updated.is_empty());
         assert!(
            pending.get(browser).is_none(),
            "the swept group was removed"
         );

         if let Some(head) = head {
            assert!(
               pending.get(head).is_some(),
               "the prompt being answered is never swept"
            );
            assert!(
               pending.is_active(head),
               "the oldest prompt is listed first"
            );
            // The other app expires on its own clock; nothing ever activated it.
            let expired = pending.expired_all(start + Duration::from_secs(30));
            assert_eq!(
               expired.iter().map(|resolved| resolved.record.id).collect::<Vec<_>>(),
               vec![head, other]
            );
         }
      }
   }

   /// A deny rule drops every destination of the decided group with `Verdict::Drop` and never
   /// touches the other app's prompt, whichever of the two apps the rule names.
   #[test]
   fn a_deny_rule_drops_every_decided_prompt_for_that_app() {
      for (rule_exe, swept_is_browser) in
         [("/usr/lib/firefox/firefox", true), ("/usr/bin/curl", false)]
      {
         let start = Instant::now();
         let mut pending = PendingPrompts::new();
         let (browser, other) = queue_two_apps(&mut pending, start);
         let (expected_swept, survivor) = if swept_is_browser {
            (browser, other)
         } else {
            (other, browser)
         };
         let mut policy = prompting_policy();
         let mut rule = allow_rule_for(rule_exe);
         rule.action = Action::Deny;
         policy.upsert_rule(rule);

         let sweep = sweep_decided(&mut pending, &mut policy, now_secs());

         assert_eq!(
            sweep.swept.iter().map(|swept| swept.record.id).collect::<Vec<_>>(),
            vec![expected_swept],
            "the deny rule for {rule_exe} settles exactly that app's prompt"
         );
         assert_eq!(sweep.swept[0].verdict, Verdict::Drop);
         assert_eq!(sweep.swept[0].resolution, Resolution::Denied);
         assert_eq!(pending.len(), 1);
         assert!(
            pending.get(survivor).is_some(),
            "the other app is untouched"
         );
      }
   }

   #[test]
   fn sweeping_empties_the_set_and_next_ids_stay_monotonic() {
      let start = Instant::now();
      let mut pending = PendingPrompts::new();
      let (_first, _second, third) = queue_three_apps(&mut pending, start);
      let mut policy = prompting_policy();
      policy.upsert_rule(allow_rule_for("/usr/lib/firefox/firefox"));
      policy.upsert_rule(allow_rule_for("/usr/bin/curl"));
      policy.upsert_rule(allow_rule_for("/usr/bin/wget"));

      let sweep = sweep_decided(&mut pending, &mut policy, now_secs());
      assert_eq!(
         sweep.swept.len(),
         3,
         "every open prompt is settled in one pass"
      );
      assert_eq!(pending.len(), 0);
      assert!(pending.is_empty());

      let next = pending
         .open(
            app_conn("/usr/bin/lynx", "198.51.100.24", 443),
            50,
            Duration::from_secs(30),
            start,
         )
         .id();
      assert!(
         next > third,
         "ids are never reused after a sweep emptied the set"
      );
      assert_eq!(pending.len(), 1);
   }

   /// A narrow rule settles the one destination it covers and leaves the rest of the group
   /// on the same prompt for the user.
   #[test]
   fn a_rule_for_one_destination_leaves_the_rest_of_the_group_open() {
      let start = Instant::now();
      let mut pending = PendingPrompts::new();
      let (head, other) = queue_two_apps(&mut pending, start);
      let mut policy = prompting_policy();
      let covered = pending.get(head).expect("open").dests[1].connection.flow_key();
      policy.grant(
         covered,
         Action::Allow,
         now_secs().saturating_add(crate::policy::GRANT_TTL_SECS),
      );

      let sweep = sweep_decided(&mut pending, &mut policy, now_secs());

      assert_eq!(
         sweep.swept.iter().map(|swept| swept.record.id).collect::<Vec<_>>(),
         vec![head],
         "only the destination the once-grant covers is settled"
      );
      assert_eq!(
         sweep.swept[0]
            .record
            .dests
            .iter()
            .flat_map(|dest| dest.packet_ids.iter().copied())
            .collect::<Vec<_>>(),
         vec![11],
         "the settled prompt carries just the covered destination"
      );
      let updated = pending.get(head).expect("the group is still open");
      assert_eq!(
         updated
            .dests
            .iter()
            .flat_map(|dest| dest.packet_ids.iter().copied())
            .collect::<Vec<_>>(),
         vec![10, 12],
         "the prompt keeps the destinations the rule does not cover"
      );
      assert!(
         pending.is_active(head),
         "the shrunk group is still listed first"
      );
      assert_eq!(
         pending.get(head).expect("open").deadline,
         Some(start + Duration::from_secs(30)),
         "the prompt keeps its deadline"
      );
      assert_eq!(sweep.updated.len(), 1);
      assert_eq!(sweep.updated[0].id, head);
      assert_eq!(
         pending.get(other).expect("open").deadline,
         Some(start + Duration::from_secs(30)),
         "the other app is untouched"
      );
   }

   /// A sweep with nothing decided touches nothing at all; the prompts it does decide are
   /// settled in one pass and the survivors are left exactly as they were, on their own clocks.
   #[test]
   fn an_undecided_sweep_changes_nothing() {
      let start = Instant::now();
      let mut pending = PendingPrompts::new();
      let (_head, _other) = queue_two_apps(&mut pending, start);
      let mut policy = prompting_policy();

      let sweep = sweep_decided(&mut pending, &mut policy, now_secs());

      assert!(sweep.swept.is_empty(), "nothing is decided yet");
      assert!(sweep.updated.is_empty());
      assert_eq!(pending.len(), 2);

      // Now something is decided: the decided prompt settles, the undecided survivor is
      // untouched, and no successor has to be announced because it was announced on open.
      let start = Instant::now();
      let mut pending = PendingPrompts::new();
      let (first, second, third) = queue_three_apps(&mut pending, start);
      let mut policy = prompting_policy();
      let second_flow = pending.get(second).expect("open").dests[0].connection.flow_key();
      policy.grant(
         second_flow,
         Action::Allow,
         now_secs().saturating_add(crate::policy::GRANT_TTL_SECS),
      );

      pending.resolve(first).expect("first is open");

      let sweep = sweep_decided(&mut pending, &mut policy, now_secs());

      assert_eq!(
         sweep.swept.iter().map(|swept| swept.record.id).collect::<Vec<_>>(),
         vec![second]
      );
      assert_eq!(pending.len(), 1);
      assert!(
         pending.is_active(third),
         "the survivor is still live"
      );
      assert_eq!(
         pending.get(third).expect("open").deadline,
         Some(start + Duration::from_secs(30)),
         "the survivor keeps the clock it was opened with"
      );
   }

   /// A six-destination group for one app, its first destination carrying a learned name.
   fn six_destination_group() -> (u64, PromptRecord) {
      let start = Instant::now();
      let timeout = Duration::from_secs(30);
      let mut pending = PendingPrompts::new();
      let mut first = app_conn("/usr/lib/firefox/firefox", "198.51.100.20", 443);
      first.domain = Some("api.github.com".to_owned());
      let id = pending.open(first, 10, timeout, start).id();
      for (index, remote) in [
         "198.51.100.21",
         "198.51.100.22",
         "198.51.100.23",
         "198.51.100.24",
         "198.51.100.25",
      ]
      .into_iter()
      .enumerate()
      {
         pending.open(
            app_conn("/usr/lib/firefox/firefox", remote, 443),
            11 + index as u32,
            timeout,
            start,
         );
      }
      let record = pending.resolve(id).expect("open").record;
      (id, record)
   }

   /// `AnyConnection` on a group is the user asking for this app on any destination: exactly
   /// one such rule, regardless of how many destinations the prompt listed.
   #[test]
   fn any_connection_on_a_group_is_one_rule() {
      let (id, record) = six_destination_group();
      let decide = DecideRequest {
         prompt_id: id,
         action: Action::Allow,
         duration: RuleDuration::Forever,
         scope: ScopeChoice::AnyConnection,
      };

      let rules = rules_for(&record, &decide, 100);

      assert_eq!(
         rules.len(),
         1,
         "a group must not multiply an any-scope answer"
      );
      assert_eq!(
         rules[0].app,
         AppMatcher::Exe(PathBuf::from("/usr/lib/firefox/firefox")),
         "the rule is scoped to the group's executable"
      );
      assert_eq!(
         rules[0].dest,
         DestMatcher::Any,
         "the user's any-connection scope is the rule's destination"
      );
   }

   /// `TheseDestinations` is the old group behaviour made explicit: one rule per listed
   /// destination, each scoped to itself, named destination to its own domain.
   #[test]
   fn these_destinations_on_a_group_is_one_rule_each() {
      let (id, record) = six_destination_group();
      let decide = DecideRequest {
         prompt_id: id,
         action: Action::Allow,
         duration: RuleDuration::Forever,
         scope: ScopeChoice::TheseDestinations,
      };

      let rules = rules_for(&record, &decide, 100);

      assert_eq!(rules.len(), 6, "one rule per destination listed");
      assert!(
         rules
            .iter()
            .all(|rule| rule.app == AppMatcher::Exe(PathBuf::from("/usr/lib/firefox/firefox"))),
         "every rule carries the group's executable"
      );
      assert!(
         rules.iter().all(|rule| !matches!(rule.dest, DestMatcher::Any)),
         "these-destinations must never widen to anywhere"
      );
      assert_eq!(
         rules[0].dest,
         DestMatcher::Domain {
            host: "api.github.com".to_owned(),
            subdomains: false,
         },
         "a named destination is scoped to its own domain"
      );
      for (rule, dest) in rules[1..].iter().zip(record.dests[1..].iter()) {
         let DestMatcher::Ip(net) = &rule.dest else {
            panic!(
               "an unnamed destination must be scoped to its own address, got {:?}",
               rule.dest
            );
         };
         assert!(
            net.contains(dest.connection.remote.addr),
            "{net:?} must cover its own destination {}",
            dest.connection.remote.addr
         );
         assert_eq!(
            dest.connection.remote.addr, net.addr,
            "the rule covers exactly its destination, not a wider network"
         );
      }
   }

   /// One destination keeps the exact shape it had before this branch, for every scope.
   #[test]
   fn a_single_destination_still_honours_every_scope() {
      let start = Instant::now();
      let mut connection = app_conn("/usr/lib/firefox/firefox", "198.51.100.20", 443);
      connection.domain = Some("api.github.com".to_owned());
      let mut pending = PendingPrompts::new();
      let id = pending.open(connection, 10, Duration::from_secs(30), start).id();
      let record = pending.resolve(id).expect("open").record;
      let decide = |scope| DecideRequest {
         prompt_id: id,
         action: Action::Allow,
         duration: RuleDuration::Forever,
         scope,
      };

      for (scope, expected) in [
         (ScopeChoice::AnyConnection, DestMatcher::Any),
         (
            ScopeChoice::Domain {
               host: "example.com".to_owned(),
               subdomains: true,
            },
            DestMatcher::Domain {
               host: "example.com".to_owned(),
               subdomains: true,
            },
         ),
         (
            ScopeChoice::Address,
            DestMatcher::Ip("198.51.100.20/32".parse().expect("the destination's own address")),
         ),
         (
            ScopeChoice::TheseDestinations,
            DestMatcher::Domain {
               host: "api.github.com".to_owned(),
               subdomains: false,
            },
         ),
      ] {
         let rules = rules_for(&record, &decide(scope.clone()), 100);
         assert_eq!(
            rules.len(),
            1,
            "scope {scope:?} is one rule for one destination"
         );
         assert_eq!(rules[0].dest, expected, "scope {scope:?}");
         assert_eq!(
            rules[0].app,
            AppMatcher::Exe(PathBuf::from("/usr/lib/firefox/firefox"))
         );
      }
   }

   /// Answering the same group with the same scope twice refreshes the one rule instead of
   /// adding a second, a disabled equivalent is re-enabled rather than shadowed, and the same
   /// app answered for another address is a different destination whose rule list must grow.
   #[test]
   fn an_answer_refreshes_an_identical_rule_or_creates_a_new_one() {
      // The same group, same scope: the second answer is an update of the one rule.
      let (id, record) = six_destination_group();
      let decide = DecideRequest {
         prompt_id: id,
         action: Action::Allow,
         duration: RuleDuration::Forever,
         scope: ScopeChoice::AnyConnection,
      };
      let mut policy = prompting_policy();

      let first = rules_for(&record, &decide, 100);
      assert_eq!(first.len(), 1);
      assert_eq!(policy.apply(first[0].clone()).1, Applied::Created);

      let second = rules_for(&record, &decide, 200);
      let (stored, applied) = policy.apply(second[0].clone());

      assert_eq!(
         applied,
         Applied::Refreshed,
         "the second answer is an update"
      );
      assert_eq!(
         policy.ruleset().len(),
         1,
         "no second rule is added"
      );
      assert_eq!(
         stored.id, first[0].id,
         "the incumbent keeps its id"
      );
      assert_eq!(stored.created_at, 100);
      assert_eq!(
         stored.updated_at, 200,
         "the refresh stamps the rule"
      );

      // A disabled equivalent is re-enabled by the next answer rather than shadowed by a new
      // rule the user would have to find and toggle.
      let mut policy = prompting_policy();
      let mut disabled = rules_for(&record, &decide, 100).remove(0);
      disabled.enabled = false;
      policy.upsert_rule(disabled);

      let (stored, applied) = policy.apply(rules_for(&record, &decide, 200).remove(0));

      assert_eq!(applied, Applied::Refreshed);
      assert_eq!(policy.ruleset().len(), 1);
      assert!(
         stored.enabled,
         "the refreshed rule is enabled again"
      );
      assert_eq!(stored.updated_at, 200);

      // The same app answered for another address is a different destination, not a
      // duplicate: the rule list must grow.
      let decide = || DecideRequest {
         prompt_id: 1,
         action: Action::Allow,
         duration: RuleDuration::Forever,
         scope: ScopeChoice::Address,
      };
      let mut policy = prompting_policy();
      let first = rule_for(
         &app_conn("/usr/lib/firefox/firefox", "198.51.100.20", 443),
         &decide(),
         100,
      );
      let second = rule_for(
         &app_conn("/usr/lib/firefox/firefox", "198.51.100.21", 443),
         &decide(),
         200,
      );

      assert_eq!(policy.apply(first).1, Applied::Created);
      assert_eq!(policy.apply(second).1, Applied::Created);
      assert_eq!(
         policy.ruleset().len(),
         2,
         "another address is another rule"
      );
   }

   /// A rule revokes the executable it names, and nothing wider.
   #[test]
   fn a_rule_revokes_the_app_it_names() {
      assert_eq!(
         rule_revoke(&allow_rule_for("/usr/lib/firefox/firefox")),
         Revoke::Exe(std::path::PathBuf::from(
            "/usr/lib/firefox/firefox"
         ))
      );

      // An any rule is not scoped to a process at all, so it revokes everything.
      let mut rule = allow_rule_for("/usr/bin/curl");
      rule.app = AppMatcher::Any;
      assert_eq!(rule_revoke(&rule), Revoke::All);

      // An unknown owner names nothing to revoke.
      let mut rule = allow_rule_for("/usr/bin/curl");
      rule.app = AppMatcher::Unknown;
      assert_eq!(rule_revoke(&rule), Revoke::Nothing);
   }

   /// A deny upsert is the only upsert that revokes; an allow leaves running traffic alone.
   #[test]
   fn an_upserting_decision_revokes_only_on_deny() {
      let allow = allow_rule_for("/usr/lib/firefox/firefox");
      let mut deny = allow.clone();
      deny.action = Action::Deny;

      assert_eq!(upsert_revoke(&allow), Revoke::Nothing);
      assert_eq!(
         upsert_revoke(&deny),
         Revoke::Exe(std::path::PathBuf::from(
            "/usr/lib/firefox/firefox"
         ))
      );
   }
}
