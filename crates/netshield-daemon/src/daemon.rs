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

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};
use netshield_core::config::Config;
use netshield_core::connection::{Attribution, Connection, Endpoint, L4Proto};
use netshield_core::dns::{DnsRecord, RecordKind, Target, parse_response, parse_tcp_response};
use netshield_core::dns_cache::DnsCache;
use netshield_core::ipc::{
   ConnectionEvent, ConnectionView, DecideRequest, Mode, PromptRequest, Request, Resolution,
   Response, ScopeChoice, StatusInfo,
};
use netshield_core::packet::{L4Payload, ParsedPacket, parse};
use netshield_core::rule::{Action, AppMatcher, Duration as RuleDuration, Rule, RuleId};
use netshield_core::{DestMatcher, IpNet, ScopeRequest, rule_from_scope};

use crate::firewall::{self, FirewallError};
use crate::ipc_server::{self, IpcError, IpcHandle, IpcServer};
use crate::netlink::nfqueue::{NfQueue, NfqError, Packet, Verdict};
use crate::pending::{PendingPrompts, PromptRecord};
use crate::policy::{Decision, Policy};
use crate::proc::Attributor;
use crate::store::{RuleStore, StoreError};

/// How long a queue receive may block before the loop checks deadlines and signals.
const RECV_TIMEOUT: Duration = Duration::from_millis(200);

/// Minimum gap between `dns: no name` debug lines for one address.
const DNS_MISS_LOG_GAP: Duration = Duration::from_secs(1);

/// Upper bound on the addresses the DNS miss limiter remembers.
const DNS_MISS_LIMIT: usize = 1024;

/// Why the daemon or `--check` could not run.
#[derive(Debug)]
pub enum DaemonError {
   Store(StoreError),
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
         Self::Store(err) => write!(f, "{err}"),
         Self::Firewall(err) => write!(f, "{err}"),
         Self::Ipc(err) => write!(f, "{err}"),
         Self::Queue { queue, reason } => write!(f, "NFQUEUE {queue}: {reason}"),
         Self::Thread(err) => write!(f, "could not start a daemon thread: {err}"),
      }
   }
}

impl std::error::Error for DaemonError {}

impl From<StoreError> for DaemonError {
   fn from(err: StoreError) -> Self {
      Self::Store(err)
   }
}

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
   if firewall::verify(config.queue_num, config.dns_queue_num).is_ok() {
      info!(
         "adopting the installed table inet {} (queues {}/{})",
         firewall::TABLE,
         config.queue_num,
         config.dns_queue_num
      );
      return Ok(true);
   }

   info!(
      "table inet {} is absent or does not verify; installing it",
      firewall::TABLE
   );
   firewall::install(
      config.queue_num,
      config.dns_queue_num,
      false,
      true,
   )?;
   firewall::verify(config.queue_num, config.dns_queue_num)?;
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
   dns_misses: MissLimiter,
}

impl Daemon {
   /// Builds the daemon around the already-open connection queue.
   fn start(
      config: Config,
      store: RuleStore,
      ipc: IpcHandle,
      queue: NfQueue,
      dns_cache: Arc<Mutex<DnsCache>>,
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
         attributor: Attributor::new(),
         ipc,
         queue,
         mode: Mode::Alert,
         started_at,
         queue_drops: 0,
         silent_warned: false,
         table_verified,
         dns_misses: MissLimiter::new(),
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
         started_at: self.started_at,
      }
   }
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

   let (store, _seeded) = RuleStore::load_or_seed(&config.rules_path)?;
   info!(
      "loaded {} rule(s) from {}",
      store.rules().len(),
      config.rules_path.display()
   );
   let table_verified = adopt_or_install(&config)?;

   let (ipc, queue, dns_queue) = match start_runtime(&config) {
      Ok(started) => started,
      Err(err) => {
         remove_table_quietly();
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
      remove_table_quietly();
      if let Err(remove_err) = ipc_server::remove_socket_file(&config.socket_path) {
         warn!("could not remove the control socket at startup failure: {remove_err}");
      }
      return Err(err);
   }

   let mut daemon = Daemon::start(config, store, ipc, queue, cache, table_verified);
   daemon.publish_rules();
   daemon.publish_status();
   info!(
      "netshieldd running: queue {} for flows, queue {} for DNS, control {}",
      daemon.config.queue_num,
      daemon.config.dns_queue_num,
      daemon.config.socket_path.display()
   );

   daemon.tick_loop();

   let socket_path = daemon.config.socket_path.clone();
   if let Err(err) = firewall::remove() {
      error!(
         "could not remove table inet {} at shutdown: {err}",
         firewall::TABLE
      );
   } else {
      info!(
         "removed table inet {} at shutdown",
         firewall::TABLE
      );
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
   let server = IpcServer::bind(&config.socket_path, config.allowed_uid)?;
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
fn remove_table_quietly() {
   if let Err(err) = firewall::remove() {
      error!(
         "could not roll back table inet {} after a startup failure: {err}",
         firewall::TABLE
      );
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

         self.sweep(Instant::now());
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
      match self.mode {
         Mode::Silent => {
            if !self.silent_warned {
               self.silent_warned = true;
               warn!("silent mode: unmatched connections are now allowed without prompting");
            }
            // Prompts already on screen are answered by the mode switch rather than left
            // to time out and deny a connection the user has just stopped being asked
            // about.
            for record in self.pending.take_all() {
               if let Err(err) = self.answer_packets(&record.packet_ids, Verdict::Accept) {
                  warn!(
                     "could not release prompt {}'s packets: {err}",
                     record.id
                  );
               }
               self.ipc.broadcast(&Response::PromptClosed {
                  id: record.id,
                  resolution: Resolution::SilentAutoAllowed,
               });
               self.broadcast_connection(&record.connection, Action::Allow, None, true);
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
            self.policy.upsert_rule(rule.clone());
            if let Err(err) = self.store.upsert(rule) {
               error!("could not persist a rule from the control socket: {err}");
            }
            self.publish_rules();
            self.publish_status();
         }
         Request::DeleteRule { id } => {
            match self.store.remove(&id) {
               Ok(true) => info!("deleted rule {}", id),
               Ok(false) => debug!("delete for unknown rule {}", id),
               Err(err) => error!("could not persist the deletion of rule {id}: {err}"),
            }
            self.policy.remove_rule(&id);
            self.publish_rules();
            self.publish_status();
         }
         Request::SetRuleEnabled { id, enabled } => {
            if let Some(mut rule) = self.policy.ruleset().get(&id).cloned() {
               rule.enabled = enabled;
               rule.updated_at = now_secs();
               self.policy.upsert_rule(rule.clone());
               if let Err(err) = self.store.upsert(rule) {
                  error!("could not persist a rule toggle from the control socket: {err}");
               }
               self.publish_rules();
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
   fn decide(&mut self, _client: u64, decide: DecideRequest) {
      let Some(resolved) = self.pending.resolve(decide.prompt_id, Instant::now()) else {
         // A GUI click can arrive after the prompt expired; the user believes a rule was
         // created, so the discarded choice must be visible at the operator's log level.
         warn!(
            "prompt {} is no longer open; discarding the decision and creating no rule",
            decide.prompt_id
         );
         return;
      };
      let record = resolved.record;

      let verdict = match decide.action {
         Action::Allow => Verdict::Accept,
         Action::Deny => Verdict::Drop,
      };
      if let Err(err) = self.answer_packets(&record.packet_ids, verdict) {
         warn!(
            "could not answer prompt {}'s packets: {err}",
            record.id
         );
      }

      let now = now_secs();
      match decide.duration {
         RuleDuration::Once => {
            self.policy.grant(
               record.connection.flow_key(),
               decide.action,
               now.saturating_add(crate::policy::GRANT_TTL_SECS),
            );
         }
         RuleDuration::Session => {
            let rule = rule_for(&record.connection, &decide, now);
            self.policy.upsert_rule(rule);
            self.publish_rules();
         }
         RuleDuration::Forever => {
            let rule = rule_for(&record.connection, &decide, now);
            self.policy.upsert_rule(rule.clone());
            if let Err(err) = self.store.upsert(rule) {
               error!("could not persist a forever rule: {err}");
            }
            self.publish_rules();
         }
      }

      let resolution = match decide.action {
         Action::Allow => Resolution::Allowed,
         Action::Deny => Resolution::Denied,
      };
      self.ipc.broadcast(&Response::PromptClosed {
         id: record.id,
         resolution,
      });
      self.broadcast_connection(&record.connection, decide.action, None, true);
      if let Some(next) = resolved.activated {
         self.announce_prompt(&next);
      }
      self.publish_status();
   }

   /// Makes an activated prompt visible: broadcasts it with the number of prompts still
   /// queued behind it, and repeats the timeout warning when no client is attached.
   fn announce_prompt(&mut self, record: &PromptRecord) {
      let timeout_secs = self.config.prompt_timeout_secs;
      let pending = self.pending.queued_behind(record.id);
      self.ipc.broadcast(&Response::Prompt(PromptRequest {
         id: record.id,
         connection: self.view(&record.connection),
         timeout_secs,
         domain_scope_available: record.connection.domain.is_some(),
         pending,
      }));
      info!(
         "prompt {} for {} -> {}:{} ({} packet(s) held, {} queued)",
         record.id,
         record.connection.app_name(),
         record.connection.remote.addr,
         record.connection.remote.port,
         record.packet_ids.len(),
         pending
      );

      if !self.ipc.is_subscribed() {
         let dest = format!(
            "{}:{}",
            record.connection.remote.addr, record.connection.remote.port
         );
         warn!(
            "{}",
            missing_client_warning(
               record.id,
               &record.connection.app_name(),
               &dest,
               timeout_secs,
            )
         );
      }
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

      let Some(connection) = self.connection_for(&parsed, &packet) else {
         // Not a flow the policy governs (ICMP, an unknown transport, a family mismatch);
         // accept rather than invent a decision for a packet the model cannot express.
         self.accept(packet.id);
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
         None => self.prompt(&connection, packet.id),
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
      let id = self.pending.open(
         connection.clone(),
         packet_id,
         timeout,
         Instant::now(),
      );
      // Only the head is on screen; a prompt queued behind it waits without a deadline and
      // is broadcast when it is activated, so it gets its full timeout while visible.
      if self.pending.is_active(id) {
         let record = self.pending.get(id).expect("just opened").clone();
         self.announce_prompt(&record);
      } else {
         debug!(
            "prompt {id} for {} -> {}:{} queued behind an open prompt",
            connection.app_name(),
            connection.remote.addr,
            connection.remote.port
         );
      }
      self.publish_status();
   }

   /// Times out the active prompt, expires grants and prunes the DNS cache.
   fn sweep(&mut self, now: Instant) {
      let expired = self.pending.expired(now);
      if let Some(resolved) = expired {
         let record = resolved.record;
         if let Err(err) = self.answer_packets(&record.packet_ids, Verdict::Drop) {
            warn!(
               "could not deny prompt {}'s packets: {err}",
               record.id
            );
         }
         warn!(
            "prompt {} timed out after {}s; denied {} from {} to {}:{}",
            record.id,
            self.config.prompt_timeout_secs,
            record.connection.app_name(),
            record.connection.local.addr,
            record.connection.remote.addr,
            record.connection.remote.port
         );
         self.ipc.broadcast(&Response::PromptClosed {
            id: record.id,
            resolution: Resolution::TimedOut,
         });
         self.broadcast_connection(&record.connection, Action::Deny, None, true);
         if let Some(next) = resolved.activated {
            self.announce_prompt(&next);
         }
         self.publish_status();
      }

      let epoch = now_secs();
      let removed = self.policy.expire_grants(epoch);
      if removed > 0 {
         debug!("expired {removed} flow grant(s)");
      }
      self.dns_cache.lock().expect("dns cache").expire(epoch);
   }

   /// Builds the [`Connection`] for a parsed packet, or `None` when the transport has no
   /// endpoints to govern.
   fn connection_for(&mut self, parsed: &ParsedPacket, packet: &Packet) -> Option<Connection> {
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
      let process = self.attributor.attribute(
         (local.addr, local.port),
         (remote.addr, remote.port),
         proto,
         packet.uid,
      );

      Some(Connection {
         family: parsed.family,
         proto,
         local,
         remote,
         process,
         domain: self.domain_for(remote.addr),
      })
   }

   /// The name the DNS cache learned for `addr`, if one is still live.
   ///
   /// A miss is logged at most once per [`DNS_MISS_LOG_GAP`] per address: a busy machine
   /// looks up a lot of uncached addresses, and each line would otherwise flood the
   /// journal. Hits are never logged.
   fn domain_for(&mut self, addr: IpAddr) -> Option<String> {
      let name = self
         .dns_cache
         .lock()
         .expect("dns cache")
         .primary(addr, now_secs())
         .map(str::to_owned);
      if name.is_none() && self.dns_misses.record(addr, Instant::now()) {
         debug!("dns: no name for {addr}");
      }
      name
   }

   /// A display snapshot of one connection.
   fn view(&self, connection: &Connection) -> ConnectionView {
      let candidates = self.domain_candidates(connection);
      ConnectionView::from_connection(connection, &candidates)
   }

   fn domain_candidates(&self, connection: &Connection) -> Vec<String> {
      let cache = self.dns_cache.lock().expect("dns cache");
      cache
         .names_for(connection.remote.addr, now_secs())
         .into_iter()
         .map(str::to_owned)
         .collect()
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

/// Remembers when each address last missed the DNS cache, so the miss debug line stays
/// cheap on a machine that resolves many addresses the cache never saw.
struct MissLimiter {
   last: HashMap<IpAddr, Instant>,
}

impl MissLimiter {
   fn new() -> Self {
      Self {
         last: HashMap::new(),
      }
   }

   /// Whether a miss for `addr` at `now` should be logged. The entry is added or refreshed
   /// only when it is, so a repeatedly missing address costs one hash lookup per second.
   fn record(&mut self, addr: IpAddr, now: Instant) -> bool {
      if let Some(at) = self.last.get(&addr) {
         if now.duration_since(*at) < DNS_MISS_LOG_GAP {
            return false;
         }
      } else if self.last.len() >= DNS_MISS_LIMIT {
         self.last.retain(|_, at| now.duration_since(*at) < DNS_MISS_LOG_GAP);
         if self.last.len() >= DNS_MISS_LIMIT {
            return false;
         }
      }
      self.last.insert(addr, now);
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

/// Builds the rule a prompt's answer creates.
fn rule_for(connection: &Connection, decide: &DecideRequest, now: u64) -> Rule {
   let app = match &connection.process {
      Attribution::Process(process) => match process.exe.clone() {
         Some(path) => AppMatcher::Exe(path),
         None => AppMatcher::Any,
      },
      Attribution::Unknown => AppMatcher::Unknown,
   };
   let dest = match &decide.scope {
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
   };
   let scope = ScopeRequest {
      action: decide.action,
      duration: decide.duration,
      dest,
   };
   rule_from_scope(RuleId::new_unique(), app, &scope, now)
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

   let (store, seeded) = RuleStore::load_or_seed(&config.rules_path)?;
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

   let removed = firewall::remove();
   match (queues, removed) {
      (Ok(_), Ok(())) => {
         println!(
            "netshieldd --check: table inet {} verified (queues {}/{}), {} rule(s) loaded{}, \
             DNS queue open; table removed",
            firewall::TABLE,
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
         error!(
            "--check could not remove table inet {}: {remove_err}",
            firewall::TABLE
         );
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
   fn a_prompt_with_no_client_warns_and_names_the_denial_timeout() {
      assert_eq!(
         missing_client_warning(7, "firefox", "198.51.100.20:443", 30),
         "no GUI is connected; prompt 7 for firefox -> 198.51.100.20:443 will be denied in \
          30s unless a GUI attaches"
      );
   }

   #[test]
   fn signals_set_the_shutdown_flag() {
      SHUTDOWN.store(false, Ordering::SeqCst);
      on_shutdown_signal(libc::SIGTERM);
      assert!(SHUTDOWN.load(Ordering::SeqCst));
      SHUTDOWN.store(false, Ordering::SeqCst);
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

   /// The live CDN shape: the address belongs to the CNAME target, but the prompt must
   /// offer the name the application actually asked for.
   #[test]
   fn a_cname_chain_reports_the_queried_name_as_primary() {
      let dns = dns_response(
         "www.example.com",
         &[
            cname_record("www.example.com", "cdn.example.net"),
            address_record("cdn.example.net", [93, 184, 216, 34]),
         ],
      );
      let packet = ipv4_packet(17, &udp_datagram(&dns), 0);

      let cache = Mutex::new(DnsCache::new());
      cache_answer(&cache, &packet);
      let addr = IpAddr::V4(std::net::Ipv4Addr::from([93, 184, 216, 34]));
      let cache = cache.lock().expect("dns cache");
      let now = now_secs();
      assert_eq!(
         cache.primary(addr, now),
         Some("www.example.com"),
         "the queried name is what the prompt displays"
      );
      assert!(
         cache.names_for(addr, now).contains(&"cdn.example.net"),
         "the CNAME target stays available as detail"
      );
   }

   /// A two-hop chain must walk every edge, not just the last one.
   #[test]
   fn a_two_hop_cname_chain_resolves_to_the_first_owner() {
      let dns = dns_response(
         "a.example",
         &[
            cname_record("a.example", "b.example"),
            cname_record("b.example", "c.example"),
            address_record("c.example", [93, 184, 216, 35]),
         ],
      );
      let packet = ipv4_packet(17, &udp_datagram(&dns), 0);

      let cache = Mutex::new(DnsCache::new());
      cache_answer(&cache, &packet);
      let addr = IpAddr::V4(std::net::Ipv4Addr::from([93, 184, 216, 35]));
      assert_eq!(
         cache.lock().expect("dns cache").primary(addr, now_secs()),
         Some("a.example")
      );
   }

   /// A cycle must terminate and still cache the address under a stable name.
   #[test]
   fn a_cname_cycle_terminates_and_caches_a_stable_name() {
      let dns = dns_response(
         "x.example",
         &[
            cname_record("x.example", "y.example"),
            cname_record("y.example", "x.example"),
            address_record("y.example", [93, 184, 216, 36]),
         ],
      );
      let packet = ipv4_packet(17, &udp_datagram(&dns), 0);

      let cache = Mutex::new(DnsCache::new());
      cache_answer(&cache, &packet);
      let addr = IpAddr::V4(std::net::Ipv4Addr::from([93, 184, 216, 36]));
      let now = now_secs();
      assert_eq!(
         cache.lock().expect("dns cache").primary(addr, now),
         Some("x.example")
      );

      // The walk stops at the repeated name, so the same answer always lands on the same
      // root instead of ping-ponging between the two owners.
      cache_answer(&cache, &packet);
      assert_eq!(
         cache.lock().expect("dns cache").primary(addr, now),
         Some("x.example")
      );
   }

   /// A CNAME with no address record behind it must not invent an address mapping.
   #[test]
   fn a_cname_without_an_address_record_caches_nothing() {
      let dns = dns_response(
         "www.example.com",
         &[cname_record("www.example.com", "cdn.example.net")],
      );
      let packet = ipv4_packet(17, &udp_datagram(&dns), 0);

      let cache = Mutex::new(DnsCache::new());
      cache_answer(&cache, &packet);
      assert!(
         cache.lock().expect("dns cache").is_empty(),
         "a name alone is not an address mapping"
      );
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

   /// The exact test that would have caught the live defect: an IPv4/UDP answer whose
   /// payload must start at the DNS message, not at the UDP header.
   #[test]
   fn ipv4_udp_dns_answer_reaches_the_parser_and_the_cache() {
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
   }

   #[test]
   fn ipv6_udp_dns_answer_reaches_the_parser() {
      let dns = a_record_response();
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
   }

   #[test]
   fn tcp_data_offset_is_honoured_with_options_present() {
      let dns = a_record_response();
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
   }

   #[test]
   fn a_non_zero_ipv4_ihl_still_finds_the_payload() {
      let dns = a_record_response();
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
   }

   #[test]
   fn a_udp_datagram_without_payload_is_none() {
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
}
