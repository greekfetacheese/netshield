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

use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};
use netshield_core::config::Config;
use netshield_core::connection::{Attribution, Connection, Endpoint, L4Proto};
use netshield_core::dns::{DnsRecord, Target, parse_response, parse_tcp_response};
use netshield_core::dns_cache::DnsCache;
use netshield_core::ipc::{
   ConnectionEvent, ConnectionView, DecideRequest, Mode, PromptRequest, Request, Resolution,
   Response, ScopeChoice, StatusInfo,
};
use netshield_core::packet::{L4Payload, ParsedPacket, parse};
use netshield_core::rule::{Action, AppMatcher, Duration as RuleDuration, Rule, RuleId};
use netshield_core::{DestMatcher, ScopeRequest, rule_from_scope};

use crate::firewall::{self, FirewallError};
use crate::ipc_server::{self, IpcError, IpcHandle, IpcServer};
use crate::netlink::nfqueue::{NfQueue, NfqError, Packet, Verdict};
use crate::pending::PendingPrompts;
use crate::policy::{Decision, Policy};
use crate::proc::Attributor;
use crate::store::{RuleStore, StoreError};

/// How long a queue receive may block before the loop checks deadlines and signals.
const RECV_TIMEOUT: Duration = Duration::from_millis(200);

/// Minimum gap between attempts to spawn the GUI, so a crash-looping binary cannot turn
/// into a fork bomb.
const GUI_SPAWN_COOLDOWN: Duration = Duration::from_secs(30);

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

/// Brings the nftables table up: adopt, replace or install.
fn adopt_or_install(config: &Config) -> Result<(), DaemonError> {
   // Verify is the only reliable existence check: it fails both when the table is absent
   // and when it exists but is not the table this configuration describes.
   if firewall::verify(config.queue_num, config.dns_queue_num).is_ok() {
      info!(
         "adopting the installed table inet {} (queues {}/{})",
         firewall::TABLE,
         config.queue_num,
         config.dns_queue_num
      );
      return Ok(());
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
   Ok(())
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
   last_gui_spawn: Option<Instant>,
   silent_warned: bool,
}

impl Daemon {
   /// Builds the daemon around the already-open connection queue.
   fn start(
      config: Config,
      store: RuleStore,
      ipc: IpcHandle,
      queue: NfQueue,
      dns_cache: Arc<Mutex<DnsCache>>,
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
         last_gui_spawn: None,
         silent_warned: false,
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
         fail_open: false,
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
   adopt_or_install(&config)?;

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

   let mut daemon = Daemon::start(config, store, ipc, queue, cache);
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
      let Some(record) = self.pending.resolve(decide.prompt_id) else {
         debug!(
            "decision for prompt {} which is no longer open",
            decide.prompt_id
         );
         return;
      };

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
      self.publish_status();
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
      let view = self.view(connection);
      self.ipc.broadcast(&Response::Prompt(PromptRequest {
         id,
         connection: view,
         timeout_secs: self.config.prompt_timeout_secs,
         domain_scope_available: connection.domain.is_some(),
         pending: self.pending.len().saturating_sub(1),
      }));
      info!(
         "prompt {id} for {} -> {}:{} ({} packet(s) held)",
         connection.app_name(),
         connection.remote.addr,
         connection.remote.port,
         self.pending.len()
      );

      if !self.ipc.is_subscribed() {
         self.spawn_gui();
      }
      self.publish_status();
   }

   /// Tries to launch the GUI in alert mode, at most once per cooldown.
   fn spawn_gui(&mut self) {
      let Some(path) = self.config.gui_path.clone() else {
         return;
      };
      if self.last_gui_spawn.is_some_and(|at| at.elapsed() < GUI_SPAWN_COOLDOWN) {
         return;
      }
      self.last_gui_spawn = Some(Instant::now());

      match Command::new(&path).arg("--alert").spawn() {
         Ok(child) => info!(
            "spawned {} --alert (pid {})",
            path.display(),
            child.id()
         ),
         Err(err) => warn!(
            "could not spawn the GUI at {}: {err}",
            path.display()
         ),
      }
   }

   /// Times out expired prompts, expires grants and prunes the DNS cache.
   fn sweep(&mut self, now: Instant) {
      let expired = self.pending.expired(now);
      for record in &expired {
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
      }

      let epoch = now_secs();
      let removed = self.policy.expire_grants(epoch);
      if removed > 0 {
         debug!("expired {removed} flow grant(s)");
      }
      self.dns_cache.lock().expect("dns cache").expire(epoch);

      if !expired.is_empty() {
         self.publish_status();
      }
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
   fn domain_for(&self, addr: IpAddr) -> Option<String> {
      self
         .dns_cache
         .lock()
         .expect("dns cache")
         .primary(addr, now_secs())
         .map(str::to_owned)
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
   };
   let scope = ScopeRequest {
      action: decide.action,
      duration: decide.duration,
      dest,
   };
   rule_from_scope(RuleId::new_unique(), app, &scope, now)
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

/// Parses one DNS answer and inserts every usable record into the cache.
fn cache_answer(cache: &Mutex<DnsCache>, payload: &[u8]) {
   let Some((body, tcp)) = transport_payload(payload) else {
      debug!("DNS payload has no TCP/UDP transport; ignoring it");
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
         debug!("DNS answer could not be parsed: {err:?}");
         return;
      }
   };

   let now = now_secs();
   let mut cache = cache.lock().expect("dns cache");
   for record in records {
      if let Target::Address(addr) = record.target {
         cache.insert(addr, &record.name, record.ttl, now);
      }
   }
}

/// The transport payload of one captured IP packet, and whether it is TCP.
///
/// `packet::parse` reports the addresses and ports but not where the transport payload
/// starts, and the DNS parsers need exactly those bytes; a DNS message read from the start
/// of the IP header would decode the IP header as a DNS header. Every offset is checked,
/// so a truncated or hostile datagram yields `None` rather than a panic.
fn transport_payload(payload: &[u8]) -> Option<(&[u8], bool)> {
   let first = *payload.first()?;
   let (start, end, proto) = match first >> 4 {
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

   let body = payload.get(start..end)?;
   match proto {
      6 => Some((body, true)),
      17 => Some((body, false)),
      _ => None,
   }
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
}
