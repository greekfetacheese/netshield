//! Process attribution: a queued packet's 4-tuple to the process that owns the socket.
//!
//! The path is the one ARCHITECTURE §5 specifies: match the flow in `/proc/net/{tcp,udp}`
//! to get the socket inode, then scan `/proc/<pid>/fd` for `socket:[<inode>]`. The first
//! step is a text parse, so the address decoders below are the part most likely to be
//! subtly wrong — `/proc` prints IPv4 as one little-endian word and IPv6 as four of them,
//! while ports are plain big-endian hex. Fixtures copied from real kernel output pin both
//! decoders down, because a decoder bug presents as "every lookup misses", not as an error.
//!
//! Attribution is allowed to fail and must then say so: a vanished process, a socket that
//! changed hands or a scan that hit its budget all become [`Attribution::Unknown`] and are
//! logged. They are never repaired into a guess, because the rule engine has an explicit
//! `Unknown` matcher and a guessed owner could inherit another application's allow.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant, SystemTime};

use log::{debug, warn};
use netshield_core::{Attribution, Family, L4Proto, ProcessInfo};

/// How long an inode→pid, pid→fd or flow→owner answer may be reused.
///
/// Short on purpose: inodes and port tuples are recycled as soon as a socket closes, so a
/// longer TTL could attribute a new socket to the previous owner. One second still
/// collapses the burst of per-packet lookups a single connection produces.
const CACHE_TTL: StdDuration = StdDuration::from_secs(1);

/// How long a flow that just missed stays marked so its next packets do not rescan.
///
/// Deliberately shorter than [`CACHE_TTL`]: a negative answer is cheap for a burst but
/// wrong if the socket appears late, so it expires after one second.
const NEGATIVE_TTL: StdDuration = StdDuration::from_secs(1);

/// Most flow→owner/flow→miss entries kept; a few hundred flows is a desktop session.
const MAX_FLOWS: usize = 512;

/// Consecutive misses for one flow class that make the condition worth a `warn!`.
const MISS_WARN_THRESHOLD: u32 = 5;

/// How long one warned flow class stays quiet.
const MISS_WARN_SUPPRESSION: StdDuration = StdDuration::from_secs(60);

/// Most flow classes the miss-warning limiter remembers.
const MAX_MISS_KEYS: usize = 256;

/// Most pids one lookup may examine.
const MAX_PIDS: usize = 4096;

/// Most descriptors one pid's scan may examine.
const MAX_FDS: usize = 4096;

/// Most unconnected UDP rows one lookup may consider as ownership candidates.
///
/// A local port shared by more sockets than this is not a desktop resolver pattern; the
/// cap keeps the candidate list bounded even when the table is adversarially large.
const MAX_UDP_CANDIDATES: usize = 64;

/// Most bytes of `/proc/<pid>/cmdline` kept after joining its NUL-separated arguments.
const MAX_CMDLINE: usize = 4096;

/// The kernel's per-process metadata directory.
const PROC: &str = "/proc";

/// Performance counters for a single [`Attributor`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttributeStats {
   /// Lookups that found the owning process.
   pub hits: u64,
   /// Lookups that returned [`Attribution::Unknown`], for any reason.
   pub misses: u64,
   /// Lookups that stopped because a scan budget was exceeded.
   pub scan_budget_exhausted: u64,
}

/// A flow that was attributed, keyed by protocol and both endpoints.
///
/// The inode caches only help while the same inode repeats; a browser opens a fresh socket
/// per connection, so the flow tuple is what actually repeats (retransmits, and the second
/// and later packets of one flow).
type FlowKey = (L4Proto, (IpAddr, u16), (IpAddr, u16));

/// The flow class whose consecutive misses are tracked for the operator warning.
type MissKey = (Option<u32>, L4Proto, u16);

/// The identity of one process, learned while its `/proc` entry was still readable.
///
/// `exe` is `Option` because a process can be recorded from metadata alone (the connector
/// announced it, but its `exe` link was already gone) — the uid and start time are still
/// worth keeping, while a guessed `exe` would be a wrong rule key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedIdentity {
   pub exe: Option<PathBuf>,
   pub comm: String,
   pub uid: u32,
   pub starttime: u64,
}

/// Identities learned from the proc connector, so a process that exits mid-scan still resolves.
#[derive(Debug, Default)]
pub struct ProcessCache {
   identities: HashMap<u32, CachedIdentity>,
}

impl ProcessCache {
   /// Creates an empty cache.
   pub fn new() -> Self {
      Self::default()
   }

   /// Seeds from a full `/proc` sweep; failures are skipped, never fatal.
   pub fn seed(&mut self) {
      let Some(pids) = numeric_pids() else {
         return;
      };
      for pid in pids {
         self.record(pid);
      }
   }

   /// Reads `/proc/<pid>/…` now and inserts the identity when it is still there.
   ///
   /// A pid whose `exe` cannot be read is still recorded with `exe: None`, so its uid and
   /// start time remain available. A pid whose uid or start time cannot be read is skipped
   /// instead: the struct has no "unknown" for those fields, and a default would be a
   /// guessed identity that could satisfy the wrong uid check.
   pub fn record(&mut self, pid: u32) {
      if let Some(identity) = identity_at(pid, Path::new(PROC)) {
         self.insert(pid, identity);
      }
   }

   /// Drops a pid's identity when the connector reports its exit.
   pub fn forget(&mut self, pid: u32) {
      self.identities.remove(&pid);
   }

   /// Returns the cached identity for a pid.
   pub fn get(&self, pid: u32) -> Option<&CachedIdentity> {
      self.identities.get(&pid)
   }

   /// Returns the number of cached identities.
   pub fn len(&self) -> usize {
      self.identities.len()
   }

   /// Whether the cache holds no identities.
   pub fn is_empty(&self) -> bool {
      self.identities.is_empty()
   }

   /// Inserts one identity, replacing any earlier record for the pid.
   fn insert(&mut self, pid: u32, identity: CachedIdentity) {
      self.identities.insert(pid, identity);
   }
}

/// The `/proc` walker and its caches.
///
/// The caches are keyed by flow, inode and pid because the expensive half is the directory
/// scan, not the table parse: Firefox and Chrome hold hundreds of descriptors, and a
/// browser opening ten connections in a second would otherwise rescan the same fd
/// directories ten times.
#[derive(Debug)]
pub struct Attributor {
   /// Identities the proc connector learned before a process exited. Only identity is
   /// cached; ownership still comes from the descriptor scan, so a hit here can never
   /// invent an owner for an inode.
   process_cache: Arc<Mutex<ProcessCache>>,
   inode_to_pid: HashMap<u32, InodeCacheEntry>,
   pid_fds: HashMap<u32, FdCacheEntry>,
   flow_owners: HashMap<FlowKey, FlowCacheEntry>,
   flow_misses: HashMap<FlowKey, Instant>,
   miss_streaks: HashMap<MissKey, MissStreak>,
   stats: AttributeStats,
   /// When the budget warning was last emitted, so a busy scan cannot flood the journal.
   last_budget_warn: Option<Instant>,
}

/// A cached inode→pid answer, with the owner recorded for the UID cross-check.
#[derive(Clone, Copy, Debug)]
struct InodeCacheEntry {
   pid: u32,
   uid: u32,
   at: Instant,
}

/// A cached pid→socket-inode list, with the owner recorded for the UID cross-check.
#[derive(Clone, Debug)]
struct FdCacheEntry {
   inodes: Vec<u32>,
   uid: u32,
   at: Instant,
}

/// A cached flow→owner answer.
#[derive(Clone, Copy, Debug)]
struct FlowCacheEntry {
   pid: u32,
   uid: u32,
   at: Instant,
}

/// Consecutive misses for one flow class and when it was last warned about.
#[derive(Clone, Copy, Debug, Default)]
struct MissStreak {
   consecutive: u32,
   warned_at: Option<Instant>,
}

/// What a failure line must name so one cause is distinguishable from another.
struct FailureContext<'a> {
   local: (IpAddr, u16),
   remote: (IpAddr, u16),
   proto: L4Proto,
   uid: Option<u32>,
   table: Option<&'a str>,
   candidates: Option<usize>,
}

impl Attributor {
   /// Creates an attributor over its own empty process cache.
   pub fn new() -> Self {
      Self::with_process_cache(Arc::new(Mutex::new(ProcessCache::new())))
   }

   /// Creates an attributor that shares the identity cache the connector thread fills.
   pub fn with_process_cache(process_cache: Arc<Mutex<ProcessCache>>) -> Self {
      Self {
         process_cache,
         inode_to_pid: HashMap::new(),
         pid_fds: HashMap::new(),
         flow_owners: HashMap::new(),
         flow_misses: HashMap::new(),
         miss_streaks: HashMap::new(),
         stats: AttributeStats::default(),
         last_budget_warn: None,
      }
   }

   /// Attributes the socket owning this outbound flow.
   ///
   /// `uid` is the kernel's `NFQA_UID`: when known it narrows the pid scan and is
   /// cross-checked against the directory owner, because a socket that changed hands
   /// between the packet and the lookup must not be attributed to either process.
   /// `None` scans every pid the daemon may read.
   pub fn attribute(
      &mut self,
      local: (IpAddr, u16),
      remote: (IpAddr, u16),
      proto: L4Proto,
      uid: Option<u32>,
   ) -> Attribution {
      let now = Instant::now();
      let flow = (proto, local, remote);
      if let Some((pid, owner_uid)) = self.cached_flow(flow, uid, now) {
         return match self.process_identity(pid, owner_uid) {
            Some(process) => {
               self.stats.hits += 1;
               Attribution::Process(process)
            }
            // The cached owner is gone, so the positive answer is stale: drop it and let
            // this call go through the `/proc` path instead of trusting it.
            None => {
               self.flow_owners.remove(&flow);
               self.lookup(local, remote, proto, uid, now)
            }
         };
      }
      if self.flow_miss_active(flow, now) {
         // The same flow just failed to resolve; its packet burst must cost one scan, not
         // one per packet. This never becomes an answer, only a cheaper miss.
         self.record_miss(proto, remote, uid, now);
         return Attribution::Unknown;
      }
      self.lookup(local, remote, proto, uid, now)
   }

   /// Runs the `/proc` lookup and maintains the flow caches around it.
   fn lookup(
      &mut self,
      local: (IpAddr, u16),
      remote: (IpAddr, u16),
      proto: L4Proto,
      uid: Option<u32>,
      now: Instant,
   ) -> Attribution {
      let flow = (proto, local, remote);
      let context = FailureContext {
         local,
         remote,
         proto,
         uid,
         table: None,
         candidates: None,
      };
      let Some(family) = family_of(local.0) else {
         return self.unknown(&context, "local address has no family", now);
      };
      if family_of(remote.0) != Some(family) {
         return self.unknown(
            &context,
            "flow endpoints mix address families",
            now,
         );
      }
      let Some(table) = socket_table(proto, family) else {
         // ICMP and unknown protocols do not appear in a socket table; v1 does not prompt
         // for them, so this is expected rather than an error.
         debug!(
            "attribution skipped for {} {} -> {}: no socket table in v1",
            proto,
            endpoint_label(local),
            endpoint_label(remote)
         );
         // Not a flow class worth a warning: v1 never prompts for ICMP, so there is no
         // unknown decision to make visible.
         self.stats.misses += 1;
         return Attribution::Unknown;
      };
      let context = FailureContext {
         table: Some(table),
         ..context
      };

      let text = match fs::read_to_string(format!("{PROC}/net/{table}")) {
         Ok(text) => text,
         Err(error) => {
            return self.unknown(
               &context,
               &format!("cannot read /proc/net/{table}: {error}"),
               now,
            );
         }
      };
      // An exact row with inode 0 is a closed connection's leftover: the 4-tuple is still
      // there but nothing holds the socket, so no descriptor scan can ever find an owner.
      // It is not the same failure as "the table has no row for this flow".
      let candidates = inode_candidates(&text, family, local, remote, proto);
      if candidates.is_empty() {
         let (reason, count) = candidate_failure_reason(&text, family, local, remote);
         let context = FailureContext {
            candidates: count,
            ..context
         };
         return self.unknown(&context, reason, now);
      }
      let context = FailureContext {
         candidates: Some(candidates.len()),
         ..context
      };

      let owner = candidate_owner(&candidates, uid, |inode| {
         match self.cached_owner(inode, uid) {
            Some(owner) => Some(owner),
            None => self.scan_for_inode(inode, uid),
         }
      });
      let (inode, pid, process_uid) = match owner {
         CandidateOwner::Found {
            inode,
            pid,
            uid: owner_uid,
         } => (inode, pid, owner_uid),
         CandidateOwner::Mismatch {
            inode,
            pid,
            packet_uid,
            owner_uid,
         } => {
            // The fd exists but belongs to someone else than the packet said: the socket
            // was reused between the queue and this scan. Guessing would grant the wrong
            // application's policy.
            warn!(
               "attribution refused for inode {inode}: packet uid {packet_uid} but \
                /proc/{pid} is owned by uid {owner_uid}"
            );
            return self.unknown(
               &context,
               &format!(
                  "socket inode {inode} is owned by uid {owner_uid}, not the packet uid \
                   {packet_uid}"
               ),
               now,
            );
         }
         CandidateOwner::Ambiguous => {
            return self.unknown(
               &context,
               "several unconnected UDP sockets share the local port and the packet has no uid",
               now,
            );
         }
         CandidateOwner::Missing => {
            return self.unknown(&context, "no /proc fd link holds the inode", now);
         }
      };

      let Some(process) = self.process_identity(pid, process_uid) else {
         return self.unknown(
            &context,
            &format!("cannot read /proc/{pid} identity for inode {inode}"),
            now,
         );
      };
      self.inode_to_pid.insert(
         inode,
         InodeCacheEntry {
            pid,
            uid: process_uid,
            at: now,
         },
      );
      self.remember_success(
         flow,
         FlowCacheEntry {
            pid,
            uid: process_uid,
            at: now,
         },
         (uid, proto, remote.1),
      );
      self.stats.hits += 1;
      Attribution::Process(process)
   }

   /// Resolves a pid's identity, preferring the connector cache.
   ///
   /// The cache exists precisely because `/proc/<pid>/exe` may be gone by the time a scan
   /// resolves an inode; a miss falls back to `/proc` and stores what it read. `uid` is the
   /// owner the descriptor scan established, never a cache lookup.
   fn process_identity(&mut self, pid: u32, uid: u32) -> Option<ProcessInfo> {
      if let Some(cached) = self.cached_identity(pid) {
         if cached.uid == uid {
            // `cmdline` is not an identity field, so it is not cached; read it when the
            // process is still around and leave it empty when the cache is all that is
            // left, which is exactly the vanished-process case.
            let cmdline = fs::read(format!("{PROC}/{pid}/cmdline"))
               .ok()
               .and_then(|bytes| join_cmdline(&bytes));
            return Some(ProcessInfo {
               pid,
               uid: cached.uid,
               exe: cached.exe.clone(),
               comm: Some(cached.comm.clone()).filter(|comm| !comm.is_empty()),
               cmdline,
            });
         }
         // The pid was recycled into another user: the cached identity is not evidence
         // about this socket. Drop it and fall back to `/proc`, never reconcile the two.
         if let Ok(mut cache) = self.process_cache.lock() {
            cache.forget(pid);
         }
      }
      let process = read_process(pid, uid)?;
      self.remember_identity(pid, &process);
      Some(process)
   }

   /// Copies a cache hit so the lock is not held while the caller renders it.
   fn cached_identity(&self, pid: u32) -> Option<CachedIdentity> {
      let cache = self.process_cache.lock().ok()?;
      cache.get(pid).cloned()
   }

   /// Stores an identity read from `/proc`, without overwriting a fuller cached one.
   fn remember_identity(&self, pid: u32, process: &ProcessInfo) {
      let Ok(mut cache) = self.process_cache.lock() else {
         return;
      };
      if cache.get(pid).is_some() {
         return;
      }
      let Some(starttime) = read_starttime_at(&Path::new(PROC).join(pid.to_string())) else {
         return;
      };
      cache.insert(
         pid,
         CachedIdentity {
            exe: process.exe.clone(),
            comm: process.comm.clone().unwrap_or_default(),
            uid: process.uid,
            starttime,
         },
      );
   }

   /// Returns the per-lookup counters.
   pub fn stats(&self) -> AttributeStats {
      self.stats
   }

   /// Returns a fresh flow→owner answer, or `None` when it is stale or disagrees with the
   /// packet's uid.
   fn cached_flow(&mut self, flow: FlowKey, uid: Option<u32>, now: Instant) -> Option<(u32, u32)> {
      let entry = *self.flow_owners.get(&flow)?;
      if now.saturating_duration_since(entry.at) >= CACHE_TTL {
         self.flow_owners.remove(&flow);
         return None;
      }
      if uid.is_some_and(|uid| uid != entry.uid) {
         // A recycled tuple with a different owner is not evidence about this packet.
         self.flow_owners.remove(&flow);
         return None;
      }
      Some((entry.pid, entry.uid))
   }

   /// Records a success: it clears the flow's negative marker and the flow class's miss
   /// streak, then stores the positive answer.
   fn remember_success(&mut self, flow: FlowKey, entry: FlowCacheEntry, class: MissKey) {
      self.flow_misses.remove(&flow);
      self.miss_streaks.remove(&class);
      self.remember_flow(flow, entry);
   }

   /// Stores a successful flow→owner answer, bounding the cache by dropping expired and
   /// then oldest entries.
   fn remember_flow(&mut self, flow: FlowKey, entry: FlowCacheEntry) {
      if self.flow_owners.len() >= MAX_FLOWS {
         self
            .flow_owners
            .retain(|_, cached| entry.at.saturating_duration_since(cached.at) < CACHE_TTL);
         while self.flow_owners.len() >= MAX_FLOWS {
            let Some(oldest) = self
               .flow_owners
               .iter()
               .min_by_key(|(_, cached)| cached.at)
               .map(|(flow, _)| *flow)
            else {
               break;
            };
            self.flow_owners.remove(&oldest);
         }
      }
      self.flow_owners.insert(flow, entry);
   }

   /// Whether this flow failed recently enough that re-scanning it would be waste.
   fn flow_miss_active(&mut self, flow: FlowKey, now: Instant) -> bool {
      let Some(at) = self.flow_misses.get(&flow).copied() else {
         return false;
      };
      if now.saturating_duration_since(at) >= NEGATIVE_TTL {
         self.flow_misses.remove(&flow);
         return false;
      }
      true
   }

   /// Marks a flow so its next packet in the next second does not rescan `/proc`.
   fn mark_flow_miss(&mut self, flow: FlowKey, now: Instant) {
      if self.flow_misses.len() >= MAX_FLOWS {
         self
            .flow_misses
            .retain(|_, at| now.saturating_duration_since(*at) < NEGATIVE_TTL);
         if self.flow_misses.len() >= MAX_FLOWS {
            self.flow_misses.clear();
         }
      }
      self.flow_misses.insert(flow, now);
   }

   /// Counts one miss and emits the operator warning when a flow class has failed often
   /// enough to stop looking like a one-off race.
   fn record_miss(
      &mut self,
      proto: L4Proto,
      remote: (IpAddr, u16),
      uid: Option<u32>,
      now: Instant,
   ) {
      self.stats.misses += 1;
      let key = (uid, proto, remote.1);
      if let Some(message) = self.miss_warning(key, proto, remote, uid, now) {
         warn!("{message}");
      }
   }

   /// Tracks consecutive misses for one `(uid-or-none, proto, remote port)` class and
   /// returns the warning text exactly when it is due.
   ///
   /// The threshold keeps a single race at `debug`; the suppression window keeps a DNS
   /// burst from filling the journal once the condition is known.
   fn miss_warning(
      &mut self,
      key: MissKey,
      proto: L4Proto,
      remote: (IpAddr, u16),
      uid: Option<u32>,
      now: Instant,
   ) -> Option<String> {
      if self.miss_streaks.len() >= MAX_MISS_KEYS && !self.miss_streaks.contains_key(&key) {
         self.miss_streaks.retain(|_, streak| {
            streak
               .warned_at
               .is_none_or(|at| now.saturating_duration_since(at) < MISS_WARN_SUPPRESSION)
         });
         if self.miss_streaks.len() >= MAX_MISS_KEYS {
            self.miss_streaks.clear();
         }
      }
      let streak = self.miss_streaks.entry(key).or_default();
      streak.consecutive = streak.consecutive.saturating_add(1);
      if streak.consecutive < MISS_WARN_THRESHOLD {
         return None;
      }
      if streak
         .warned_at
         .is_some_and(|at| now.saturating_duration_since(at) < MISS_WARN_SUPPRESSION)
      {
         return None;
      }
      streak.warned_at = Some(now);
      Some(format!(
         "attribution cannot map {} flows destined to {} ({}) to a process: these flows \
          stay unknown and policy decides them, not the daemon",
         proto,
         endpoint_label(remote),
         uid_label(uid)
      ))
   }

   /// Returns a fresh inode→pid cache answer, or `None` when it is stale or disagrees
   /// with the packet's uid.
   fn cached_owner(&mut self, inode: u32, uid: Option<u32>) -> Option<(u32, u32)> {
      let entry = *self.inode_to_pid.get(&inode)?;
      if entry.at.elapsed() >= CACHE_TTL {
         self.inode_to_pid.remove(&inode);
         return None;
      }
      if uid.is_some_and(|uid| uid != entry.uid) {
         // A stale entry that disagrees with the packet is evidence the inode was
         // recycled; rescan instead of trusting the cache.
         self.inode_to_pid.remove(&inode);
         return None;
      }
      Some((entry.pid, entry.uid))
   }

   /// Scans `/proc/<pid>/fd` for the socket inode, honouring the uid and scan budgets.
   ///
   /// Returns `None` both for "not found" and for "budget exhausted"; the latter has
   /// already been counted and logged by [`Attributor::budget_exhausted`].
   fn scan_for_inode(&mut self, inode: u32, uid: Option<u32>) -> Option<(u32, u32)> {
      let pids = numeric_pids()?;
      self.scan_pids_for_inode(pids, inode, uid, socket_inodes)
   }

   /// The body of [`Attributor::scan_for_inode`], over an explicit pid list and descriptor
   /// reader so the cache/refresh behaviour can be exercised without a live `/proc`.
   fn scan_pids_for_inode(
      &mut self,
      pids: Vec<u32>,
      inode: u32,
      uid: Option<u32>,
      mut read_inodes: impl FnMut(u32) -> Result<Vec<u32>, ScanError>,
   ) -> Option<(u32, u32)> {
      if pids.len() > MAX_PIDS {
         self.budget_exhausted(&format!(
            "pid scan would examine {} processes (budget {MAX_PIDS})",
            pids.len()
         ));
         return None;
      }

      for pid in pids {
         if let Some((found, owner)) = self.cached_fd_lookup(pid, inode, uid)
            && found
         {
            return Some((pid, owner));
         }
         // A cached negative is a hint, not proof: the process may have opened the
         // socket after the snapshot was taken (the resolver does exactly that per
         // query). Fall through and re-read its descriptors once; the refresh below
         // replaces the entry, so this pid is scanned at most once per lookup.

         let owner_uid = match read_pid_uid(pid) {
            Some(owner_uid) => owner_uid,
            // The process exited between the directory read and this lookup.
            None => continue,
         };
         if uid.is_some_and(|wanted| wanted != owner_uid) {
            continue;
         }

         let (inodes, over_budget) = match read_inodes(pid) {
            Ok(inodes) => (inodes, false),
            // The fresh entries were still inspected, so a socket among them is a real
            // hit; the warning below records that the rest of the directory went unseen.
            Err(ScanError::Budget(inodes)) => (inodes, true),
            Err(ScanError::Unreadable) => continue,
         };
         if over_budget {
            self.budget_exhausted(&format!(
               "descriptor scan of pid {pid} exceeded {MAX_FDS} entries"
            ));
         }
         let found = inodes.contains(&inode);
         // A trimmed snapshot is cached too: a positive is a real descriptor at that pid,
         // and a negative stays only a hint that the next lookup refreshes.
         self.pid_fds.insert(
            pid,
            FdCacheEntry {
               inodes,
               uid: owner_uid,
               at: Instant::now(),
            },
         );
         if found {
            return Some((pid, owner_uid));
         }
         if over_budget {
            // The cut-off dropped descriptors this pid holds, so no other process can be
            // ruled in or out: the answer is unknown, not a miss from a complete scan.
            return None;
         }
      }
      None
   }

   /// Consults the pid→fd cache for one pid, returning `Some((found, uid))` only when the
   /// entry is fresh and usable for this packet's uid.
   fn cached_fd_lookup(
      &mut self,
      pid: u32,
      inode: u32,
      packet_uid: Option<u32>,
   ) -> Option<(bool, u32)> {
      let entry = self.pid_fds.get(&pid)?;
      if entry.at.elapsed() >= CACHE_TTL {
         self.pid_fds.remove(&pid);
         return None;
      }
      if packet_uid.is_some_and(|wanted| entry.uid != wanted) {
         return None;
      }
      Some((entry.inodes.contains(&inode), entry.uid))
   }

   /// Counts and rate-limits a budget-exhaustion warning.
   fn budget_exhausted(&mut self, reason: &str) {
      self.stats.scan_budget_exhausted += 1;
      let now = Instant::now();
      let due = self
         .last_budget_warn
         .is_none_or(|last| now.duration_since(last) >= StdDuration::from_secs(1));
      if due {
         self.last_budget_warn = Some(now);
         warn!("attribution scan budget exhausted: {reason}; connection is unknown");
      }
   }

   /// Records a miss, marks the flow negative and logs why attribution failed.
   fn unknown(&mut self, context: &FailureContext<'_>, reason: &str, now: Instant) -> Attribution {
      self.mark_flow_miss(
         (context.proto, context.local, context.remote),
         now,
      );
      self.record_miss(context.proto, context.remote, context.uid, now);
      debug!(
         "attribution failed: {}",
         failure_message(context, reason)
      );
      Attribution::Unknown
   }
}

/// Renders the one-line diagnostic shared by every [`Attributor::unknown`] failure.
///
/// It names the flow, the protocol, the uid state and the table/candidate count because
/// those four facts separate a vanished socket from a uid-less resolver packet; a bare
/// reason cannot. Kept under 160 characters by keeping the table to its basename.
fn failure_message(context: &FailureContext<'_>, reason: &str) -> String {
   let table = context.table.map_or("no-table", |table| table);
   format!(
      "{} {} -> {} {} table={} cand={}: {reason}",
      context.proto,
      endpoint_label(context.local),
      endpoint_label(context.remote),
      uid_label(context.uid),
      table,
      context.candidates.map_or_else(|| "-".to_owned(), |count| count.to_string())
   )
}

/// Renders the kernel-supplied uid state as `uid=Some(n)` or `uid=none`.
fn uid_label(uid: Option<u32>) -> String {
   match uid {
      Some(uid) => format!("uid=Some({uid})"),
      None => "uid=none".to_owned(),
   }
}

impl Default for Attributor {
   fn default() -> Self {
      Self::new()
   }
}

/// Why a pid's descriptor directory could not be fully scanned.
enum ScanError {
   /// The process vanished or its fds are not readable by this daemon.
   Unreadable,
   /// The directory held more entries than one lookup may examine. The payload is what the
   /// newest [`MAX_FDS`] entries yielded: the scan must still attribute the fresh socket it
   /// was allowed to inspect, while the caller counts and warns about the truncation.
   Budget(Vec<u32>),
}

/// Returns the socket table for a protocol and family, or `None` when there is none.
fn socket_table(proto: L4Proto, family: Family) -> Option<&'static str> {
   match (proto, family) {
      (L4Proto::Tcp, Family::V4) => Some("tcp"),
      (L4Proto::Tcp, Family::V6) => Some("tcp6"),
      (L4Proto::Udp, Family::V4) => Some("udp"),
      (L4Proto::Udp, Family::V6) => Some("udp6"),
      (L4Proto::Icmp | L4Proto::Other(_), _) => None,
   }
}

/// The address family of an IP address.
fn family_of(addr: IpAddr) -> Option<Family> {
   match addr {
      IpAddr::V4(_) => Some(Family::V4),
      IpAddr::V6(_) => Some(Family::V6),
   }
}

/// Decodes `HEXADDR:HEXPORT` from one `/proc/net` column.
///
/// IPv4 is a single little-endian `u32` rendered as 8 hex characters, IPv6 is four
/// little-endian `u32` groups rendered as 32; ports are big-endian hex. The kernel's byte
/// order is the trap here: `0100007F` is 127.0.0.1, not 1.0.0.127.
fn decode_endpoint(field: &str, family: Family) -> Option<(IpAddr, u16)> {
   let (addr, port) = field.split_once(':')?;
   let addr = match family {
      Family::V4 => decode_v4(addr)?,
      Family::V6 => decode_v6(addr)?,
   };
   let port = u16::from_str_radix(port, 16).ok()?;
   Some((addr, port))
}

/// Decodes the IPv4 column: one little-endian word in 8 hex characters.
fn decode_v4(hex: &str) -> Option<IpAddr> {
   if hex.len() != 8 {
      return None;
   }
   let word = u32::from_str_radix(hex, 16).ok()?;
   Some(IpAddr::V4(Ipv4Addr::from(word.to_le_bytes())))
}

/// Decodes the IPv6 column: four little-endian words in 32 hex characters.
fn decode_v6(hex: &str) -> Option<IpAddr> {
   if hex.len() != 32 {
      return None;
   }
   let mut bytes = [0u8; 16];
   for (index, chunk) in hex.as_bytes().chunks(8).enumerate() {
      let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
      bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
   }
   Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

/// Iterates the parseable rows of a `/proc/net/{tcp,udp}` table as
/// `(local, remote, inode)`.
///
/// Field layout, from the kernel's header: 1 local, 2 remote, 3 state, 7 uid, 9 inode.
/// A malformed or header line is skipped rather than treated as an error; the table is
/// kernel output and one unparsable line must not hide the socket on another line.
fn socket_rows(
   text: &str,
   family: Family,
) -> impl Iterator<Item = ((IpAddr, u16), (IpAddr, u16), u64)> + '_ {
   text.lines().filter_map(move |line| {
      let fields: Vec<&str> = line.split_whitespace().collect();
      if fields.len() <= 9 {
         return None;
      }
      let local = decode_endpoint(fields[1], family)?;
      let remote = decode_endpoint(fields[2], family)?;
      let inode = fields[9].parse::<u64>().ok()?;
      Some((local, remote, inode))
   })
}

/// Returns the inode candidates for a flow, best match first.
///
/// TCP is exact-only: an unconnected socket is indistinguishable from another flow on the
/// same port, so a loose fallback would attribute one application's packet to another.
///
/// UDP may be unconnected, which is how the system resolver and most DNS clients send.
/// Their table row keeps the wildcard local address and an unspecified remote even after
/// `sendto()`, while the queued packet carries the interface address. The fallback accepts
/// rows on the packet's local port whose remote is unspecified and whose local address is
/// either unspecified or the packet's local address. All such rows are returned because
/// the uid cross-check and the fd scan are what pick the owner; the packet tuple alone
/// cannot. An exact row always wins and is returned alone.
///
/// An inode of 0 is never a candidate in either path: the row outlived its socket
/// (TIME_WAIT), so no process can hold it and returning it would send the scan chasing an
/// inode no descriptor can contain. The diagnostic distinguishes "no row" from "a row with
/// no live socket" through [`candidate_failure_reason`].
fn inode_candidates(
   text: &str,
   family: Family,
   local: (IpAddr, u16),
   remote: (IpAddr, u16),
   proto: L4Proto,
) -> Vec<u64> {
   let exact = exact_row_inode(text, family, local, remote);
   if let Some(inode) = exact {
      if inode == 0 {
         // TIME_WAIT and friends keep the flow's 4-tuple but no live socket, so the row
         // can never be held by any process. Returning it would send the scan looking
         // for an inode no descriptor can contain.
         return Vec::new();
      }
      return vec![inode];
   }
   if proto != L4Proto::Udp {
      return Vec::new();
   }

   let mut candidates = Vec::new();
   for (row_local, row_remote, inode) in socket_rows(text, family) {
      if row_local.1 != local.1 {
         continue;
      }
      if !row_remote.0.is_unspecified() || row_remote.1 != 0 {
         continue;
      }
      if !row_local.0.is_unspecified() && row_local.0 != local.0 {
         continue;
      }
      if inode == 0 {
         // A table row without a live socket, e.g. TIME_WAIT, can never own the packet.
         continue;
      }
      candidates.push(inode);
      if candidates.len() == MAX_UDP_CANDIDATES {
         break;
      }
   }
   candidates
}

/// Names why [`inode_candidates`] returned nothing, with the candidate count to log.
///
/// "No row at all" and "a row whose socket is already closed" both leave the candidate
/// list empty, but they have different causes and fixes, so the diagnostic must not
/// collapse them into one message.
fn candidate_failure_reason(
   text: &str,
   family: Family,
   local: (IpAddr, u16),
   remote: (IpAddr, u16),
) -> (&'static str, Option<usize>) {
   match exact_row_inode(text, family, local, remote) {
      Some(0) => (
         "the exact row has inode 0: no live socket, the connection was already \
          closed when it was queued",
         Some(0),
      ),
      _ => ("no matching socket row in the table", None),
   }
}

/// Returns the inode of the row whose local and remote endpoints equal the flow's.
///
/// This is the exact match TCP depends on and UDP prefers. A row with inode 0 is still a
/// match: the caller needs to tell "no row" from "a row whose socket is already closed".
fn exact_row_inode(
   text: &str,
   family: Family,
   local: (IpAddr, u16),
   remote: (IpAddr, u16),
) -> Option<u64> {
   socket_rows(text, family)
      .find(|(row_local, row_remote, _)| *row_local == local && *row_remote == remote)
      .map(|(_, _, inode)| inode)
}

/// The outcome of trying inode candidates against `/proc/<pid>/fd`.
#[derive(Debug, PartialEq, Eq)]
enum CandidateOwner {
   /// The candidate's owner agrees with the kernel-supplied uid (or no uid was supplied).
   Found { inode: u32, pid: u32, uid: u32 },
   /// The only candidate found is owned by a different uid than the packet's.
   Mismatch {
      inode: u32,
      pid: u32,
      packet_uid: u32,
      owner_uid: u32,
   },
   /// Several candidates exist and the packet carries no uid to disambiguate them.
   Ambiguous,
   /// No candidate inode is held by any readable process.
   Missing,
}

/// Tries candidates in order until one yields an owner that agrees with `uid`.
///
/// `owner_of` is injected so this selection logic can be exercised without a live `/proc`.
fn candidate_owner(
   candidates: &[u64],
   uid: Option<u32>,
   mut owner_of: impl FnMut(u32) -> Option<(u32, u32)>,
) -> CandidateOwner {
   if uid.is_none() && candidates.len() > 1 {
      // Two sockets can share a local port; without the kernel uid there is no evidence
      // to pick one, and a wrong application in a firewall prompt is worse than Unknown.
      return CandidateOwner::Ambiguous;
   }
   let mut mismatch = None;
   for &candidate in candidates {
      let Ok(inode) = u32::try_from(candidate) else {
         continue;
      };
      let Some((pid, owner_uid)) = owner_of(inode) else {
         continue;
      };
      if let Some(wanted) = uid
         && wanted != owner_uid
      {
         mismatch.get_or_insert((inode, pid, wanted, owner_uid));
         continue;
      }
      return CandidateOwner::Found {
         inode,
         pid,
         uid: owner_uid,
      };
   }
   match mismatch {
      Some((inode, pid, packet_uid, owner_uid)) => CandidateOwner::Mismatch {
         inode,
         pid,
         packet_uid,
         owner_uid,
      },
      None => CandidateOwner::Missing,
   }
}

/// Opens `/proc/<pid>/fd` and collects the socket inodes it holds.
///
/// Descriptors are ordered newest-first before any link is read, mirroring OpenSnitch's
/// `sortFdsByTime`: a firewall looks for a socket created moments ago, so the newest
/// [`MAX_FDS`] entries are the ones worth spending the budget on. A directory holding more
/// than that is still trimmed, but its freshest entries are read; the caller is told with
/// [`ScanError::Budget`] and receives those inodes rather than an empty list.
fn socket_inodes(pid: u32) -> Result<Vec<u32>, ScanError> {
   read_fd_dir(Path::new(PROC).join(pid.to_string()).join("fd"))
}

/// Scans one descriptor directory, newest entry first, trimming the list to [`MAX_FDS`].
///
/// Split from [`socket_inodes`] so the ordering and the budget can be exercised on a
/// directory the test controls instead of a live `/proc`.
fn read_fd_dir(path: PathBuf) -> Result<Vec<u32>, ScanError> {
   let directory = fs::read_dir(&path).map_err(|_| ScanError::Unreadable)?;
   let mut entries = Vec::new();
   let mut seen = 0usize;
   for entry in directory {
      let Ok(entry) = entry else {
         continue;
      };
      seen += 1;
      entries.push((entry.file_name(), entry_mtime(&entry)));
   }
   let over_budget = seen > MAX_FDS;
   let mut inodes = Vec::new();
   for name in sort_fds_newest_first(entries, MAX_FDS) {
      let target = match fs::read_link(path.join(name)) {
         Ok(target) => target,
         // A descriptor closed between readdir and readlink.
         Err(_) => continue,
      };
      if let Some(target) = target.to_str()
         && let Some(inode) = socket_link_inode(target)
      {
         inodes.push(inode);
      }
   }
   if over_budget {
      return Err(ScanError::Budget(inodes));
   }
   Ok(inodes)
}

/// Returns a directory entry's own modification time, without following a symlink.
///
/// A `/proc` descriptor is a link: `socket:[<inode>]`, `/dev/null`, a pipe. Its link
/// metadata is the descriptor's age, which is what this ordering is about, and
/// `fs::metadata` would follow the link instead. For a socket that gives the socket inode's
/// time (`0`) and for a regular file the target's age, so following the link would sort
/// precisely the descriptors this scan is looking for into the untimed bucket.
fn entry_mtime(entry: &fs::DirEntry) -> Option<SystemTime> {
   entry.metadata().ok()?.modified().ok()
}

/// Sorts `(name, mtime)` descriptor entries newest-first, as OpenSnitch does; entries
/// without a time go last. Returns the file names to inspect, trimmed to `limit`.
fn sort_fds_newest_first(
   entries: Vec<(OsString, Option<SystemTime>)>,
   limit: usize,
) -> Vec<OsString> {
   sort_newest_first(entries)
      .into_iter()
      .take(limit)
      .map(|(name, _)| name)
      .collect()
}

/// Parses a `/proc/<pid>/fd` link target of the form `socket:[<inode>]`.
fn socket_link_inode(target: &str) -> Option<u32> {
   let inner = target.strip_prefix("socket:[")?.strip_suffix(']')?;
   inner.parse().ok()
}

/// Reads the owner uid of `/proc/<pid>` from its directory metadata.
///
/// The directory, not `status`, is authoritative here: it is the kernel's inode owner and
/// takes one `stat` instead of a parse that could disagree with the fd scan.
fn read_pid_uid(pid: u32) -> Option<u32> {
   read_pid_uid_at(&PathBuf::from(format!("{PROC}/{pid}")))
}

/// Reads a process directory's owner uid from its metadata.
fn read_pid_uid_at(dir: &Path) -> Option<u32> {
   fs::metadata(dir).ok().map(|meta| meta.uid())
}

/// Lists the numeric entries of `/proc`, newest process first.
///
/// The scan order matters: the socket being attributed was created moments ago, so the
/// process that started last is the likeliest owner. A pid whose directory time cannot be
/// read is still scanned, only last, so a racing exit or an unreadable entry never hides a
/// younger process.
fn numeric_pids() -> Option<Vec<u32>> {
   let entries = fs::read_dir(PROC).ok()?;
   let mut pids = Vec::new();
   for entry in entries.flatten() {
      let Ok(name) = entry.file_name().into_string() else {
         continue;
      };
      let Ok(pid) = name.parse::<u32>() else {
         continue;
      };
      let mtime = fs::metadata(entry.path()).ok().and_then(|meta| meta.modified().ok());
      pids.push((pid, mtime));
   }
   Some(sort_pids_newest_first(pids))
}

/// Sorts `(pid, mtime)` pairs newest-first; entries without a time go last, ties keep input
/// order.
fn sort_pids_newest_first(entries: Vec<(u32, Option<SystemTime>)>) -> Vec<u32> {
   sort_newest_first(entries).into_iter().map(|(pid, _)| pid).collect()
}

/// Sorts `(item, mtime)` entries newest-first, with untimed entries last and ties stable.
///
/// `sort_by` is a stable sort, so equal times and two missing times keep the readdir order;
/// that keeps the scan deterministic for the tests and for a reproduced failure.
fn sort_newest_first<T>(mut entries: Vec<(T, Option<SystemTime>)>) -> Vec<(T, Option<SystemTime>)> {
   entries.sort_by(|(_, a), (_, b)| match (a, b) {
      (Some(a), Some(b)) => b.cmp(a),
      (Some(_), None) => std::cmp::Ordering::Less,
      (None, Some(_)) => std::cmp::Ordering::Greater,
      (None, None) => std::cmp::Ordering::Equal,
   });
   entries
}

/// Reads one process's identity under `root` (the real `/proc` or a test fixture).
///
/// Returns `None` when neither the uid nor the start time can be read: the struct has no
/// "unknown" for those fields, and a default would be a guessed identity that could satisfy
/// the wrong uid check. A readable uid and start time are enough to record the pid even
/// without an `exe`, which is exactly the racing-exit case this cache exists for.
fn identity_at(pid: u32, root: &Path) -> Option<CachedIdentity> {
   let dir = root.join(pid.to_string());
   let uid = read_status_uid_at(&dir).or_else(|| read_pid_uid_at(&dir))?;
   let starttime = read_starttime_at(&dir)?;
   // A pid without an `exe` is still recorded: the uid and start time are known, and
   // leaving `exe` empty is what keeps the cache from inventing a rule key.
   Some(CachedIdentity {
      exe: fs::read_link(dir.join("exe")).ok(),
      comm: read_comm_at(&dir).unwrap_or_default(),
      uid,
      starttime,
   })
}

/// Reads a process directory's `comm`, trimmed, when it is non-empty.
fn read_comm_at(dir: &Path) -> Option<String> {
   fs::read_to_string(dir.join("comm"))
      .ok()
      .map(|text| text.trim().to_owned())
      .filter(|text| !text.is_empty())
}

/// Reads the `Uid:` line of a process directory's `status`.
fn read_status_uid_at(dir: &Path) -> Option<u32> {
   let text = fs::read_to_string(dir.join("status")).ok()?;
   status_uid(&text)
}

/// Parses the first field of the `Uid:` line (the real uid) from `/proc/<pid>/status`.
fn status_uid(text: &str) -> Option<u32> {
   text
      .lines()
      .find_map(|line| line.strip_prefix("Uid:"))
      .and_then(|rest| rest.split_whitespace().next())
      .and_then(|uid| uid.parse().ok())
}

/// Reads field 22 (`starttime`) of a process directory's `stat`.
fn read_starttime_at(dir: &Path) -> Option<u64> {
   let text = fs::read_to_string(dir.join("stat")).ok()?;
   stat_starttime(&text)
}

/// Parses field 22 of one `/proc/<pid>/stat` line.
///
/// The second field, `comm`, is parenthesised and may itself contain spaces, digits and
/// parentheses, so the fields after it start at the last `)`; splitting from there keeps a
/// process named `) 1 2 (` from shifting every later field.
fn stat_starttime(text: &str) -> Option<u64> {
   let rest = &text[text.rfind(')')? + 1..];
   rest.split_whitespace().nth(19)?.parse().ok()
}

/// Reads the process identity, or `None` when it can no longer be read.
///
/// `/proc/<pid>/exe` is the rule key, so a process that vanished before it could be read
/// is `Unknown` rather than a `ProcessInfo` with a guessed identity.
fn read_process(pid: u32, uid: u32) -> Option<ProcessInfo> {
   let exe = fs::read_link(format!("{PROC}/{pid}/exe")).ok()?;
   let comm = read_comm_at(Path::new(PROC).join(pid.to_string()).as_path());
   let cmdline = fs::read(format!("{PROC}/{pid}/cmdline"))
      .ok()
      .and_then(|bytes| join_cmdline(&bytes));
   Some(ProcessInfo {
      pid,
      uid,
      exe: Some(exe),
      comm,
      cmdline,
   })
}

/// Joins NUL-separated `cmdline` arguments with spaces, truncated at 4 KiB.
fn join_cmdline(bytes: &[u8]) -> Option<String> {
   let args: Vec<String> = bytes
      .split(|byte| *byte == 0)
      .filter(|arg| !arg.is_empty())
      .map(|arg| String::from_utf8_lossy(arg).into_owned())
      .collect();
   if args.is_empty() {
      return None;
   }
   let mut joined = args.join(" ");
   if joined.len() > MAX_CMDLINE {
      let mut end = MAX_CMDLINE;
      while !joined.is_char_boundary(end) {
         end -= 1;
      }
      joined.truncate(end);
   }
   Some(joined)
}

/// Renders an endpoint for a log message.
fn endpoint_label((addr, port): (IpAddr, u16)) -> String {
   match addr {
      IpAddr::V6(addr) => format!("[{addr}]:{port}"),
      IpAddr::V4(addr) => format!("{addr}:{port}"),
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::net::UdpSocket;

   /// `/proc/net/tcp` captured on the development machine (kernel 7.0.0-38-generic,
   /// Ubuntu) with two listening sockets, plus the matching `/proc/net/tcp6` loopback
   /// row. They are verbatim kernel output, including the header line the parser skips.
   const TCP_FIXTURE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 12311 1 0000000000000000 100 0 0 10 5
   1: 0100007F:0C08 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 233146 1 0000000000000000 100 0 0 10 0
";

   /// `/proc/net/udp` captured on the development machine, in the same verbatim style as
   /// the TCP fixtures: one unconnected DNS socket that has only `sendto()`-ed (the kernel
   /// keeps the wildcard local address and an unspecified remote while the queued packet
   /// carries the interface address), one connected socket on another port, a duplicate
   /// port-only socket that shares its port, and TIME_WAIT-style rows with inode 0.
   const UDP_FIXTURE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:8000 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 34567 2 0000000000000000 0
   1: 00000000:8001 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 34570 2 0000000000000000 0
   2: 0501A8C0:8001 01010101:0035 01 00000000:00000000 00:00000000 00000000  1000        0 45678 1 0000000000000000 20 4 30 10 -1
   3: 00000000:8002 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 0 2 0000000000000000 0
   4: 00000000:8002 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 45679 2 0000000000000000 0
   5: 00000000:8003 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 0 2 0000000000000000 0
";

   /// `/proc/net/udp6` captured on the same machine: an unconnected `[::]` socket.
   const UDP6_FIXTURE: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:8000 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 56789 2 0000000000000000 0
";

   /// `/proc/net/tcp6` captured on the same machine: the `::1:631` listener row.
   const TCP6_FIXTURE: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 11054 1 0000000000000000 100 0 0 10 0
";

   /// A `/proc/net/tcp` row left by a closed connection: the 4-tuple is still recorded,
   /// but the row has no live socket and reports `inode 0` (state `06`, TIME_WAIT).
   const TCP_CLOSED_FIXTURE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0401A8C0:D67E 0679528C:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 100 0 0 10 -1
";

   fn v4(address: [u8; 4], port: u16) -> (IpAddr, u16) {
      (IpAddr::V4(Ipv4Addr::from(address)), port)
   }

   fn v6(address: Ipv6Addr, port: u16) -> (IpAddr, u16) {
      (IpAddr::V6(address), port)
   }

   fn own_uid() -> u32 {
      fs::metadata(format!("{PROC}/{}", std::process::id()))
         .expect("read our own /proc entry")
         .uid()
   }

   /// The exact-match lookup as TCP uses it; the existing fixtures exercise this path.
   fn find_inode(
      text: &str,
      family: Family,
      local: (IpAddr, u16),
      remote: (IpAddr, u16),
   ) -> Option<u32> {
      inode_candidates(text, family, local, remote, L4Proto::Tcp)
         .first()
         .and_then(|inode| u32::try_from(*inode).ok())
   }

   #[test]
   fn ipv4_column_is_little_endian() {
      assert_eq!(
         decode_endpoint("0100007F:0C08", Family::V4),
         Some(v4([127, 0, 0, 1], 3080))
      );
      assert_eq!(
         decode_endpoint("3500007F:0035", Family::V4),
         Some(v4([127, 0, 0, 53], 53))
      );
      assert_eq!(
         decode_endpoint("00000000:0000", Family::V4),
         Some(v4([0, 0, 0, 0], 0))
      );
      assert_eq!(decode_endpoint("0100007F", Family::V4), None);
      assert_eq!(decode_endpoint("not-hex:0000", Family::V4), None);
   }

   #[test]
   fn ipv6_column_is_four_little_endian_groups() {
      assert_eq!(
         decode_endpoint(
            "00000000000000000000000001000000:0277",
            Family::V6
         ),
         Some(v6(Ipv6Addr::LOCALHOST, 631))
      );
      // A real Cloudflare-facing remote from /proc/net/tcp6: 2606:4700::6810:...
      assert_eq!(
         decode_endpoint(
            "00470626000000000000000068081A68:01BB",
            Family::V6
         ),
         Some(v6(
            "2606:4700::681a:868".parse().expect("literal"),
            443
         ))
      );
      assert_eq!(decode_endpoint("...:0000", Family::V6), None);
   }

   #[test]
   fn fixture_matching_finds_the_right_inode() {
      let local = v4([127, 0, 0, 1], 3080);
      let remote = v4([0, 0, 0, 0], 0);
      assert_eq!(
         find_inode(TCP_FIXTURE, Family::V4, local, remote),
         Some(233_146)
      );

      // The first row is the resolved stub listener on 127.0.0.53:53, not on 127.0.0.1.
      assert_eq!(
         find_inode(
            TCP_FIXTURE,
            Family::V4,
            v4([127, 0, 0, 53], 53),
            remote
         ),
         Some(12_311)
      );
   }

   #[test]
   fn fixture_matching_returns_none_when_no_row_matches() {
      let local = v4([127, 0, 0, 1], 9999);
      assert_eq!(
         find_inode(
            TCP_FIXTURE,
            Family::V4,
            local,
            v4([0, 0, 0, 0], 0)
         ),
         None
      );
      // Same local endpoint but a remote that no row records.
      assert_eq!(
         find_inode(
            TCP_FIXTURE,
            Family::V4,
            v4([127, 0, 0, 1], 3080),
            v4([127, 0, 0, 9], 9)
         ),
         None
      );
   }

   #[test]
   fn fixture_matching_works_for_ipv6() {
      assert_eq!(
         find_inode(
            TCP6_FIXTURE,
            Family::V6,
            v6(Ipv6Addr::LOCALHOST, 631),
            v6(Ipv6Addr::UNSPECIFIED, 0)
         ),
         Some(11_054)
      );
   }

   #[test]
   fn unconnected_udp_row_is_found_by_local_port() {
      // The packet carries the interface address; the unconnected socket row keeps the
      // wildcard local address and an unspecified remote, so an exact match cannot find it.
      assert_eq!(
         inode_candidates(
            UDP_FIXTURE,
            Family::V4,
            v4([192, 168, 1, 5], 32768),
            v4([1, 1, 1, 1], 53),
            L4Proto::Udp
         ),
         vec![34_567]
      );
   }

   #[test]
   fn connected_udp_row_is_matched_exactly_and_wins_over_a_port_only_row() {
      // Row 2 is connect()ed: real local address and real remote. Row 1 is an unconnected
      // socket on the same local port, so it is a valid port-only candidate for the same
      // tuple, yet the exact row must win.
      assert_eq!(
         inode_candidates(
            UDP_FIXTURE,
            Family::V4,
            v4([192, 168, 1, 5], 32769),
            v4([1, 1, 1, 1], 53),
            L4Proto::Udp
         ),
         vec![45_678]
      );
      // Prove row 1 really is a candidate for that local port by changing only the remote.
      assert_eq!(
         inode_candidates(
            UDP_FIXTURE,
            Family::V4,
            v4([192, 168, 1, 5], 32769),
            v4([9, 9, 9, 9], 53),
            L4Proto::Udp
         ),
         vec![34_570]
      );
   }

   #[test]
   fn udp_port_only_candidate_must_share_the_local_port() {
      // The fixture holds unconnected rows on ports 32768..32771; a packet on any other
      // local port must not be matched to them just because the remote is unspecified.
      assert_eq!(
         inode_candidates(
            UDP_FIXTURE,
            Family::V4,
            v4([192, 168, 1, 5], 40_000),
            v4([1, 1, 1, 1], 53),
            L4Proto::Udp
         ),
         Vec::<u64>::new()
      );
   }

   #[test]
   fn tcp_never_falls_back_to_local_port_only() {
      // The row's local port matches the packet, but its remote is the wildcard; TCP has
      // no port-only stage, so this must stay unattributed.
      assert_eq!(
         inode_candidates(
            TCP_FIXTURE,
            Family::V4,
            v4([127, 0, 0, 1], 3080),
            v4([127, 0, 0, 1], 9),
            L4Proto::Tcp
         ),
         Vec::<u64>::new()
      );
   }

   #[test]
   fn unconnected_udp6_row_matches_an_ipv6_packet() {
      let local = v6("2001:db8::1".parse().expect("literal"), 32768);
      let remote = v6(
         "2606:4700::681a:868".parse().expect("literal"),
         53,
      );
      assert_eq!(
         inode_candidates(
            UDP6_FIXTURE,
            Family::V6,
            local,
            remote,
            L4Proto::Udp
         ),
         vec![56_789]
      );
   }

   #[test]
   fn unconnected_udp_rows_with_inode_zero_are_skipped() {
      // Port 32770 has a zero-inode row and a live row; only the live inode is a candidate.
      assert_eq!(
         inode_candidates(
            UDP_FIXTURE,
            Family::V4,
            v4([192, 168, 1, 5], 32770),
            v4([1, 1, 1, 1], 53),
            L4Proto::Udp
         ),
         vec![45_679]
      );
      // Port 32771 only has a zero-inode row: nothing to attribute.
      assert_eq!(
         inode_candidates(
            UDP_FIXTURE,
            Family::V4,
            v4([192, 168, 1, 5], 32771),
            v4([1, 1, 1, 1], 53),
            L4Proto::Udp
         ),
         Vec::<u64>::new()
      );
   }

   #[test]
   fn exact_row_with_inode_zero_is_not_a_candidate_for_any_protocol() {
      let local = v4([192, 168, 1, 4], 54910);
      let remote = v4([140, 82, 121, 6], 443);
      // The row matches the flow exactly, but its socket is gone: it must not become a
      // candidate, because no process can hold an inode-0 descriptor.
      assert_eq!(
         inode_candidates(
            TCP_CLOSED_FIXTURE,
            Family::V4,
            local,
            remote,
            L4Proto::Tcp
         ),
         Vec::<u64>::new()
      );
      assert_eq!(
         inode_candidates(
            TCP_CLOSED_FIXTURE,
            Family::V4,
            local,
            remote,
            L4Proto::Udp
         ),
         Vec::<u64>::new()
      );
   }

   #[test]
   fn closed_connection_reports_no_live_socket_not_a_scan_miss() {
      let local = v4([192, 168, 1, 4], 54910);
      let remote = v4([140, 82, 121, 6], 443);
      let (reason, count) = candidate_failure_reason(TCP_CLOSED_FIXTURE, Family::V4, local, remote);
      assert_eq!(
         count,
         Some(0),
         "the exact row exists, with no live socket"
      );
      assert!(
         reason.contains("no live socket"),
         "the closed row must be named as such: {reason}"
      );
      assert!(
         !reason.contains("/proc fd link"),
         "a closed socket is not a scan miss: {reason}"
      );

      // A flow with no row at all is the other distinct outcome, and the candidate count
      // stays unknown because nothing was found to count.
      let (reason, count) = candidate_failure_reason(
         TCP_CLOSED_FIXTURE,
         Family::V4,
         v4([192, 168, 1, 4], 40_000),
         remote,
      );
      assert_eq!(count, None);
      assert_eq!(reason, "no matching socket row in the table");
   }

   #[test]
   fn udp_ambiguity_uses_the_packet_uid_to_pick_the_owner() {
      let candidates = [11u64, 22, 33];
      let owner_of = |inode: u32| match inode {
         11 => None,
         22 => Some((100, 991)),
         33 => Some((200, 1000)),
         _ => None,
      };

      // The first live candidate is owned by uid 1000, the second by the packet's 991; the
      // uid cross-check must walk past the first to the one that agrees.
      assert_eq!(
         candidate_owner(&candidates, Some(991), owner_of),
         CandidateOwner::Found {
            inode: 22,
            pid: 100,
            uid: 991,
         }
      );
      // Without the kernel uid there is no evidence to choose, so ambiguity is Unknown.
      assert_eq!(
         candidate_owner(&candidates, None, owner_of),
         CandidateOwner::Ambiguous
      );
      // A uid that owns none of the candidates is refused, not guessed.
      assert_eq!(
         candidate_owner(&candidates, Some(7), owner_of),
         CandidateOwner::Mismatch {
            inode: 22,
            pid: 100,
            packet_uid: 7,
            owner_uid: 991,
         }
      );
   }

   #[test]
   fn socket_link_parses_only_socket_targets() {
      assert_eq!(
         socket_link_inode("socket:[233146]"),
         Some(233_146)
      );
      assert_eq!(socket_link_inode("/dev/null"), None);
      assert_eq!(socket_link_inode("pipe:[12]"), None);
      assert_eq!(socket_link_inode("socket:[not-a-number]"), None);
   }

   #[test]
   fn cmdline_joins_nul_separated_arguments_and_drops_the_tail() {
      assert_eq!(
         join_cmdline(b"/usr/bin/firefox\0--new-window\0"),
         Some("/usr/bin/firefox --new-window".to_owned())
      );
      assert_eq!(join_cmdline(b"\0\0"), None);

      let mut big = vec![b'a'; MAX_CMDLINE + 100];
      big[MAX_CMDLINE - 1] = 0;
      let joined = join_cmdline(&big).expect("long cmdline");
      assert!(joined.len() <= MAX_CMDLINE);
   }

   #[test]
   fn icmp_is_unknown_without_touching_a_table() {
      let mut attributor = Attributor::new();
      let attribution = attributor.attribute(
         v4([127, 0, 0, 1], 5000),
         v4([127, 0, 0, 1], 5001),
         L4Proto::Icmp,
         Some(1000),
      );
      assert_eq!(attribution, Attribution::Unknown);
      assert_eq!(attributor.stats().misses, 1);
   }

   #[test]
   fn live_self_test_attributes_our_own_udp_socket() {
      let socket = UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
      socket.connect("127.0.0.1:9").expect("connect the datagram socket");
      let local = socket.local_addr().expect("local address");
      let peer = socket.peer_addr().expect("peer address");
      let uid = own_uid();

      let mut attributor = Attributor::new();
      let attribution = attributor.attribute(
         (local.ip(), local.port()),
         (peer.ip(), peer.port()),
         L4Proto::Udp,
         Some(uid),
      );

      match &attribution {
         Attribution::Process(process) => {
            assert_eq!(
               process.pid,
               std::process::id(),
               "live /proc chain attributed the socket to {:?}, expected our pid {}",
               process,
               std::process::id()
            );
            assert_eq!(process.uid, uid);
            assert!(
               process.exe.is_some(),
               "our /proc/<pid>/exe must be readable"
            );
         }
         Attribution::Unknown => panic!(
            "live attribution of {:?} -> {:?} failed; stats {:?}",
            local,
            peer,
            attributor.stats()
         ),
      }
      assert_eq!(attributor.stats().hits, 1);
      assert_eq!(attributor.stats().misses, 0);
   }

   #[test]
   fn live_lookup_with_a_wrong_uid_is_unknown() {
      let socket = UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
      socket.connect("127.0.0.1:9").expect("connect the datagram socket");
      let local = socket.local_addr().expect("local address");
      let peer = socket.peer_addr().expect("peer address");

      let mut attributor = Attributor::new();
      let attribution = attributor.attribute(
         (local.ip(), local.port()),
         (peer.ip(), peer.port()),
         L4Proto::Udp,
         Some(own_uid().wrapping_add(1)),
      );
      assert_eq!(attribution, Attribution::Unknown);
      assert_eq!(attributor.stats().misses, 1);
   }

   #[test]
   fn unattributable_tuple_is_unknown_and_counts_a_miss() {
      let mut attributor = Attributor::new();
      let attribution = attributor.attribute(
         v4([127, 0, 0, 1], 1),
         v4([192, 0, 2, 1], 65_000),
         L4Proto::Tcp,
         Some(own_uid()),
      );
      assert_eq!(attribution, Attribution::Unknown);
      assert_eq!(attributor.stats().misses, 1);
      assert_eq!(attributor.stats().hits, 0);
      assert_eq!(attributor.stats().scan_budget_exhausted, 0);
   }

   #[test]
   fn failure_message_names_flow_protocol_table_uid_and_candidates() {
      let context = FailureContext {
         local: v4([192, 168, 1, 5], 32768),
         remote: v4([1, 1, 1, 1], 53),
         proto: L4Proto::Udp,
         uid: None,
         table: Some("udp"),
         candidates: Some(1),
      };
      let message = failure_message(&context, "no /proc fd link holds the inode");
      assert!(message.contains("udp "), "{message}");
      assert!(
         message.contains("192.168.1.5:32768 -> 1.1.1.1:53"),
         "{message}"
      );
      assert!(message.contains("uid=none"), "{message}");
      assert!(message.contains("table=udp"), "{message}");
      assert!(message.contains("cand=1"), "{message}");
      assert!(
         message.len() < 160,
         "too long ({}): {message}",
         message.len()
      );

      let with_uid = FailureContext {
         uid: Some(1000),
         ..context
      };
      let message = failure_message(&with_uid, "no matching socket row in the table");
      assert!(message.contains("uid=Some(1000)"), "{message}");
   }

   #[test]
   fn failure_message_renders_a_missing_table_and_candidate_count() {
      let context = FailureContext {
         local: v6(
            "2606:4700:4700::1111".parse().expect("literal"),
            5353,
         ),
         remote: v6(
            "2606:4700:4700::1001".parse().expect("literal"),
            53,
         ),
         proto: L4Proto::Udp,
         uid: None,
         table: None,
         candidates: None,
      };
      let message = failure_message(&context, "local address has no family");
      assert!(
         message.contains("[2606:4700:4700::1111]:5353 ->"),
         "{message}"
      );
      assert!(message.contains("uid=none"), "{message}");
      assert!(message.contains("table=no-table"), "{message}");
      assert!(message.contains("cand=-"), "{message}");
   }

   fn flow(local_port: u16, remote_port: u16) -> FlowKey {
      (
         L4Proto::Udp,
         v4([10, 0, 0, 2], local_port),
         v4([1, 1, 1, 1], remote_port),
      )
   }

   #[test]
   fn flow_cache_returns_the_same_owner_without_rescanning_proc() {
      let mut attributor = Attributor::new();
      let flow = flow(50_000, 53);
      let start = Instant::now();
      attributor.remember_flow(
         flow,
         FlowCacheEntry {
            pid: 4242,
            uid: 1000,
            at: start,
         },
      );

      // A second call inside the TTL is answered from the flow cache alone; the test
      // would have no `/proc` row for this synthetic tuple, so a scan could not pass.
      assert_eq!(
         attributor.cached_flow(
            flow,
            Some(1000),
            start + StdDuration::from_millis(300)
         ),
         Some((4242, 1000))
      );
      assert_eq!(
         attributor.cached_flow(flow, Some(1000), start + CACHE_TTL),
         None,
         "an entry at the TTL bound is stale"
      );
      assert!(
         attributor.flow_owners.is_empty(),
         "expired entries are dropped"
      );
   }

   #[test]
   fn flow_cache_answers_a_second_lookup_after_the_socket_closed() {
      let socket = UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
      socket.connect("127.0.0.1:9").expect("connect the datagram socket");
      let local = socket.local_addr().expect("local address");
      let peer = socket.peer_addr().expect("peer address");
      let uid = own_uid();

      let mut attributor = Attributor::new();
      let first = attributor.attribute(
         (local.ip(), local.port()),
         (peer.ip(), peer.port()),
         L4Proto::Udp,
         Some(uid),
      );
      assert!(matches!(first, Attribution::Process(_)));
      drop(socket);

      // The socket is gone, so the table/scan path would now miss; the flow cache must
      // answer with the owner it was told about for this still-fresh tuple.
      let second = attributor.attribute(
         (local.ip(), local.port()),
         (peer.ip(), peer.port()),
         L4Proto::Udp,
         Some(uid),
      );
      assert_eq!(first, second);
      assert_eq!(attributor.stats().hits, 2);
      assert_eq!(attributor.stats().misses, 0);
   }

   #[test]
   fn flow_cache_refuses_a_cached_owner_that_disagrees_with_the_packet_uid() {
      let mut attributor = Attributor::new();
      let flow = flow(50_001, 53);
      let start = Instant::now();
      attributor.remember_flow(
         flow,
         FlowCacheEntry {
            pid: 1,
            uid: 1000,
            at: start,
         },
      );
      assert_eq!(
         attributor.cached_flow(flow, Some(0), start + StdDuration::from_millis(1)),
         None
      );
      assert!(attributor.flow_owners.is_empty());
   }

   #[test]
   fn flow_cache_is_bounded_to_a_few_hundred_entries() {
      let mut attributor = Attributor::new();
      let start = Instant::now();
      for port in 0..(MAX_FLOWS as u16 + 16) {
         attributor.remember_flow(
            flow(20_000, port),
            FlowCacheEntry {
               pid: 1,
               uid: 1,
               at: start,
            },
         );
      }
      assert!(attributor.flow_owners.len() <= MAX_FLOWS);
   }

   #[test]
   fn negative_flow_entry_expires_after_its_short_ttl() {
      let mut attributor = Attributor::new();
      let flow = flow(50_002, 53);
      let start = Instant::now();
      attributor.mark_flow_miss(flow, start);

      assert!(attributor.flow_miss_active(flow, start + StdDuration::from_millis(500)));
      assert!(!attributor.flow_miss_active(flow, start + NEGATIVE_TTL));
      assert!(!attributor.flow_misses.contains_key(&flow));
   }

   #[test]
   fn a_later_success_clears_the_negative_marker_and_the_miss_streak() {
      let mut attributor = Attributor::new();
      let flow = flow(50_003, 53);
      let class = (Some(1000), L4Proto::Udp, 53);
      let start = Instant::now();
      attributor.mark_flow_miss(flow, start);
      attributor.record_miss(L4Proto::Udp, flow.2, Some(1000), start);
      assert_eq!(attributor.miss_streaks[&class].consecutive, 1);

      attributor.remember_success(
         flow,
         FlowCacheEntry {
            pid: 777,
            uid: 1000,
            at: start,
         },
         class,
      );
      assert!(!attributor.flow_misses.contains_key(&flow));
      assert!(!attributor.miss_streaks.contains_key(&class));
      assert_eq!(
         attributor.cached_flow(
            flow,
            Some(1000),
            start + StdDuration::from_millis(1)
         ),
         Some((777, 1000)),
         "the success must overwrite the negative entry"
      );
   }

   #[test]
   fn stale_negative_fd_snapshot_still_finds_a_newly_opened_socket() {
      let pid = std::process::id();
      let uid = own_uid();
      let inode = 987_654u32;
      let mut attributor = Attributor::new();
      // Seed the cache with the snapshot that predates the socket: same pid, no inode X.
      attributor.pid_fds.insert(
         pid,
         FdCacheEntry {
            inodes: vec![123],
            uid,
            at: Instant::now(),
         },
      );

      let mut reads = 0u32;
      let owner = attributor.scan_pids_for_inode(vec![pid], inode, Some(uid), |scanned| {
         assert_eq!(
            scanned, pid,
            "the injected read is for our own pid"
         );
         reads += 1;
         Ok(vec![123, inode])
      });
      assert_eq!(
         owner,
         Some((pid, uid)),
         "a negative fd snapshot must be refreshed, not trusted"
      );
      assert_eq!(reads, 1, "one pid, one refresh per lookup");

      // The refreshed snapshot is now the fast path: a positive answer must not re-read.
      let mut reads = 0u32;
      let cached = attributor.scan_pids_for_inode(vec![pid], inode, Some(uid), |scanned| {
         assert_eq!(scanned, pid);
         reads += 1;
         Ok(vec![inode])
      });
      assert_eq!(cached, Some((pid, uid)));
      assert_eq!(
         reads, 0,
         "a cached positive must not re-read /proc"
      );
   }

   #[test]
   fn a_missed_pid_is_refreshed_only_once_per_lookup() {
      let pid = std::process::id();
      let uid = own_uid();
      let mut reads = 0u32;
      let mut attributor = Attributor::new();
      let owner = attributor.scan_pids_for_inode(vec![pid], 4242, Some(uid), |scanned| {
         assert_eq!(scanned, pid);
         reads += 1;
         Ok(vec![123])
      });
      assert_eq!(owner, None);
      assert_eq!(
         reads, 1,
         "one pid is read at most once per lookup"
      );
   }

   #[test]
   fn miss_warning_fires_once_for_six_misses_and_again_after_suppression() {
      let mut attributor = Attributor::new();
      let start = Instant::now();
      let remote = flow(50_004, 53).2;
      let key = (None, L4Proto::Udp, 53);
      let mut warnings = Vec::new();
      for step in 0..6 {
         let now = start + StdDuration::from_millis(step * 10);
         if let Some(message) = attributor.miss_warning(key, L4Proto::Udp, remote, None, now) {
            warnings.push(message);
         }
      }
      assert_eq!(
         warnings.len(),
         1,
         "one warning for the burst: {warnings:?}"
      );
      assert!(
         warnings[0].contains("1.1.1.1:53"),
         "{}",
         warnings[0]
      );
      assert!(
         warnings[0].contains("uid=none"),
         "{}",
         warnings[0]
      );
      assert!(
         warnings[0].contains("cannot map udp flows"),
         "{}",
         warnings[0]
      );

      let later = start + MISS_WARN_SUPPRESSION - StdDuration::from_secs(1);
      assert_eq!(
         attributor.miss_warning(key, L4Proto::Udp, remote, None, later),
         None,
         "a warning inside the suppression window is dropped"
      );
      let after = start + MISS_WARN_SUPPRESSION + StdDuration::from_secs(1);
      let message = attributor
         .miss_warning(key, L4Proto::Udp, remote, None, after)
         .expect("a warning after the suppression window");
      assert!(message.contains("1.1.1.1:53"), "{message}");
   }

   #[test]
   fn miss_warning_treats_different_flow_classes_separately() {
      let mut attributor = Attributor::new();
      let start = Instant::now();
      let remote = flow(50_005, 53).2;
      for step in 0..5 {
         let now = start + StdDuration::from_millis(step);
         let _ = attributor.miss_warning(
            (None, L4Proto::Udp, 53),
            L4Proto::Udp,
            remote,
            None,
            now,
         );
      }
      let other = (Some(1000), L4Proto::Udp, 53);
      assert_eq!(
         attributor.miss_warning(other, L4Proto::Udp, remote, Some(1000), start),
         None,
         "a different uid is a different class"
      );
      assert_eq!(attributor.miss_streaks[&other].consecutive, 1);
   }

   #[test]
   fn failure_message_stays_one_line() {
      let context = FailureContext {
         local: v6(
            "2001:db8:1234:5678:9abc:def0:1234:5678".parse().expect("literal"),
            65535,
         ),
         remote: v6(
            "2606:4700:4700::1111".parse().expect("literal"),
            53,
         ),
         proto: L4Proto::Udp,
         uid: Some(u32::MAX),
         table: Some("udp6"),
         candidates: Some(MAX_UDP_CANDIDATES),
      };
      let message = failure_message(&context, "no /proc fd link holds the inode");
      assert!(!message.contains('\n'), "{message}");
      assert!(
         message.len() < 160,
         "too long ({}): {message}",
         message.len()
      );
   }

   /// A fixed instant for ordering tests; values are offsets from it.
   fn at(offset: u64) -> SystemTime {
      SystemTime::UNIX_EPOCH + StdDuration::from_secs(1_000 + offset)
   }

   #[test]
   fn sort_pids_newest_first_orders_newest_first_with_stable_ties() {
      // Pids 10 and 11 share a timestamp: a stable sort keeps their readdir order.
      let entries = vec![
         (10, Some(at(1))),
         (20, Some(at(9))),
         (11, Some(at(1))),
         (30, Some(at(5))),
      ];
      assert_eq!(
         sort_pids_newest_first(entries),
         vec![20, 30, 10, 11]
      );
   }

   #[test]
   fn sort_pids_newest_first_puts_untimed_entries_last() {
      let entries = vec![(1, None), (2, Some(at(1))), (3, None), (4, Some(at(2)))];
      assert_eq!(
         sort_pids_newest_first(entries),
         vec![4, 2, 1, 3],
         "a pid with no readable time stays scannable, only last"
      );
   }

   #[test]
   fn sort_fds_newest_first_orders_newest_first_with_stable_ties() {
      let entries = vec![
         (OsString::from("a"), Some(at(1))),
         (OsString::from("b"), Some(at(9))),
         (OsString::from("c"), Some(at(1))),
      ];
      assert_eq!(
         sort_fds_newest_first(entries, MAX_FDS),
         vec![
            OsString::from("b"),
            OsString::from("a"),
            OsString::from("c")
         ]
      );
   }

   #[test]
   fn sort_fds_newest_first_puts_untimed_entries_last_and_keeps_the_newest() {
      let entries = vec![
         (OsString::from("stale"), Some(at(1))),
         (OsString::from("untimed"), None),
         (OsString::from("newest"), Some(at(9))),
         (OsString::from("middle"), Some(at(5))),
      ];
      // The cut-off must drop the oldest and the untimed descriptors, never the newest.
      assert_eq!(
         sort_fds_newest_first(entries, 2),
         vec![OsString::from("newest"), OsString::from("middle")]
      );
   }

   /// The descriptor ordering must read the link's own time. A socket link's target does
   /// not exist on disk, so following it yields no time at all and every socket would be
   /// sorted last — the inverse of what the scan needs.
   #[test]
   fn descriptor_mtime_is_the_link_time_not_the_target_time() {
      let nanos = SystemTime::now()
         .duration_since(std::time::UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      let dir = std::env::temp_dir().join(format!("netshield-fd-mtime-{nanos}"));
      fs::create_dir_all(&dir).expect("create the descriptor directory");
      std::os::unix::fs::symlink("socket:[4242]", dir.join("fd-socket"))
         .expect("create the socket link");

      let entry = fs::read_dir(&dir)
         .expect("read the descriptor directory")
         .next()
         .expect("one descriptor")
         .expect("a readable descriptor");
      assert!(
         entry.metadata().expect("link metadata").modified().is_ok(),
         "the socket link itself carries the descriptor's time"
      );
      assert!(
         fs::metadata(entry.path()).is_err(),
         "the link target does not exist, so following it must fail"
      );

      let _ = fs::remove_dir_all(&dir);
   }

   /// Creates a descriptor directory holding `MAX_FDS + 10` entries where the only socket
   /// is the newest: the budget may trim the directory but must still inspect that socket.
   #[test]
   fn descriptor_budget_keeps_the_newest_entries_and_still_finds_the_socket() {
      let nanos = SystemTime::now()
         .duration_since(std::time::UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      let dir = std::env::temp_dir().join(format!("netshield-fd-budget-{nanos}"));
      fs::create_dir_all(&dir).expect("create the descriptor directory");

      let inode = 987_654u32;
      // The stale descriptors are created first, so the socket link below is the newest
      // entry by creation order; temp-file mtimes have sub-second resolution.
      for index in 0..(MAX_FDS + 9) {
         fs::write(dir.join(format!("stale-{index}")), b"").expect("create a stale descriptor");
      }
      // A `/proc/<pid>/fd` socket link is a symlink to `socket:[<inode>]`; the ordering
      // reads the link's own time, so the target need not exist.
      std::os::unix::fs::symlink(format!("socket:[{inode}]"), dir.join("fd-socket"))
         .expect("create the socket link");
      // Timestamps are taken from the filesystem, so make the gap unambiguous rather than
      // relying on two writes landing in the same clock tick.
      let socket_link = dir.join("fd-socket");
      let newest = fs::symlink_metadata(&socket_link)
         .expect("read the socket link")
         .modified()
         .expect("the socket link has an mtime");
      for index in 0..(MAX_FDS + 9) {
         let stale = dir.join(format!("stale-{index}"));
         fs::File::options()
            .write(true)
            .open(&stale)
            .expect("open a stale descriptor")
            .set_modified(newest - StdDuration::from_secs(3_600))
            .expect("backdate a stale descriptor");
      }

      let pid = std::process::id();
      let uid = own_uid();
      let mut attributor = Attributor::new();
      let owner = attributor.scan_pids_for_inode(vec![pid], inode, Some(uid), |_| {
         read_fd_dir(dir.clone())
      });
      assert_eq!(
         owner,
         Some((pid, uid)),
         "the newest descriptor must be inspected even when the directory exceeds the budget"
      );
      assert_eq!(
         attributor.stats().scan_budget_exhausted,
         1,
         "the trimmed directory must still be reported as over budget"
      );

      let _ = fs::remove_dir_all(&dir);
   }

   /// A `/proc/<pid>` fixture holding the four files `ProcessCache::record` reads.
   fn proc_fixture(name: &str, exe: Option<&str>, comm: &str) -> PathBuf {
      let nanos = SystemTime::now()
         .duration_since(std::time::UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      let root = std::env::temp_dir().join(format!("netshield-{name}-{nanos}"));
      let dir = root.join("4242");
      fs::create_dir_all(&dir).expect("create the pid directory");
      if let Some(exe) = exe {
         std::os::unix::fs::symlink(exe, dir.join("exe")).expect("create the exe link");
      }
      fs::write(dir.join("comm"), format!("{comm}\n")).expect("write comm");
      fs::write(
         dir.join("status"),
         "Name:\tfirefox\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
      )
      .expect("write status");
      fs::write(
         dir.join("stat"),
         // Field 22 is 987654; the parentheses hold spaces and digits so a naive split
         // would shift the start time.
         "4242 (fi (re) fox) S 1 4242 4242 0 -1 4194560 0 0 0 0 12 34 0 0 20 0 1 0 987654 0",
      )
      .expect("write stat");
      root
   }

   #[test]
   fn process_cache_records_uid_starttime_and_exe() {
      let root = proc_fixture(
         "cache-hit",
         Some("/usr/lib/firefox/firefox"),
         "firefox",
      );
      let identity = identity_at(4242, &root).expect("a fully readable process");
      assert_eq!(identity.uid, 1000);
      assert_eq!(identity.starttime, 987_654);
      assert_eq!(identity.comm, "firefox");
      assert_eq!(
         identity.exe,
         Some(PathBuf::from("/usr/lib/firefox/firefox"))
      );

      let mut cache = ProcessCache::new();
      cache.insert(4242, identity.clone());
      assert_eq!(cache.get(4242), Some(&identity));
      assert_eq!(cache.len(), 1);

      cache.forget(4242);
      assert_eq!(cache.get(4242), None);
      assert!(cache.is_empty());

      let _ = fs::remove_dir_all(&root);
   }

   #[test]
   fn process_cache_tolerates_a_missing_exe() {
      // The racing-exit case: the pid directory is readable but `exe` is gone. The
      // identity must still be recorded so the uid and start time are known.
      let root = proc_fixture("cache-no-exe", None, "vanished");
      let identity = identity_at(4242, &root).expect("uid and start time are readable");
      assert_eq!(identity.exe, None);
      assert_eq!(identity.uid, 1000);
      assert_eq!(identity.starttime, 987_654);
      assert_eq!(identity.comm, "vanished");

      let _ = fs::remove_dir_all(&root);
   }

   #[test]
   fn process_cache_skips_a_pid_whose_metadata_is_gone() {
      let root = std::env::temp_dir().join("netshield-cache-missing");
      assert_eq!(identity_at(999_999, &root), None);
   }

   #[test]
   fn status_uid_reads_the_first_field_only() {
      let status = "Name:\tsleep\nUid:\t0\t1000\t1000\t1000\nGid:\t0\t1000\t1000\t1000\n";
      assert_eq!(status_uid(status), Some(0));
      assert_eq!(status_uid("Name:\tx\n"), None);
   }

   #[test]
   fn stat_starttime_ignores_comm_parentheses_and_spaces() {
      let stat = "7 (a (b) c) S 1 7 7 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 555 0";
      assert_eq!(stat_starttime(stat), Some(555));
      assert_eq!(stat_starttime("garbage"), None);
      assert_eq!(stat_starttime("7 (short)"), None);
   }

   #[test]
   fn a_cached_identity_never_answers_for_an_unheld_inode() {
      // The flow is not in any socket table, so the scan finds no owner. Even though the
      // cache knows a pid and its uid, the answer must stay Unknown: the cache carries
      // identity, never ownership.
      let mut cache = ProcessCache::new();
      cache.insert(
         4,
         CachedIdentity {
            exe: Some(PathBuf::from("/usr/bin/curl")),
            comm: "curl".to_owned(),
            uid: own_uid(),
            starttime: 1,
         },
      );
      let shared = Arc::new(Mutex::new(cache));
      let mut attributor = Attributor::with_process_cache(Arc::clone(&shared));
      let attribution = attributor.attribute(
         v4([127, 0, 0, 1], 1),
         v4([192, 0, 2, 1], 65_000),
         L4Proto::Tcp,
         Some(own_uid()),
      );
      assert_eq!(attribution, Attribution::Unknown);
      assert_eq!(attributor.stats().hits, 0);
      assert_eq!(attributor.stats().misses, 1);
      assert_eq!(
         shared.lock().expect("process cache").len(),
         1,
         "a lookup must not rewrite the identity cache with an ownership answer"
      );
   }

   #[test]
   fn a_cache_hit_with_a_disagreeing_uid_is_dropped_not_laundered() {
      // A pid belongs to uid 7; the packet claims uid 1000. The cached identity must not
      // be returned, because the descriptor scan's uid agreement check would then pass on
      // an identity that belongs to someone else.
      let pid = 999_999;
      let mut cache = ProcessCache::new();
      cache.insert(
         pid,
         CachedIdentity {
            exe: Some(PathBuf::from("/usr/bin/curl")),
            comm: "curl".to_owned(),
            uid: own_uid().wrapping_add(1),
            starttime: 1,
         },
      );
      let shared = Arc::new(Mutex::new(cache));
      let mut attributor = Attributor::with_process_cache(Arc::clone(&shared));
      let resolved = attributor.process_identity(pid, own_uid());
      assert!(
         resolved.is_none(),
         "a recycled pid must not reuse the old identity: {resolved:?}"
      );
      assert_eq!(
         shared.lock().expect("process cache").len(),
         0,
         "the stale identity is dropped"
      );
   }
}
