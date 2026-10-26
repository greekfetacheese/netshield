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
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration as StdDuration, Instant};

use log::{debug, warn};
use netshield_core::{Attribution, Family, L4Proto, ProcessInfo};

/// How long an inode→pid or pid→fd answer may be reused.
///
/// Short on purpose: inodes are recycled as soon as a socket closes, so a longer TTL could
/// attribute a new socket to the previous owner. One second still collapses the burst of
/// per-packet lookups a single connection produces.
const CACHE_TTL: StdDuration = StdDuration::from_secs(1);

/// Most pids one lookup may examine.
const MAX_PIDS: usize = 4096;

/// Most descriptors one pid's scan may examine.
const MAX_FDS: usize = 4096;

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

/// The `/proc` walker and its caches.
///
/// The caches are keyed by inode and by pid because the expensive half is the directory
/// scan, not the table parse: Firefox and Chrome hold hundreds of descriptors, and a
/// browser opening ten connections in a second would otherwise rescan the same fd
/// directories ten times.
#[derive(Debug)]
pub struct Attributor {
   inode_to_pid: HashMap<u32, InodeCacheEntry>,
   pid_fds: HashMap<u32, FdCacheEntry>,
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

impl Attributor {
   /// Creates an empty attributor with no cached answers.
   pub fn new() -> Self {
      Self {
         inode_to_pid: HashMap::new(),
         pid_fds: HashMap::new(),
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
      let Some(family) = family_of(local.0) else {
         return self.unknown("local address has no family");
      };
      if family_of(remote.0) != Some(family) {
         return self.unknown("flow endpoints mix address families");
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
         self.stats.misses += 1;
         return Attribution::Unknown;
      };

      let text = match fs::read_to_string(format!("{PROC}/net/{table}")) {
         Ok(text) => text,
         Err(error) => {
            return self.unknown(&format!("cannot read /proc/net/{table}: {error}"));
         }
      };
      let Some(inode) = find_inode(&text, family, local, remote) else {
         return self.unknown(&format!(
            "no /proc/net/{table} row for {} -> {}",
            endpoint_label(local),
            endpoint_label(remote)
         ));
      };
      if inode == 0 {
         // TIME_WAIT and friends keep a table row but no live socket to own it.
         return self.unknown("the matching socket row has inode 0");
      }

      let owner = match self.cached_owner(inode, uid) {
         Some(owner) => owner,
         None => match self.scan_for_inode(inode, uid) {
            Some(owner) => owner,
            None => {
               return self.unknown(&format!(
                  "no /proc/<pid>/fd link owns inode {inode}"
               ));
            }
         },
      };
      let (pid, process_uid) = owner;
      if let Some(packet_uid) = uid
         && packet_uid != process_uid
      {
         // The fd exists but belongs to someone else than the packet said: the socket
         // was reused between the queue and this scan. Guessing would grant the wrong
         // application's policy.
         self.stats.misses += 1;
         warn!(
            "attribution refused for inode {inode}: packet uid {packet_uid} but \
             /proc/{pid} is owned by uid {process_uid}"
         );
         return Attribution::Unknown;
      }

      let Some(process) = read_process(pid, process_uid) else {
         return self.unknown(&format!(
            "cannot read /proc/{pid} identity for inode {inode}"
         ));
      };
      self.inode_to_pid.insert(
         inode,
         InodeCacheEntry {
            pid,
            uid: process_uid,
            at: Instant::now(),
         },
      );
      self.stats.hits += 1;
      Attribution::Process(process)
   }

   /// Returns the per-lookup counters.
   pub fn stats(&self) -> AttributeStats {
      self.stats
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
      if pids.len() > MAX_PIDS {
         self.budget_exhausted(&format!(
            "pid scan would examine {} processes (budget {MAX_PIDS})",
            pids.len()
         ));
         return None;
      }

      for pid in pids {
         if let Some((found, owner)) = self.cached_fd_lookup(pid, inode, uid) {
            if found {
               return Some((pid, owner));
            }
            continue;
         }

         let owner_uid = match read_pid_uid(pid) {
            Some(owner_uid) => owner_uid,
            // The process exited between the directory read and this lookup.
            None => continue,
         };
         if uid.is_some_and(|wanted| wanted != owner_uid) {
            continue;
         }

         let inodes = match socket_inodes(pid) {
            Ok(inodes) => inodes,
            Err(ScanError::Budget) => {
               self.budget_exhausted(&format!(
                  "descriptor scan of pid {pid} exceeded {MAX_FDS} entries"
               ));
               return None;
            }
            Err(ScanError::Unreadable) => continue,
         };
         let found = inodes.contains(&inode);
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

   /// Records a miss and logs why attribution failed.
   fn unknown(&mut self, reason: &str) -> Attribution {
      self.stats.misses += 1;
      debug!("attribution failed: {reason}");
      Attribution::Unknown
   }
}

impl Default for Attributor {
   fn default() -> Self {
      Self::new()
   }
}

/// Why a pid's descriptor directory could not be scanned.
enum ScanError {
   /// The process vanished or its fds are not readable by this daemon.
   Unreadable,
   /// The directory held more entries than one lookup may examine.
   Budget,
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

/// Finds the inode of the row matching both endpoints.
///
/// Field layout, from the kernel's header: 1 local, 2 remote, 3 state, 7 uid, 9 inode.
/// A malformed or header line is skipped rather than treated as an error; the table is
/// kernel output and one unparsable line must not hide the socket on another line.
fn find_inode(
   text: &str,
   family: Family,
   local: (IpAddr, u16),
   remote: (IpAddr, u16),
) -> Option<u32> {
   for line in text.lines() {
      let fields: Vec<&str> = line.split_whitespace().collect();
      if fields.len() <= 9 {
         continue;
      }
      let Some(parsed_local) = decode_endpoint(fields[1], family) else {
         continue;
      };
      let Some(parsed_remote) = decode_endpoint(fields[2], family) else {
         continue;
      };
      if parsed_local == local && parsed_remote == remote {
         return fields[9].parse::<u32>().ok();
      }
   }
   None
}

/// Opens `/proc/<pid>/fd` and collects the socket inodes it holds.
fn socket_inodes(pid: u32) -> Result<Vec<u32>, ScanError> {
   let directory = fs::read_dir(format!("{PROC}/{pid}/fd")).map_err(|_| ScanError::Unreadable)?;
   let mut inodes = Vec::new();
   let mut seen = 0usize;
   for entry in directory {
      let Ok(entry) = entry else {
         continue;
      };
      seen += 1;
      if seen > MAX_FDS {
         return Err(ScanError::Budget);
      }
      let Ok(target) = fs::read_link(entry.path()) else {
         // A descriptor closed between readdir and readlink.
         continue;
      };
      if let Some(target) = target.to_str()
         && let Some(inode) = socket_link_inode(target)
      {
         inodes.push(inode);
      }
   }
   Ok(inodes)
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
   let path = PathBuf::from(format!("{PROC}/{pid}"));
   fs::metadata(path).ok().map(|meta| meta.uid())
}

/// Lists the numeric entries of `/proc`.
fn numeric_pids() -> Option<Vec<u32>> {
   let entries = fs::read_dir(PROC).ok()?;
   let mut pids = Vec::new();
   for entry in entries.flatten() {
      let Ok(name) = entry.file_name().into_string() else {
         continue;
      };
      if let Ok(pid) = name.parse::<u32>() {
         pids.push(pid);
      }
   }
   Some(pids)
}

/// Reads the process identity, or `None` when it can no longer be read.
///
/// `/proc/<pid>/exe` is the rule key, so a process that vanished before it could be read
/// is `Unknown` rather than a `ProcessInfo` with a guessed identity.
fn read_process(pid: u32, uid: u32) -> Option<ProcessInfo> {
   let exe = fs::read_link(format!("{PROC}/{pid}/exe")).ok()?;
   let comm = fs::read_to_string(format!("{PROC}/{pid}/comm"))
      .ok()
      .map(|text| text.trim().to_owned())
      .filter(|text| !text.is_empty());
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

   /// `/proc/net/tcp6` captured on the same machine: the `::1:631` listener row.
   const TCP6_FIXTURE: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 11054 1 0000000000000000 100 0 0 10 0
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
}
