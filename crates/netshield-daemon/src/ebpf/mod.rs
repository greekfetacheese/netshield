//! The in-kernel sender registry: the pid behind a flow, recorded at syscall time.
//!
//! `/proc` can only answer while the socket exists, so a flow whose socket closes before
//! [`crate::proc`] scans the tables is unattributable by construction. These two
//! tracepoint programs write the answer into a hash map at the moment `sendto` or
//! `connect` runs, which is before the caller can close the socket. The daemon asks the
//! map first and keeps `/proc` as the fallback, and [`SendRegistry::open`] failing simply
//! means that fallback is all there is — exactly the pre-registry behaviour.
//!
//! This module is the second sanctioned home for `unsafe` (see `AGENTS.md`): the kernel
//! ABI it speaks has no Rust wrapper that does not add a dependency.

mod syscall;

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use log::{info, warn};

/// How long a record may be believed. The daemon asks right after the packet is queued, so
/// the record is normally microseconds old; the window only exists because a clock is
/// cheaper to consult than a syscall.
const SENDER_TTL_NS: u64 = 2_000_000_000;

/// Bounded so the map costs at most ~200 kB of kernel memory.
const MAX_SENDERS: u32 = 4096;

/// Where tracefs may be mounted, in the order the kernel documents it.
const TRACEFS_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// The tracepoint whose `sockaddr` argument is read for a datagram send.
const SENDTO: &str = "sys_enter_sendto";

/// The tracepoint whose `sockaddr` argument is read for a connect.
const CONNECT: &str = "sys_enter_connect";

/// The kernel's list of online CPUs.
const CPU_ONLINE: &str = "/sys/devices/system/cpu/online";

/// A sanity bound on how many CPUs one registry may attach to.
const MAX_CPUS: usize = 4096;

// eBPF opcode pieces, from `include/uapi/linux/bpf.h`.
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_STX: u8 = 0x03;
const BPF_ALU64: u8 = 0x07;
const BPF_JMP: u8 = 0x05;
const BPF_MEM: u8 = 0x60;
const BPF_IMM: u8 = 0x00;
const BPF_X: u8 = 0x08;
const BPF_K: u8 = 0x00;
const BPF_W: u8 = 0x00;
const BPF_H: u8 = 0x08;
const BPF_DW: u8 = 0x18;
const BPF_MOV: u8 = 0xb0;
const BPF_ADD: u8 = 0x00;
const BPF_JNE: u8 = 0x50;
const BPF_JA: u8 = 0x00;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;

/// `BPF_PSEUDO_MAP_FD`: the `src_reg` of the first of the two instructions that load a
/// map descriptor into a register.
const BPF_PSEUDO_MAP_FD: u8 = 1;

/// `BPF_FUNC_probe_read_user`: copy a user pointer's bytes into the BPF stack.
const BPF_FUNC_PROBE_READ_USER: i32 = 112;

/// `BPF_FUNC_get_current_uid_gid`.
const BPF_FUNC_GET_CURRENT_UID_GID: i32 = 15;

/// `BPF_FUNC_get_current_pid_tgid`.
const BPF_FUNC_GET_CURRENT_PID_TGID: i32 = 14;

/// `BPF_FUNC_ktime_get_ns`.
const BPF_FUNC_KTIME_GET_NS: i32 = 5;

/// `BPF_FUNC_map_update_elem`.
const BPF_FUNC_MAP_UPDATE_ELEM: i32 = 2;

/// One eBPF instruction: the kernel's `struct bpf_insn`, byte-for-byte.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Insn {
   code: u8,
   /// `(src_reg << 4) | dst_reg`.
   dst_src: u8,
   off: i16,
   imm: i32,
}

/// Assembles one instruction from its parts.
const fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
   Insn {
      code,
      dst_src: (src << 4) | dst,
      off,
      imm,
   }
}

fn ldx_dw(dst: u8, src: u8, off: i16) -> Insn {
   insn(BPF_LDX | BPF_MEM | BPF_DW, dst, src, off, 0)
}

fn ldx_h(dst: u8, src: u8, off: i16) -> Insn {
   insn(BPF_LDX | BPF_MEM | BPF_H, dst, src, off, 0)
}

fn ldx_w(dst: u8, src: u8, off: i16) -> Insn {
   insn(BPF_LDX | BPF_MEM | BPF_W, dst, src, off, 0)
}

fn stx_dw(dst: u8, off: i16, src: u8) -> Insn {
   insn(BPF_STX | BPF_MEM | BPF_DW, dst, src, off, 0)
}

fn stx_w(dst: u8, off: i16, src: u8) -> Insn {
   insn(BPF_STX | BPF_MEM | BPF_W, dst, src, off, 0)
}

fn stx_h(dst: u8, off: i16, src: u8) -> Insn {
   insn(BPF_STX | BPF_MEM | BPF_H, dst, src, off, 0)
}

fn mov64_reg(dst: u8, src: u8) -> Insn {
   insn(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
}

fn mov64_imm(dst: u8, imm: i32) -> Insn {
   insn(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
}

fn add64_imm(dst: u8, imm: i32) -> Insn {
   insn(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
}

fn jne_imm(dst: u8, imm: i32, off: i16) -> Insn {
   insn(BPF_JMP | BPF_JNE | BPF_K, dst, 0, off, imm)
}

fn ja(off: i16) -> Insn {
   insn(BPF_JMP | BPF_JA, 0, 0, off, 0)
}

fn call(func: i32) -> Insn {
   insn(BPF_JMP | BPF_CALL, 0, 0, 0, func)
}

fn exit() -> Insn {
   insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
}

/// Loads map `map_fd` into `dst`: a pseudo map descriptor load followed by the zero
/// instruction the encoding reserves for the upper 32 bits of the immediate.
fn ld_map_fd(dst: u8, map_fd: i32) -> [Insn; 2] {
   [
      insn(
         BPF_LD | BPF_DW | BPF_IMM,
         dst,
         BPF_PSEUDO_MAP_FD,
         0,
         map_fd,
      ),
      insn(0, 0, 0, 0, 0),
   ]
}

/// The BPF program's key: who sent, and where. Layout is shared with the in-kernel program,
/// so every field order and size is load-bearing.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FlowKey {
   uid: u32,
   family: u16,
   /// Network byte order, as the `sockaddr` carries it.
   dport: u16,
   /// v4 in the first four bytes, the rest zero.
   addr: [u8; 16],
}

/// The BPF program's value.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FlowVal {
   /// `bpf_get_current_pid_tgid`: tgid in the high half, pid in the low half.
   pid_tgid: u64,
   /// `bpf_ktime_get_ns` at record time.
   ts_ns: u64,
}

/// Builds the one tracepoint program, which differs between `sendto` and `connect` only in
/// the context offset that holds the user's `sockaddr` pointer.
///
/// The frame layout is fixed by the program: the copied `sockaddr` sits at `fp-32`, the key
/// at `fp-56` and the value at `fp-72`.
fn program(map_fd: i32, sockaddr_offset: i16) -> Vec<Insn> {
   let map = ld_map_fd(1, map_fd);
   vec![
      ldx_dw(3, 1, sockaddr_offset), // r3 = the user's sockaddr pointer from the ctx
      mov64_reg(1, 10),              // r1 = fp
      add64_imm(1, -32),             // dst = fp-32
      mov64_imm(2, 28),              // size = sizeof(sockaddr_in6)
      call(BPF_FUNC_PROBE_READ_USER),
      jne_imm(0, 0, 31), // read failed (a NULL addr from connect/sendto misuse) -> index 37
      mov64_imm(0, 0),
      stx_dw(10, -40, 0), // zero the key area fp-56..fp-33
      stx_dw(10, -48, 0),
      stx_dw(10, -56, 0),
      call(BPF_FUNC_GET_CURRENT_UID_GID),
      stx_w(10, -56, 0), // key.uid
      ldx_h(0, 10, -32),
      stx_h(10, -52, 0), // key.family
      ldx_h(0, 10, -30),
      stx_h(10, -50, 0), // key.dport
      ldx_h(0, 10, -32),
      jne_imm(0, 2, 3),  // not AF_INET -> v6 block at 21
      ldx_w(0, 10, -28), // v4 address
      stx_w(10, -48, 0),
      ja(4),              // -> 25
      ldx_dw(0, 10, -24), // v6 low half
      stx_dw(10, -48, 0),
      ldx_dw(0, 10, -16), // v6 high half
      stx_dw(10, -40, 0),
      call(BPF_FUNC_GET_CURRENT_PID_TGID),
      stx_dw(10, -72, 0), // value.pid_tgid
      call(BPF_FUNC_KTIME_GET_NS),
      stx_dw(10, -64, 0), // value.ts_ns
      map[0],             // load the map descriptor (this instruction and the next)
      map[1],
      mov64_reg(2, 10),
      add64_imm(2, -56), // r2 = &key
      mov64_reg(3, 10),
      add64_imm(3, -72), // r3 = &value
      mov64_imm(4, 0),   // BPF_ANY
      call(BPF_FUNC_MAP_UPDATE_ELEM),
      mov64_imm(0, 0),
      exit(),
   ]
}

/// Why the registry could not be brought up.
#[derive(Debug)]
pub enum RegistryError {
   /// The kernel or this container does not expose the interface: no tracefs, or a
   /// tracepoint whose format no longer names a `sockaddr` argument.
   Unavailable(String),
   /// A `bpf(2)`, `perf_event_open(2)` or `ioctl(2)` call failed.
   Syscall(String),
   /// The verifier rejected a program; the string carries its log.
   Verifier(String),
}

impl std::fmt::Display for RegistryError {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self {
         Self::Unavailable(reason) => write!(f, "tracepoint unavailable: {reason}"),
         Self::Syscall(reason) => write!(f, "kernel syscall failed: {reason}"),
         Self::Verifier(reason) => write!(f, "verifier rejected the program: {reason}"),
      }
   }
}

impl std::error::Error for RegistryError {}

/// The optional in-kernel record of recent senders.
pub struct SendRegistry {
   map_fd: i32,
   /// Kept alive: dropping a perf event detaches its program.
   events: Vec<i32>,
   hits: AtomicU64,
   misses: AtomicU64,
}

impl SendRegistry {
   /// Loads and attaches the probes, or explains why it could not.
   ///
   /// `open()` is deliberately fallible and never fatal: a kernel without tracefs, a
   /// container without `CAP_BPF`, or a tracepoint whose format changed all mean
   /// "attribution falls back to `/proc`", which is the behaviour NetShield had before
   /// this module existed.
   pub fn open() -> Result<Self, RegistryError> {
      Self::try_open().inspect_err(|err| {
         warn!("send registry inactive, using /proc attribution only: {err}");
      })
   }

   fn try_open() -> Result<Self, RegistryError> {
      // Read the two offsets and ids before touching the kernel: a format change is the
      // cheapest failure and must not leave a map or program behind.
      let root = tracefs_root().ok_or_else(|| {
         RegistryError::Unavailable(
            "no tracefs mount at /sys/kernel/tracing or /sys/kernel/debug/tracing".to_string(),
         )
      })?;
      let mut planned = Vec::with_capacity(2);
      for name in [SENDTO, CONNECT] {
         let offset = read_sockaddr_offset(&root, name)?;
         let id = read_tracepoint_id(&root, name)?;
         planned.push((offset, id));
      }

      let cpus = online_cpus()?;

      let attr = syscall::MapCreate {
         map_type: syscall::BPF_MAP_TYPE_HASH,
         key_size: std::mem::size_of::<FlowKey>() as u32,
         value_size: std::mem::size_of::<FlowVal>() as u32,
         max_entries: MAX_SENDERS,
         map_flags: 0,
         inner_map_fd: 0,
         // `NUMA_NO_NODE` as the kernel's signed int sees it: no preferred node.
         numa_node: u32::MAX,
         map_name: [0; 16],
         map_ifindex: 0,
         btf_fd: 0,
         btf_key_type_id: 0,
         btf_value_type_id: 0,
         btf_vmlinux_value_type_id: 0,
         _pad: [0; 64],
      };
      let map_fd = syscall::map_create(&attr)
         .map_err(|err| RegistryError::Syscall(format!("BPF_MAP_CREATE: {err}")))?;

      let mut events: Vec<i32> = Vec::new();
      let mut progs: Vec<i32> = Vec::new();
      let loaded = (|| -> Result<(), RegistryError> {
         for (offset, id) in &planned {
            let insns = program(map_fd, *offset);
            let mut prog = syscall::ProgLoad::for_tracepoint();
            let (prog_fd, _log) = syscall::prog_load(&mut prog, &insns).map_err(|err| {
               // No log means the verifier never saw the program: `EPERM` is a missing
               // capability, not a rejected instruction.
               if err.raw_os_error() == Some(libc::EPERM) {
                  RegistryError::Syscall(format!(
                     "BPF_PROG_LOAD for tracepoint {id}: {err}"
                  ))
               } else {
                  RegistryError::Verifier(format!("tracepoint {id}: {err}"))
               }
            })?;
            progs.push(prog_fd);
            for &cpu in &cpus {
               let event = syscall::perf_event_open_tracepoint(*id, cpu).map_err(|err| {
                  RegistryError::Syscall(format!(
                     "perf_event_open(tracepoint {id}, cpu {cpu}): {err}"
                  ))
               })?;
               events.push(event);
               syscall::perf_enable(event, prog_fd).map_err(|err| {
                  RegistryError::Syscall(format!(
                     "attaching tracepoint {id} on cpu {cpu}: {err}"
                  ))
               })?;
            }
         }
         Ok(())
      })();

      if let Err(err) = loaded {
         for event in events.drain(..) {
            syscall::close_owned(event);
         }
         for prog in progs.drain(..) {
            syscall::close_owned(prog);
         }
         syscall::close_owned(map_fd);
         return Err(err);
      }

      // The perf events now hold the program references, so their descriptors can go.
      for prog in progs.drain(..) {
         syscall::close_owned(prog);
      }
      info!(
         "send registry active: {} probes on {} cpus",
         planned.len(),
         cpus.len()
      );
      Ok(Self {
         map_fd,
         events,
         hits: AtomicU64::new(0),
         misses: AtomicU64::new(0),
      })
   }

   /// The pid that sent to `remote` from `uid` within [`SENDER_TTL_NS`], if the kernel
   /// recorded it.
   pub fn recent_sender(&self, uid: u32, remote: (IpAddr, u16)) -> Option<u32> {
      let key = flow_key(uid, remote);
      let mut val = FlowVal {
         pid_tgid: 0,
         ts_ns: 0,
      };
      // SAFETY: `key` and `val` are live, properly aligned locals of exactly the map's key
      // and value sizes, `map_fd` is owned by `self` and stays open for the call, and
      // BPF_MAP_LOOKUP_ELEM only writes through the value pointer.
      let looked_up = unsafe {
         syscall::map_lookup(
            self.map_fd,
            (&key as *const FlowKey).cast(),
            (&mut val as *mut FlowVal).cast(),
         )
      };
      if looked_up.is_ok() && is_fresh(val.ts_ns, now_ns()) {
         self.hits.fetch_add(1, Ordering::Relaxed);
         return Some((val.pid_tgid & 0xffff_ffff) as u32);
      }
      self.misses.fetch_add(1, Ordering::Relaxed);
      None
   }

   /// Counters for the coverage measurement: how often a lookup answered, and how often not.
   pub fn stats(&self) -> (u64, u64) {
      (
         self.hits.load(Ordering::Relaxed),
         self.misses.load(Ordering::Relaxed),
      )
   }
}

impl Drop for SendRegistry {
   fn drop(&mut self) {
      for &event in &self.events {
         syscall::close_owned(event);
      }
      syscall::close_owned(self.map_fd);
   }
}

/// Builds the map key for `remote`, in the byte order the in-kernel program writes.
fn flow_key(uid: u32, remote: (IpAddr, u16)) -> FlowKey {
   let (addr, family) = match remote.0 {
      IpAddr::V4(v4) => {
         let mut addr = [0u8; 16];
         addr[..4].copy_from_slice(&v4.octets());
         (addr, libc::AF_INET as u16)
      }
      IpAddr::V6(v6) => (v6.octets(), libc::AF_INET6 as u16),
   };
   FlowKey {
      uid,
      family,
      dport: remote.1.to_be(),
      addr,
   }
}

/// Whether a record stamped `ts_ns` may still be believed at `now_ns`.
///
/// A record stamped in the future (only possible if the clock moved backwards) is treated
/// as stale: a wrong pid is worse than a `/proc` scan.
fn is_fresh(ts_ns: u64, now_ns: u64) -> bool {
   now_ns.wrapping_sub(ts_ns) < SENDER_TTL_NS
}

/// `CLOCK_MONOTONIC` in nanoseconds, the clock `bpf_ktime_get_ns` reads.
fn now_ns() -> u64 {
   let mut ts = libc::timespec {
      tv_sec: 0,
      tv_nsec: 0,
   };
   // SAFETY: `CLOCK_MONOTONIC` is a valid clock id and `ts` is a live, correctly sized
   // `timespec` that the kernel only writes. A failure leaves the zeroed value, which
   // makes a record look stale and therefore only costs a lookup, never a wrong answer.
   unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
   (ts.tv_sec as u64)
      .wrapping_mul(1_000_000_000)
      .wrapping_add(ts.tv_nsec.max(0) as u64)
}

/// The mounted tracefs root, if there is one.
fn tracefs_root() -> Option<PathBuf> {
   TRACEFS_ROOTS
      .iter()
      .map(PathBuf::from)
      .find(|root| root.join("events").is_dir())
}

/// The CPUs a probe must be attached to.
///
/// The online list is preferred because it names ids, not a count: a machine with CPU 1
/// offline has a count that no contiguous range of ids matches. The count is only a
/// fallback for a kernel that does not export the list.
fn online_cpus() -> Result<Vec<i32>, RegistryError> {
   if let Some(cpus) = fs::read_to_string(CPU_ONLINE).ok().and_then(|text| parse_cpu_list(&text)) {
      return Ok(cpus);
   }
   let count = std::thread::available_parallelism()
      .map_err(|err| RegistryError::Unavailable(format!("cannot size the cpu set: {err}")))?;
   let count = i32::try_from(count.get())
      .map_err(|_| RegistryError::Unavailable("cpu count does not fit in i32".to_string()))?;
   Ok((0..count).collect())
}

/// Parses the kernel's CPU list syntax (`0-3,6,8-9`) into ids.
///
/// Returns `None` on anything unexpected — a malformed list is not a reason to guess which
/// CPUs exist.
fn parse_cpu_list(text: &str) -> Option<Vec<i32>> {
   let mut cpus = Vec::new();
   for part in text.trim().split(',') {
      let (first, last) = match part.trim().split_once('-') {
         Some((first, last)) => (first.trim(), last.trim()),
         None => (part.trim(), part.trim()),
      };
      let first: i32 = first.parse().ok()?;
      let last: i32 = last.parse().ok()?;
      if first < 0 || last < first || last - first >= MAX_CPUS as i32 {
         return None;
      }
      for cpu in first..=last {
         if cpus.len() >= MAX_CPUS {
            return None;
         }
         cpus.push(cpu);
      }
   }
   if cpus.is_empty() { None } else { Some(cpus) }
}

/// Reads the `offset:` of the field whose type names a `sockaddr`.
///
/// The syscall tracepoint argument order is not ABI-frozen, so the offset is read from the
/// tracepoint's own format file rather than assumed to be 48 or 24.
fn read_sockaddr_offset(root: &Path, name: &str) -> Result<i16, RegistryError> {
   let path = root.join("events/syscalls").join(name).join("format");
   let text = fs::read_to_string(&path).map_err(|err| {
      RegistryError::Unavailable(format!("cannot read {}: {err}", path.display()))
   })?;
   sockaddr_offset_in(&text).ok_or_else(|| {
      RegistryError::Unavailable(format!(
         "{} has no field of type sockaddr",
         path.display()
      ))
   })
}

/// Extracts the offset from the `sockaddr` field of a tracepoint format file.
fn sockaddr_offset_in(format: &str) -> Option<i16> {
   format.lines().find_map(|line| {
      let rest = line.trim().strip_prefix("field:")?;
      let (ty, rest) = rest.split_once(';')?;
      if !ty.contains("sockaddr") {
         return None;
      }
      let after = rest.split("offset:").nth(1)?.trim_start();
      let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
      let offset: i32 = digits.parse().ok()?;
      i16::try_from(offset).ok()
   })
}

/// Reads a tracepoint's id from its `id` file.
fn read_tracepoint_id(root: &Path, name: &str) -> Result<i32, RegistryError> {
   let path = root.join("events/syscalls").join(name).join("id");
   let text = fs::read_to_string(&path).map_err(|err| {
      RegistryError::Unavailable(format!("cannot read {}: {err}", path.display()))
   })?;
   text.trim().parse::<i32>().map_err(|err| {
      RegistryError::Unavailable(format!(
         "{} is not a tracepoint id: {err}",
         path.display()
      ))
   })
}

#[cfg(test)]
mod tests {
   use std::net::{Ipv4Addr, Ipv6Addr};
   use std::time::{SystemTime, UNIX_EPOCH};

   use super::*;

   #[test]
   fn the_program_reads_the_sockaddr_at_the_given_offset() {
      let at_48 = program(7, 48);
      let at_24 = program(7, 24);
      assert_eq!(at_48[0], ldx_dw(3, 1, 48));
      assert_eq!(at_24[0], ldx_dw(3, 1, 24));
      assert_eq!(at_48.len(), 39);
      assert_eq!(at_24.len(), 39);
   }

   #[test]
   fn the_key_layout_matches_between_the_halves() {
      assert_eq!(std::mem::size_of::<FlowKey>(), 24);
      assert_eq!(std::mem::size_of::<FlowVal>(), 16);
      assert_eq!(std::mem::offset_of!(FlowKey, addr), 8);
   }

   #[test]
   fn a_v4_destination_is_the_first_four_bytes() {
      let key = flow_key(
         1000,
         (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53),
      );
      assert_eq!(key.uid, 1000);
      assert_eq!(key.family, libc::AF_INET as u16);
      assert_eq!(key.dport, 53u16.to_be());
      let mut expected = [0u8; 16];
      expected[..4].copy_from_slice(&[127, 0, 0, 1]);
      assert_eq!(key.addr, expected);
   }

   #[test]
   fn a_v6_destination_fills_the_key() {
      let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
      let key = flow_key(0, (IpAddr::V6(ip), 443));
      assert_eq!(key.family, libc::AF_INET6 as u16);
      assert_eq!(key.dport, 443u16.to_be());
      assert_eq!(key.addr, ip.octets());
   }

   #[test]
   fn a_stale_record_is_rejected() {
      assert!(is_fresh(0, 0));
      assert!(is_fresh(0, SENDER_TTL_NS - 1));
      assert!(!is_fresh(0, SENDER_TTL_NS));
      assert!(!is_fresh(0, SENDER_TTL_NS + 1));
      // A stamp from the future means the clock moved; treat it as stale.
      assert!(!is_fresh(SENDER_TTL_NS, 0));
   }

   #[test]
   fn a_missing_tracepoint_is_an_error_not_a_panic() {
      let nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map(|since| since.as_nanos())
         .unwrap_or(0);
      let root = std::env::temp_dir().join(format!("netshield-ebpf-missing-{nanos}"));

      assert!(read_sockaddr_offset(&root, SENDTO).is_err());
      assert!(read_tracepoint_id(&root, SENDTO).is_err());

      let dir = root.join("events/syscalls").join(SENDTO);
      fs::create_dir_all(&dir).expect("create the temp tracepoint directory");
      fs::write(dir.join("id"), "1234\n").expect("write the temp id file");
      fs::write(
         dir.join("format"),
         "field:unsigned long pad;\toffset:0;\tsize:8;\tsigned:0;\n\
          field:struct sockaddr __user * dest_addr;\toffset:48;\tsize:8;\tsigned:0;\n",
      )
      .expect("write the temp format file");

      assert_eq!(read_tracepoint_id(&root, SENDTO).ok(), Some(1234));
      assert_eq!(read_sockaddr_offset(&root, SENDTO).ok(), Some(48));

      fs::write(
         dir.join("format"),
         "field:int fd;\toffset:16;\tsize:8;\n",
      )
      .expect("rewrite the temp format file without a sockaddr");
      assert!(read_sockaddr_offset(&root, SENDTO).is_err());

      fs::remove_dir_all(&root).ok();
   }
}
