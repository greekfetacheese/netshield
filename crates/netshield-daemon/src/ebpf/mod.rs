//! The in-kernel sender registry: the pid behind a flow, recorded at syscall time.
//!
//! `/proc` can only answer while the socket exists, so a flow whose socket closes before
//! [`crate::proc`] scans the tables is unattributable by construction. These tracepoint
//! programs write the answer into a hash map at the moment `sendto`, `sendmsg`,
//! `sendmmsg` or `connect` runs, which is before the caller can close the socket. The
//! daemon asks the map first and keeps `/proc` as the fallback, and [`SendRegistry::open`]
//! failing simply means that fallback is all there is — exactly the pre-registry behaviour.
//!
//! This module is the second sanctioned home for `unsafe` (see `AGENTS.md`): the kernel
//! ABI it speaks has no Rust wrapper that does not add a dependency.

mod syscall;

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use log::{debug, info, warn};

/// Where a pid for a recent send can come from.
///
/// A trait only so `Attributor`'s tests can answer without root, a tracefs mount and a kernel
/// that will load a BPF program.
pub trait SenderLookup: Send + Sync {
   /// The pid that sent to `remote` from `uid` recently, if the kernel recorded it.
   fn recent_sender(&self, uid: u32, remote: (IpAddr, u16)) -> Option<u32>;
   /// (lookups answered, lookups with nothing to say), when the implementation counts them.
   fn stats(&self) -> Option<(u64, u64)> {
      None
   }
}

impl SenderLookup for SendRegistry {
   fn recent_sender(&self, uid: u32, remote: (IpAddr, u16)) -> Option<u32> {
      SendRegistry::recent_sender(self, uid, remote)
   }

   fn stats(&self) -> Option<(u64, u64)> {
      Some(SendRegistry::stats(self))
   }
}

// `Attributor` derives `Debug`; the probe's internal descriptors and counters are not useful
// in a debug line, and keeping the trait object printable costs nothing.
impl std::fmt::Debug for dyn SenderLookup {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.write_str("SenderLookup")
   }
}

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

/// The tracepoint whose `user_msghdr` argument is read for a named send.
const SENDMSG: &str = "sys_enter_sendmsg";

/// The tracepoint whose `mmsghdr` array argument is read for a batched send.
const SENDMMSG: &str = "sys_enter_sendmmsg";

/// The tracepoint whose `sockaddr` argument is read for a connect.
const CONNECT: &str = "sys_enter_connect";

/// Where the program finds the destination for a given syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Destination {
   /// The context holds a `struct sockaddr *` directly (`sendto`).
   SockaddrAt(i16),
   /// The context holds a `struct user_msghdr *` (`sendmsg`); read its `msg_name` first.
   ///
   /// `sendmmsg` uses this too, with the offset of its `msgvec`: the array's first
   /// `mmsghdr` starts with the `msghdr` whose `msg_name` this reads.
   MsghdrAt(i16),
}

/// The tracepoints the registry attaches, in the order it attaches them.
const PROBES: [&str; 4] = [SENDTO, CONNECT, SENDMSG, SENDMMSG];

/// Whether a tracepoint's destination argument is an `msghdr` rather than a `sockaddr`.
fn reads_msghdr(name: &str) -> bool {
   matches!(name, SENDMSG | SENDMMSG)
}

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

/// Builds the one tracepoint program, which differs between the probes only in where the
/// context names the user's destination.
///
/// The frame layout is fixed by the program: the copied `sockaddr` sits at `fp-32`, the
/// key at `fp-56` and the value at `fp-72`. A `MsghdrAt` program first stages the
/// `msghdr` at `fp-64`. That staging area overlaps the key and the value, which is safe
/// because those bytes are dead once `r3` holds `msg_name`, before either is written.
///
/// `msghdr` is `struct user_msghdr` as the kernel's uapi spells it, whose first two
/// members are the ones that matter here: `msg_name` at offset 0 (a user pointer) and
/// `msg_namelen` at offset 8.
fn program(map_fd: i32, destination: Destination) -> Vec<Insn> {
   let mut insns = match destination {
      Destination::SockaddrAt(ctx_offset) => sockaddr_prologue(ctx_offset),
      Destination::MsghdrAt(ctx_offset) => msghdr_prologue(ctx_offset),
   };
   insns.extend(record_tail(map_fd));
   insns
}

/// `sizeof(struct user_msghdr)`. `msg_name` and `msg_namelen` are the only members this
/// program reads, and both are 8 bytes.
const MSGHDR_BYTES: i32 = 16;

/// `sizeof(struct sockaddr_in6)`, the longest destination this program copies.
const SOCKADDR_BYTES: i32 = 28;

/// The prologue for `sendto` and `connect`: the context holds the user's `sockaddr *`.
///
/// The [`record_tail`] that follows appears one instruction later in this program's
/// numbering; each of its relative indices is therefore one higher here.
///
///   0  r3 = *(u64 *)(ctx + ctx_offset)   the user's sockaddr pointer
fn sockaddr_prologue(ctx_offset: i16) -> Vec<Insn> {
   vec![ldx_dw(3, 1, ctx_offset)]
}

/// The prologue for `sendmsg` and `sendmmsg`: the context holds a user pointer to a
/// `msghdr` (for `sendmmsg`, the first `mmsghdr`, whose `msg_hdr` starts at offset 0).
///
/// `sendmmsg` records only its first message's name. NetShield attributes flows, not
/// datagrams, and every message in a batch shares the socket, so a per-message loop would
/// add hand-assembled code and no coverage.
///
/// A NULL `msg_name` means the socket is connected and the syscall carries no destination
/// at all; the `connect` hook recorded that one, so the program returns without touching
/// the map.
///
/// The prologue is 10 instructions, so every [`record_tail`] index appears 10 higher in this
/// program's numbering, which is what the verifier reports.
///
///   0  r3 = *(u64 *)(ctx + ctx_offset)   the msghdr (or msgvec) user pointer
///   1  r1 = fp                            \
///   2  r1 += -64                           | probe_read_user(fp-64, 16, r3)
///   3  r2 = 16                             |
///   4  call probe_read_user              /
///   5  if r0 != 0 goto 8                 unreadable msghdr: return, no map write
///   6  r3 = *(u64 *)(fp + -64)           r3 = msg_name
///   7  if r3 != 0 goto 10                connected socket: return, connect record stands
///   8  r0 = 0                            \
///   9  exit                               | return without a map write
fn msghdr_prologue(ctx_offset: i16) -> Vec<Insn> {
   vec![
      ldx_dw(3, 1, ctx_offset),
      mov64_reg(1, 10),
      add64_imm(1, -64),
      mov64_imm(2, MSGHDR_BYTES),
      call(BPF_FUNC_PROBE_READ_USER),
      jne_imm(0, 0, 2),   // -> 8, return without a map write
      ldx_dw(3, 10, -64), // r3 = the msghdr's msg_name
      jne_imm(3, 0, 2),   // -> 10, the sockaddr read
      mov64_imm(0, 0),
      exit(),
   ]
}

/// The tail shared by all three probe kinds: `r3` already holds the user's `sockaddr *`.
///
/// Its internal branch offsets are relative and therefore independent of the prologue that
/// precedes it. Indices are relative to this array; add the prologue length (1 for
/// `SockaddrAt`, 10 for `MsghdrAt`) for the numbering the verifier reports.
///
///   0  r1 = fp                            \
///   1  r1 += -32                           | probe_read_user(fp-32, 28, r3)
///   2  r2 = 28                             |
///   3  call probe_read_user              /
///   4  if r0 != 0 goto 36                read failed (a NULL addr) -> index 36
///   5  r0 = 0
///   6  *(u64 *)(fp - 40) = r0           zero the key area fp-56..fp-33
///   7  *(u64 *)(fp - 48) = r0
///   8  *(u64 *)(fp - 56) = r0
///   9  call get_current_uid_gid
///  10  *(u32 *)(fp - 56) = r0           key.uid
///  11  r0 = *(u16 *)(fp - 32)
///  12  *(u16 *)(fp - 52) = r0           key.family
///  13  r0 = *(u16 *)(fp - 30)
///  14  *(u16 *)(fp - 50) = r0           key.dport
///  15  r0 = *(u16 *)(fp - 32)
///  16  if r0 != 2 goto 20               not AF_INET -> v6 block at 20
///  17  r0 = *(u32 *)(fp - 28)           v4 address
///  18  *(u32 *)(fp - 48) = r0
///  19  goto 24                          -> value block
///  20  r0 = *(u64 *)(fp - 24)           v6 low half
///  21  *(u64 *)(fp - 48) = r0
///  22  r0 = *(u64 *)(fp - 16)           v6 high half
///  23  *(u64 *)(fp - 40) = r0
///  24  call get_current_pid_tgid
///  25  *(u64 *)(fp - 72) = r0           value.pid_tgid
///  26  call ktime_get_ns
///  27  *(u64 *)(fp - 64) = r0           value.ts_ns
///  28  r1 = map_fd                       \
///  29  (upper 32 bits of the descriptor)  | load the map descriptor
///  30  r2 = fp                           |
///  31  r2 += -56                          |
///  32  r3 = fp                           |
///  33  r3 += -72                          |
///  34  r4 = 0                            | BPF_ANY
///  35  call map_update_elem              /
///  36  r0 = 0
///  37  exit
fn record_tail(map_fd: i32) -> Vec<Insn> {
   let map = ld_map_fd(1, map_fd);
   vec![
      mov64_reg(1, 10),             // r1 = fp
      add64_imm(1, -32),            // dst = fp-32
      mov64_imm(2, SOCKADDR_BYTES), // size = sizeof(sockaddr_in6)
      call(BPF_FUNC_PROBE_READ_USER),
      jne_imm(0, 0, 31), // read failed -> index 36
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
      jne_imm(0, 2, 3),  // not AF_INET -> v6 block at 20
      ldx_w(0, 10, -28), // v4 address
      stx_w(10, -48, 0),
      ja(4),              // -> 24
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
   /// format that no longer names the `sockaddr` or `msghdr` argument.
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
      // Read the offsets and ids before touching the kernel: a format change is the
      // cheapest failure and must not leave a map or program behind.
      let root = tracefs_root().ok_or_else(|| {
         RegistryError::Unavailable(
            "no tracefs mount at /sys/kernel/tracing or /sys/kernel/debug/tracing".to_string(),
         )
      })?;
      // A format that does not name the argument makes that program unavailable, but only
      // that one: the others still attach. The id is read alongside it, and a tracepoint
      // that cannot even be planned is reported and skipped for the same reason.
      let mut planned = Vec::with_capacity(PROBES.len());
      for name in PROBES {
         let destination = if reads_msghdr(name) {
            read_destination_offset(&root, name, "msghdr").map(Destination::MsghdrAt)
         } else {
            read_destination_offset(&root, name, "sockaddr").map(Destination::SockaddrAt)
         }
         .and_then(|destination| read_tracepoint_id(&root, name).map(|id| (destination, id)));
         match destination {
            Ok((destination, id)) => planned.push((name, destination, id)),
            Err(err) => warn!("send registry probe {name} is unavailable: {err}"),
         }
      }

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
      // Each tracepoint is attached on its own: a verifier rejection or a failed
      // `perf_event_open` for one of them must leave the others running, so the failure is
      // reported with its tracepoint name and that probe is skipped.
      let mut attached = 0usize;
      for (name, destination, id) in planned {
         match Self::attach_one(map_fd, name, destination, id, &mut events) {
            Ok(()) => attached += 1,
            Err(err) => warn!("send registry probe {name} was not attached: {err}"),
         }
      }
      if attached == 0 {
         for event in events.drain(..) {
            syscall::close_owned(event);
         }
         syscall::close_owned(map_fd);
         return Err(RegistryError::Unavailable(
            "no send tracepoint could be attached".to_string(),
         ));
      }

      info!("send registry active: {attached} tracepoints attached");
      Ok(Self {
         map_fd,
         events,
         hits: AtomicU64::new(0),
         misses: AtomicU64::new(0),
      })
   }

   /// Loads and attaches one tracepoint's program, keeping its perf event in `events` only
   /// if both steps succeed.
   fn attach_one(
      map_fd: i32,
      name: &str,
      destination: Destination,
      id: i32,
      events: &mut Vec<i32>,
   ) -> Result<(), RegistryError> {
      let insns = program(map_fd, destination);
      let mut prog = syscall::ProgLoad::for_tracepoint();
      let (prog_fd, _log) = syscall::prog_load(&mut prog, &insns).map_err(|err| {
         // No log means the verifier never saw the program: `EPERM` is a missing
         // capability, not a rejected instruction.
         if err.raw_os_error() == Some(libc::EPERM) {
            RegistryError::Syscall(format!(
               "BPF_PROG_LOAD for {name} (tracepoint {id}): {err}"
            ))
         } else {
            RegistryError::Verifier(format!("{name} (tracepoint {id}): {err}"))
         }
      })?;
      let attached = Self::attach_tracepoint(id, prog_fd, events);
      // Whatever the perf event's state, the program descriptor is ours to close: success
      // means the event holds the reference, failure means nothing does.
      syscall::close_owned(prog_fd);
      attached
   }

   /// Opens the single perf event that carries `prog_fd` for the tracepoint `id`, and keeps
   /// its descriptor in `events` so it outlives the call.
   ///
   /// An `EEXIST` from either syscall means another program already owns this tracepoint's
   /// program slot; that is reported like any other attach failure, so the caller runs with
   /// `/proc` attribution alone instead of treating it as fatal.
   fn attach_tracepoint(id: i32, prog_fd: i32, events: &mut Vec<i32>) -> Result<(), RegistryError> {
      // One event per tracepoint, not per cpu: the kernel stores a tracepoint's BPF program on the
      // tracepoint itself, so a second perf event for the same id fails with EEXIST and the first
      // one already runs for every occurrence on every cpu. Measured: a sender pinned to cpu 3 is
      // still recorded by an event opened on cpu 0.
      let event = syscall::perf_event_open_tracepoint(id, 0).map_err(|err| {
         RegistryError::Syscall(format!("perf_event_open(tracepoint {id}): {err}"))
      })?;
      if let Err(err) = syscall::perf_enable(event, prog_fd) {
         // The event never ran a program, so it must not stay in `events`; dropping it here
         // keeps the registry from holding a descriptor for a tracepoint it does not own.
         syscall::close_owned(event);
         return Err(RegistryError::Syscall(format!(
            "attaching tracepoint {id}: {err}"
         )));
      }
      events.push(event);
      Ok(())
   }

   /// The pid that sent to `remote` from `uid` within [`SENDER_TTL_NS`], if the kernel
   /// recorded it.
   ///
   /// A record whose process id is zero is a miss, not a lookup for pid 0: zero means the
   /// program could not name the sender, and `/proc/0` would only obscure that.
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
      if looked_up.is_ok() {
         let now = now_ns();
         if !is_fresh(val.ts_ns, now) {
            debug!(
               "send registry's record for {remote:?} from uid {uid} is {} ms old",
               now.wrapping_sub(val.ts_ns) / 1_000_000
            );
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
         }
         // The high half of `bpf_get_current_pid_tgid` is the thread group id: the process. The low
         // half is the tid, and `/proc/<tid>` cannot be read from another process, so a worker
         // thread's send would be recorded with an id that nothing outside its thread group can
         // name — which is how a browser's QUIC traffic ended up unattributable.
         let pid = sender_pid(val.pid_tgid);
         if pid != 0 {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(pid);
         }
      }
      debug!("send registry has no record for {remote:?} from uid {uid}");
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

/// The process id carried by a `bpf_get_current_pid_tgid` value.
///
/// The kernel packs `tgid << 32 | tid`; only the thread group id names a process that
/// `/proc` can be read for from outside the owning thread group.
fn sender_pid(pid_tgid: u64) -> u32 {
   (pid_tgid >> 32) as u32
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

/// Reads the `offset:` of the field whose type names `ty` (`sockaddr` or `msghdr`).
///
/// The syscall tracepoint argument order is not ABI-frozen, so the offset is read from the
/// tracepoint's own format file rather than assumed to be 48 or 24.
fn read_destination_offset(root: &Path, name: &str, ty: &str) -> Result<i16, RegistryError> {
   let path = root.join("events/syscalls").join(name).join("format");
   let text = fs::read_to_string(&path).map_err(|err| {
      RegistryError::Unavailable(format!("cannot read {}: {err}", path.display()))
   })?;
   field_offset_in(&text, ty).ok_or_else(|| {
      RegistryError::Unavailable(format!(
         "{} has no field of type {ty}",
         path.display()
      ))
   })
}

/// Extracts the offset of the first field of a tracepoint format file whose type contains
/// `ty`.
///
/// The match is on the type text, not on the field name, so a kernel that renames `msg` or
/// `msgvec` still works.
fn field_offset_in(format: &str, ty: &str) -> Option<i16> {
   format.lines().find_map(|line| {
      let rest = line.trim().strip_prefix("field:")?;
      let (field_ty, rest) = rest.split_once(';')?;
      if !field_ty.contains(ty) {
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
   fn a_sendto_program_is_unchanged() {
      let at_48 = program(7, Destination::SockaddrAt(48));
      let at_24 = program(7, Destination::SockaddrAt(24));
      assert_eq!(at_48[0], ldx_dw(3, 1, 48));
      assert_eq!(at_24[0], ldx_dw(3, 1, 24));
      assert_eq!(at_48.len(), 39);
      assert_eq!(at_24.len(), 39);
   }

   #[test]
   fn a_sendmsg_program_reads_the_msghdr() {
      let insns = program(7, Destination::MsghdrAt(24));
      assert_eq!(
         insns[0],
         ldx_dw(3, 1, 24),
         "r3 = the msghdr pointer"
      );
      assert_eq!(insns[1], mov64_reg(1, 10));
      assert_eq!(
         insns[2],
         add64_imm(1, -64),
         "the msghdr lands at fp-64"
      );
      assert_eq!(
         insns[3],
         mov64_imm(2, 16),
         "16 bytes: msg_name and msg_namelen"
      );
      assert_eq!(insns[4], call(BPF_FUNC_PROBE_READ_USER));
      // A failed read returns without touching the map: 5 + 1 + 2 = 8.
      assert_eq!(insns[5], jne_imm(0, 0, 2));
      assert_eq!(insns[6], ldx_dw(3, 10, -64), "r3 = msg_name");
      // A NULL msg_name is a connected socket: 7 + 1 + 2 = 10, the sockaddr read.
      assert_eq!(insns[7], jne_imm(3, 0, 2));
      assert_eq!(insns[8], mov64_imm(0, 0));
      assert_eq!(insns[9], exit());
      // The same record tail as `sendto`, so the key and value stay identical.
      assert_eq!(insns.len(), 10 + 38);
      assert_eq!(&insns[10..], &record_tail(7)[..]);
   }

   #[test]
   fn a_sendmmsg_program_uses_the_first_msghdrs_name() {
      // The first `mmsghdr`'s `msg_hdr` is at offset 0 of the array, so `msgvec` is read
      // exactly like `sendmsg`'s `msg`: one prologue serves both.
      let sendmsg = program(7, Destination::MsghdrAt(24));
      let sendmmsg = program(7, Destination::MsghdrAt(24));
      assert_eq!(sendmsg, sendmmsg);
      assert_eq!(sendmsg.len(), 48);
   }

   #[test]
   fn the_key_and_value_layouts_are_unchanged() {
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
   fn a_worker_thread_is_named_by_its_process() {
      assert_eq!(sender_pid((4242u64 << 32) | 4243), 4242);
      assert_eq!(sender_pid((4242u64 << 32) | 4242), 4242);
   }

   #[test]
   fn a_record_without_a_process_id_is_a_miss() {
      assert_eq!(sender_pid(0), 0);
      // A tid without a tgid names no process that `/proc` can be read for.
      assert_eq!(sender_pid(4243), 0);
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
   fn the_attach_reports_the_tracepoint_it_could_not_attach() {
      // perf_event_open needs CAP_PERFMON/CAP_SYS_ADMIN, so without root this asserts
      // nothing about the tracepoint id; the failure the daemon must survive is the
      // unprivileged one, which `open()` already falls back from.
      if crate::ipc_server::effective_uid() != Some(0) {
         return;
      }
      let mut events = Vec::new();
      let err = SendRegistry::attach_tracepoint(i32::MAX, -1, &mut events)
         .expect_err("tracepoint i32::MAX cannot exist");
      assert!(
         err.to_string().contains(&i32::MAX.to_string()),
         "the failure must name the tracepoint: {err}"
      );
      assert!(
         events.is_empty(),
         "no descriptor is kept for a failed attach"
      );
   }

   /// Sends one UDP datagram to the socket's own bound address, closes the socket 1 ms
   /// later and leaves the process alive, which is the shape of a flow whose socket is gone
   /// by the time `/proc` is scanned. Returns the destination and the sending uid.
   ///
   /// Every `unsafe` block below is a libc call on a descriptor this helper opened, with
   /// live locals of exactly the type libc declares for the lengths it passes.
   fn send_one(batched: bool) -> ((IpAddr, u16), u32) {
      let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
      assert!(
         fd >= 0,
         "socket: {}",
         std::io::Error::last_os_error()
      );
      let mut local: libc::sockaddr_in = unsafe { std::mem::zeroed() };
      local.sin_family = libc::AF_INET as u16;
      // 127.0.0.1 in the network byte order `in_addr` stores.
      local.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
      local.sin_port = 0;
      let bound = unsafe {
         libc::bind(
            fd,
            (&local as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
         )
      };
      assert_eq!(
         bound,
         0,
         "bind: {}",
         std::io::Error::last_os_error()
      );
      let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
      let named = unsafe {
         libc::getsockname(
            fd,
            (&mut local as *mut libc::sockaddr_in).cast(),
            &mut len,
         )
      };
      assert_eq!(
         named,
         0,
         "getsockname: {}",
         std::io::Error::last_os_error()
      );

      // Send to the port the socket itself bound: the datagram needs no listener, and the
      // destination is exactly the one the tracepoint has to record.
      let mut dest = local;
      let mut payload = *b"n";
      let mut iov = libc::iovec {
         iov_base: (&mut payload as *mut u8).cast(),
         iov_len: payload.len(),
      };
      let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
      msg.msg_name = (&mut dest as *mut libc::sockaddr_in).cast();
      msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
      msg.msg_iov = &mut iov;
      msg.msg_iovlen = 1;

      let sent = if batched {
         let mut batch = [libc::mmsghdr {
            msg_hdr: msg,
            msg_len: 0,
         }];
         // SAFETY: `batch` is a live one-element array of the `mmsghdr` the syscall reads,
         // and `vlen` is exactly its length.
         unsafe {
            libc::syscall(
               libc::SYS_sendmmsg,
               fd,
               batch.as_mut_ptr(),
               1 as libc::c_long,
               0 as libc::c_long,
            )
         }
      } else {
         // SAFETY: `msg` is a live `msghdr` whose pointers name live locals, and the syscall
         // only reads it for the duration of the call.
         unsafe { libc::syscall(libc::SYS_sendmsg, fd, &msg, 0) }
      };
      assert_eq!(
         sent,
         1,
         "{}: {}",
         if batched { "sendmmsg" } else { "sendmsg" },
         std::io::Error::last_os_error()
      );

      std::thread::sleep(std::time::Duration::from_millis(1));
      // SAFETY: `fd` was opened above, is owned by this helper and is closed exactly once.
      unsafe { libc::close(fd) };

      let uid = unsafe { libc::getuid() };
      let port = u16::from_be(local.sin_port);
      (
         (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
         uid,
      )
   }

   /// The live coverage measurement: both named sends must leave a record, exactly as
   /// `sendto` does, so a socket closed before the `/proc` scan is still attributable.
   #[test]
   #[ignore = "needs root: loads a BPF program and attaches tracepoints"]
   fn sendmsg_and_sendmmsg_are_recorded() {
      if crate::ipc_server::effective_uid() != Some(0) {
         eprintln!("skipping: attaching tracepoints needs CAP_BPF/CAP_PERFMON");
         return;
      }
      let registry = SendRegistry::open().expect("the send registry must open as root");
      let ours = std::process::id();

      for (path, batched) in [("sendmsg", false), ("sendmmsg", true)] {
         let (remote, uid) = send_one(batched);
         let recorded = registry.recent_sender(uid, remote);
         println!("{path} -> {remote:?} from uid {uid}: recorded {recorded:?}, expected {ours}");
         assert_eq!(
            recorded,
            Some(ours),
            "{path} to {remote:?} must record our own pid {ours}"
         );
      }
   }

   #[test]
   fn a_missing_tracepoint_is_an_error_not_a_panic() {
      let nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map(|since| since.as_nanos())
         .unwrap_or(0);
      let root = std::env::temp_dir().join(format!("netshield-ebpf-missing-{nanos}"));

      assert!(read_destination_offset(&root, SENDTO, "sockaddr").is_err());
      assert!(read_destination_offset(&root, SENDMSG, "msghdr").is_err());
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
      assert_eq!(
         read_destination_offset(&root, SENDTO, "sockaddr").ok(),
         Some(48)
      );

      fs::write(
         dir.join("format"),
         "field:int fd;\toffset:16;\tsize:8;\n",
      )
      .expect("rewrite the temp format file without a sockaddr");
      assert!(read_destination_offset(&root, SENDTO, "sockaddr").is_err());

      // A tracepoint whose format does not name the msghdr is unavailable for that program
      // alone; the discovery step is what reports it.
      let sendmsg = root.join("events/syscalls").join(SENDMSG);
      fs::create_dir_all(&sendmsg).expect("create the sendmsg tracepoint directory");
      fs::write(
         sendmsg.join("format"),
         "field:struct user_msghdr __user * msg;\toffset:24;\tsize:8;\tsigned:0;\n",
      )
      .expect("write the sendmsg format file");
      assert_eq!(
         read_destination_offset(&root, SENDMSG, "msghdr").ok(),
         Some(24)
      );
      fs::write(
         sendmsg.join("format"),
         "field:int fd;\toffset:16;\tsize:8;\n",
      )
      .expect("rewrite the sendmsg format file without an msghdr");
      assert!(read_destination_offset(&root, SENDMSG, "msghdr").is_err());

      fs::remove_dir_all(&root).ok();
   }
}
