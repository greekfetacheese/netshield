//! The raw kernel ABI behind the sender registry: `bpf(2)` and `perf_event_open(2)`.
//!
//! This is the second sanctioned `unsafe` home (`AGENTS.md`): no C library is linked and
//! no new dependency is taken, so the `union bpf_attr` layouts, the instruction encoding
//! and the perf event attribute are spelled out here. Every layout is `#[repr(C)]` and
//! size-checked at compile time, every call is checked for a negative return and turned
//! into an [`io::Error`], and anything unexpected is an error rather than a panic — the
//! registry is optional, so the caller can always fall back to `/proc`.
//!
//! `libc` exports `SYS_bpf` and `SYS_perf_event_open`, which are used below, but it does
//! not export `struct perf_event_attr` or the `PERF_EVENT_IOC_*` request numbers on
//! Linux. Those are declared here from the kernel headers, with the ioctl requests
//! encoded through the kernel's `_IOC` layout rather than copied as magic numbers.

use std::io;

use super::Insn;

/// `sizeof(union bpf_attr)`: the kernel rejects attributes larger than this and zero-fills
/// whatever a shorter command arm leaves unset.
const ATTR_SIZE: u32 = 128;

/// `enum bpf_cmd`.
pub(crate) const BPF_MAP_CREATE: u32 = 0;
pub(crate) const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub(crate) const BPF_PROG_LOAD: u32 = 5;

/// `enum bpf_map_type`.
pub(crate) const BPF_MAP_TYPE_HASH: u32 = 1;

/// `enum bpf_prog_type`.
pub(crate) const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;

/// `PERF_TYPE_TRACEPOINT` from `<linux/perf_event.h>`; libc does not export it on Linux.
const PERF_TYPE_TRACEPOINT: u32 = 2;

/// `PERF_FLAG_FD_CLOEXEC` from `<linux/perf_event.h>`: keep the event out of exec'd
/// children, which a root daemon must not leak into a re-exec of itself.
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;

/// `PERF_ATTR_SIZE_VER0`: only `type`, `config` and the `disabled` bit are used, and the
/// smallest published size is accepted by the widest range of kernels.
const PERF_ATTR_SIZE: u32 = 64;

/// Bit 0 of the perf attribute flags word (`disabled`): leave the event off until the
/// program is attached and `PERF_EVENT_IOC_ENABLE` runs.
const PERF_ATTR_DISABLED: u64 = 1;

/// The kernel's `_IOC` encoding from `<asm-generic/ioctl.h>`, which libc does not expose
/// on Linux: `dir << 30 | size << 16 | type << 8 | nr`.
const fn ioc(dir: u32, ty: u8, nr: u8, size: u32) -> libc::c_ulong {
   ((dir << 30) | (size << 16) | ((ty as u32) << 8) | nr as u32) as libc::c_ulong
}

/// `PERF_EVENT_IOC_ENABLE` = `_IO('$', 0)`.
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = ioc(0, b'$', 0, 0);

/// `PERF_EVENT_IOC_SET_BPF` = `_IOW('$', 8, __u32)`.
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = ioc(1, b'$', 8, 4);

/// Most verifier log bytes requested; the kernel truncates rather than overruns.
const VERIFIER_LOG_BYTES: usize = 64 * 1024;

/// The `license` string the verifier reads.
///
/// `bpf_probe_read_user` is a GPL-only helper, so the program must declare `"GPL"` or the
/// load fails. This string classifies the BPF program for that gate; it does not relicense
/// this crate, which stays MIT.
const LICENSE: &[u8] = b"GPL\0";

/// One `union bpf_attr` arm for `BPF_MAP_CREATE`.
///
/// `_pad` brings the arm to the union's 128 bytes so the kernel's `copy_from_user` sees a
/// fully initialised attribute.
#[repr(C)]
pub(crate) struct MapCreate {
   pub(crate) map_type: u32,
   pub(crate) key_size: u32,
   pub(crate) value_size: u32,
   pub(crate) max_entries: u32,
   pub(crate) map_flags: u32,
   pub(crate) inner_map_fd: u32,
   pub(crate) numa_node: u32,
   pub(crate) map_name: [u8; 16],
   pub(crate) map_ifindex: u32,
   pub(crate) btf_fd: u32,
   pub(crate) btf_key_type_id: u32,
   pub(crate) btf_value_type_id: u32,
   pub(crate) btf_vmlinux_value_type_id: u32,
   pub(crate) _pad: [u8; 64],
}

/// One `union bpf_attr` arm for `BPF_PROG_LOAD`.
#[repr(C)]
pub(crate) struct ProgLoad {
   prog_type: u32,
   insn_cnt: u32,
   insns: u64,
   license: u64,
   log_level: u32,
   log_size: u32,
   log_buf: u64,
   kern_version: u32,
   prog_flags: u32,
   prog_name: [u8; 16],
   prog_ifindex: u32,
   expected_attach_type: u32,
   _pad: [u8; 56],
}

impl ProgLoad {
   /// A zeroed attribute for a tracepoint program; [`prog_load`] fills the instruction,
   /// license and log fields it owns.
   pub(crate) fn for_tracepoint() -> Self {
      Self {
         prog_type: BPF_PROG_TYPE_TRACEPOINT,
         insn_cnt: 0,
         insns: 0,
         license: 0,
         log_level: 0,
         log_size: 0,
         log_buf: 0,
         kern_version: 0,
         prog_flags: 0,
         prog_name: [0; 16],
         prog_ifindex: 0,
         expected_attach_type: 0,
         _pad: [0; 56],
      }
   }
}

/// One `union bpf_attr` arm for `BPF_MAP_LOOKUP_ELEM`: the key and value are user pointers
/// carried as integers, which is how the union declares them.
#[repr(C)]
struct Element {
   map_fd: u32,
   _pad: u32,
   key: u64,
   value: u64,
   flags: u64,
   _pad2: [u8; 96],
}

/// `struct perf_event_attr` from `<linux/perf_event.h>`.
///
/// Only the leading 64 bytes are ever read (`size` is set to [`PERF_ATTR_SIZE`]), but the
/// full layout is declared so the size field stays larger than what could be read.
#[repr(C)]
struct PerfEventAttr {
   type_: u32,
   size: u32,
   config: u64,
   sample_period: u64,
   sample_type: u64,
   read_format: u64,
   flags: u64,
   wakeup_events: u32,
   bp_type: u32,
   config1: u64,
   config2: u64,
   branch_sample_type: u64,
   sample_regs_user: u64,
   sample_regs_intr: u64,
   aux_watermark: u32,
   sample_max_stack: u16,
   reserved1: u16,
   aux_sample_size: u32,
   reserved2: u32,
   sig_data: u64,
   config3: u64,
}

impl PerfEventAttr {
   /// A disabled system-wide event for tracepoint `id`.
   fn tracepoint(id: i32) -> Self {
      Self {
         type_: PERF_TYPE_TRACEPOINT,
         size: PERF_ATTR_SIZE,
         config: id as u64,
         sample_period: 0,
         sample_type: 0,
         read_format: 0,
         flags: PERF_ATTR_DISABLED,
         wakeup_events: 0,
         bp_type: 0,
         config1: 0,
         config2: 0,
         branch_sample_type: 0,
         sample_regs_user: 0,
         sample_regs_intr: 0,
         aux_watermark: 0,
         sample_max_stack: 0,
         reserved1: 0,
         aux_sample_size: 0,
         reserved2: 0,
         sig_data: 0,
         config3: 0,
      }
   }
}

const _: () = assert!(std::mem::size_of::<MapCreate>() == ATTR_SIZE as usize);
const _: () = assert!(std::mem::size_of::<ProgLoad>() == ATTR_SIZE as usize);
const _: () = assert!(std::mem::size_of::<Element>() == ATTR_SIZE as usize);
const _: () = assert!(std::mem::size_of::<Insn>() == 8);

/// Calls `bpf(cmd, attr, 128)`.
///
/// The caller guarantees `attr` points to the arm that matches `cmd`.
fn bpf(cmd: u32, attr: *const u8) -> io::Result<i64> {
   // SAFETY: `attr` points to a live, `#[repr(C)]` command arm of exactly `ATTR_SIZE`
   // bytes whose layout matches the kernel's `union bpf_attr` for `cmd`; `SYS_bpf` only
   // copies those bytes into kernel memory and never keeps the user pointer.
   let rc = unsafe {
      libc::syscall(
         libc::SYS_bpf,
         cmd as libc::c_long,
         attr,
         ATTR_SIZE as libc::c_long,
      )
   };
   if rc < 0 {
      return Err(io::Error::last_os_error());
   }
   // `c_long` is 32-bit on 32-bit targets; widen rather than assume the host width.
   Ok(rc as i64)
}

/// Creates a map and returns its descriptor.
pub(crate) fn map_create(attr: &MapCreate) -> io::Result<i32> {
   let fd = bpf(BPF_MAP_CREATE, (attr as *const MapCreate).cast())?;
   i32::try_from(fd)
      .map_err(|_| io::Error::other("BPF_MAP_CREATE returned a descriptor wider than i32"))
}

/// Looks `key` up and copies the value into `value`.
///
/// # Safety
///
/// `key` and `value` must point to live, aligned buffers of the map's key and value sizes,
/// and no other thread may be using `map_fd` after it was closed.
pub(crate) unsafe fn map_lookup(map_fd: i32, key: *const u8, value: *mut u8) -> io::Result<()> {
   let map_fd = u32::try_from(map_fd).map_err(|_| {
      io::Error::new(
         io::ErrorKind::InvalidInput,
         "negative map descriptor",
      )
   })?;
   let attr = Element {
      map_fd,
      _pad: 0,
      key: key as u64,
      value: value as u64,
      flags: 0,
      _pad2: [0; 96],
   };
   bpf(
      BPF_MAP_LOOKUP_ELEM,
      (&attr as *const Element).cast(),
   )?;
   Ok(())
}

/// Loads one program, returning its descriptor and — on success — the verifier log.
///
/// On failure the error's text carries both the syscall error and the verifier log, which
/// is the only way to tell a bad instruction from a missing capability.
pub(crate) fn prog_load(attr: &mut ProgLoad, insns: &[Insn]) -> io::Result<(i32, String)> {
   let mut log = vec![0u8; VERIFIER_LOG_BYTES];
   attr.insn_cnt = u32::try_from(insns.len()).map_err(|_| {
      io::Error::new(
         io::ErrorKind::InvalidInput,
         "program has too many instructions",
      )
   })?;
   attr.insns = insns.as_ptr() as u64;
   attr.license = LICENSE.as_ptr() as u64;
   attr.log_level = 1;
   attr.log_size = VERIFIER_LOG_BYTES as u32;
   attr.log_buf = log.as_mut_ptr() as u64;

   match bpf(BPF_PROG_LOAD, (attr as *const ProgLoad).cast()) {
      Ok(fd) => i32::try_from(fd)
         .map(|fd| (fd, String::new()))
         .map_err(|_| io::Error::other("BPF_PROG_LOAD returned a descriptor wider than i32")),
      Err(err) => {
         let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
         let text = String::from_utf8_lossy(&log[..end]).trim().to_string();
         // An empty log means the verifier never ran — a capability failure. Keep the
         // kernel's own error object so the caller can tell that from a rejection.
         if text.is_empty() {
            Err(err)
         } else {
            Err(io::Error::new(
               err.kind(),
               format!("{err}: {text}"),
            ))
         }
      }
   }
}

/// Opens one system-wide perf event for tracepoint `id` on `cpu`.
pub(crate) fn perf_event_open_tracepoint(id: i32, cpu: i32) -> io::Result<i32> {
   let mut attr = PerfEventAttr::tracepoint(id);
   // SAFETY: `attr` is a live, `#[repr(C)]` `perf_event_attr` whose `size` field is 64, so
   // the kernel reads only those initialised bytes; pid -1 with a non-negative cpu asks
   // for a system-wide event on that cpu, group_fd -1 opens a fresh group, and every
   // variadic argument is widened to `c_long` because glibc's `syscall` reads long slots.
   let fd = unsafe {
      libc::syscall(
         libc::SYS_perf_event_open,
         &mut attr,
         -1 as libc::c_long,
         cpu as libc::c_long,
         -1 as libc::c_long,
         PERF_FLAG_FD_CLOEXEC,
      )
   };
   if fd < 0 {
      return Err(io::Error::last_os_error());
   }
   i32::try_from(fd)
      .map_err(|_| io::Error::other("perf_event_open returned a descriptor wider than i32"))
}

/// Attaches `prog_fd` to an open perf event and enables it.
pub(crate) fn perf_enable(fd: i32, prog_fd: i32) -> io::Result<()> {
   ioctl(
      fd,
      PERF_EVENT_IOC_SET_BPF,
      prog_fd as libc::c_ulong,
   )?;
   ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)
}

/// Issues one of the two perf ioctls above.
fn ioctl(fd: i32, request: libc::c_ulong, arg: libc::c_ulong) -> io::Result<()> {
   // SAFETY: `fd` is an open perf event descriptor owned by this module, and both requests
   // used here take an unsigned long by value (the program descriptor, then zero) rather
   // than a pointer, so no memory is shared with the kernel.
   let rc = unsafe { libc::ioctl(fd, request, arg) };
   if rc < 0 {
      return Err(io::Error::last_os_error());
   }
   Ok(())
}

/// Closes a descriptor this module opened.
///
/// The caller must own `fd` and call this at most once; every call site here pairs it with
/// exactly one successful [`map_create`], [`prog_load`] or [`perf_event_open_tracepoint`].
pub(crate) fn close_owned(fd: i32) {
   // SAFETY: `fd` came from one of this module's syscalls, is owned by the caller, and is
   // not closed anywhere else, so the descriptor is valid and still open here.
   unsafe { libc::close(fd) };
}
