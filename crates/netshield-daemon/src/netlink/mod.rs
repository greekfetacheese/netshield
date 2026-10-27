//! Direct `NETLINK_NETFILTER` transport for the NFQUEUE verdict path.
//!
//! The modules are layered the way the kernel lays the wire format out: [`attrs`] encodes
//! and decodes `nlattr` TLVs, [`socket`] frames messages and owns the socket, and
//! [`nfqueue`] builds the queue handshake and the packet/verdict payloads on top.
//!
//! The process connector shares the raw-call confinement but not the nfnetlink wire
//! format: [`proc_connector`] is a native-endian `NETLINK_CONNECTOR` feed of `exec` and
//! `exit`, which is what lets attribution survive a process that exits mid-scan.
//!
//! `unsafe` is confined to this module tree: every syscall is a raw `libc` call whose
//! arguments are constructed here from fixed layouts, and every block comments the
//! invariant that makes the call sound. Inputs from the kernel are bounds-checked before
//! they reach any offset, so a hostile datagram is an error rather than a panic.

pub mod attrs;
pub mod nfqueue;
pub mod proc_connector;
pub mod socket;
