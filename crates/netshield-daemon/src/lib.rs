//! NetShield's root daemon library.
//!
//! The daemon owns the packet path: it opens an NFQUEUE, reads the packets nftables
//! queues to it, attributes them to a process and answers each one with a verdict.
//! That path speaks `NETLINK_NETFILTER` directly — no `libnetfilter_queue`, no bindgen,
//! no C — so the wire format is implemented and unit-tested here rather than delegated
//! to a library whose behaviour would then be a dependency of the firewall's correctness.
//!
//! The transport lives in [`netlink`] and the table that feeds it in [`firewall`]; both
//! are unit-tested, and [`probe`] (in the binary) wires them together on a live machine.

pub mod firewall;
pub mod logging;
pub mod netlink;
