//! NetShield's root daemon library.
//!
//! The daemon owns the packet path: it opens an NFQUEUE, reads the packets nftables
//! queues to it, attributes them to a process and answers each one with a verdict.
//! That path speaks `NETLINK_NETFILTER` directly — no `libnetfilter_queue`, no bindgen,
//! no C — so the wire format is implemented and unit-tested here rather than delegated
//! to a library whose behaviour would then be a dependency of the firewall's correctness.
//!
//! Only the transport lives in this crate today. The rule engine and the process
//! attribution built on top of it consume `netshield-core`'s pure model, which is why the
//! dependency edge exists before the first use.

pub mod netlink;
