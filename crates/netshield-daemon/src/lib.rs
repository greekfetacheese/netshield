//! NetShield's root daemon library.
//!
//! The daemon owns the packet path: it opens an NFQUEUE, reads the packets nftables
//! queues to it, attributes them to a process and answers each one with a verdict.
//! That path speaks `NETLINK_NETFILTER` directly — no `libnetfilter_queue`, no bindgen,
//! no C — so the wire format is implemented and unit-tested here rather than delegated
//! to a library whose behaviour would then be a dependency of the firewall's correctness.
//!
//! The transport lives in [`netlink`], the table that feeds it in [`firewall`], and the
//! loop that ties them together in [`daemon`]: [`policy`] turns a connection into a
//! decision, [`pending`] holds the prompts waiting on a user, and [`ipc_server`] is the
//! control socket the GUI talks to. All four are unit-tested; [`daemon::run`] wires them
//! together on a live machine.

pub mod conntrack;
pub mod daemon;
pub mod ebpf;
pub mod firewall;
pub mod ipc_server;
pub mod logging;
pub mod netlink;
pub mod pending;
pub mod policy;
pub mod proc;
pub mod store;
