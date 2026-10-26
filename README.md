# NetShield

A Linux application firewall: every new outbound connection is held in the kernel until
you decide what happens to it, per application — with the ability to scope a decision to
the specific domain being contacted.

Inspired by OpenSnitch and Little Snitch; pure Rust, egui GUI, nftables + NFQUEUE beneath.

**Status: early development.** The architecture is settled (`docs/ARCHITECTURE.md`) and
the build plan is in `docs/PLAN.md`. Nothing is installed or usable yet.

## How it works, in one paragraph

`netshieldd` (root) installs a single nftables table that queues the first packet of every
new outbound flow — TCP via a SYN match, everything else via conntrack — into an NFQUEUE
it reads over a raw netlink socket. For each queued packet it resolves the owning process
from `/proc`, matches the connection against the rule store, and answers the kernel
immediately (allow/deny) or holds it while `netshield-gui` (unprivileged) shows an alert.
The rules are per application and can be scoped to a domain learned from DNS answers, so
"allow Firefox to reach api.github.com" is a rule you can actually express.

If the daemon dies, the queue's `bypass` flag makes the kernel accept traffic rather than
freeze the machine; that is a deliberate fail-open choice, recorded at boot in the GUI.

## Repository layout

```
crates/netshield-core     models, rule engine, packet/DNS parsers, IPC types (no I/O)
crates/netshield-daemon   netlink NFQUEUE transport, nftables, /proc attribution, IPC server
crates/netshield-gui      egui GUI: connection log, rule manager, alert windows
docs/                     architecture and build plan
packaging/                systemd unit, install script
```

## Requirements

Linux with nftables (kernel ≥ 5.10 realistic, developed against 7.0), Rust ≥ 1.90,
systemd. Root is required for the daemon; the GUI runs as the logged-in user.

## Licence

Dual-licensed under MIT or Apache-2.0, at your option.
