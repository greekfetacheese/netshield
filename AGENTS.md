# NetShield — agent rules

A Linux application firewall in Rust: root daemon (`netshieldd`) + egui GUI
(`netshield-gui`). Read `docs/ARCHITECTURE.md` before touching anything; it is the
authority on the enforcement model, the rule model and the protocol. `docs/PLAN.md` says
which phase is current.

## Non-negotiables

1. **Read the design doc first.** If the brief and `docs/ARCHITECTURE.md` disagree, stop
   and report the contradiction — do not pick one.
2. **No new dependencies.** The dependency set is a design decision, not an
   implementation detail: `netshield-core` has `serde` + `serde_json` and nothing else; the
   daemon adds `libc`, `log`, `redb` (the rule store) and `serde`/`serde_json` (the control
   protocol is JSON, and both crates are already in the tree via core); the GUI adds the
   egui stack pinned to the versions in `Cargo.toml`, plus `serde`/`serde_json` for its own
   preferences file (`~/.config/netshield/gui.json`). Anything else needs the orchestrator's
   approval first.
3. **No async runtime.** Threads and blocking I/O. Never introduce `tokio`/`async-std`.
4. **No `unsafe` outside `netshield-daemon/src/netlink/`** (and the `/proc` reads if a
   raw syscall is genuinely required), with one sanctioned exception: the `libc::chown`
   call in `crates/netshield-daemon/src/ipc_server.rs::chown_socket`, which hands the
   control socket to `allowed_uid`. Raw kernel interfaces that have no C library — the
   BPF probe loader in `crates/netshield-daemon/src/ebpf/` — are the second exception:
   `bpf(2)`, `perf_event_open(2)` and the instruction encoding have no safe wrapper without
   a new dependency, which this project does not take. The module must fail closed: any
   error from loading or attaching means the daemon runs with `/proc` attribution alone,
   exactly as before. Every `unsafe` block carries a comment naming its
   invariant, and the module keeps its inputs bounds-checked before it is reached.
5. **Never `cargo fmt` workspace-wide.** Format touched files only:
   `rustfmt --edition 2024 --config-path rustfmt.toml --config skip_children=true <file>`
6. **Never `--profile prod`.** Debug for `cargo check`/`cargo test`, `--release` when
   asked.
7. **Test scope:** the crate you touched (`cargo test -p netshield-core`), never
   `--workspace`, unless the brief says otherwise.
8. **Parsers must be panic-free on hostile input.** Every byte offset in `packet.rs`,
   `dns.rs` and the netlink attribute reader is checked; a malformed packet is an `Err`,
   never an index panic. Untrusted input arrives from the network and from the kernel.
9. **Security posture: fail loud.** A dropped packet, an unusable rule, an unattributable
   process or a failed firewall install is logged at `warn`/`error` and surfaced, never
   silently absorbed into a default. Do not add fallbacks that turn an error into an
   allow.
10. **Match the surrounding style.** 3-space indent, `max_width = 100` (see
    `rustfmt.toml`), doc comments on public items that explain *why*, error enums rather
    than `anyhow` in the daemon, no dead code, no duplicated logic.
