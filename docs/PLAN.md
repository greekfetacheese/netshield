# NetShield — build plan

Phases are ordered so that every step ends with something verifiable, and so the only
steps that need root and a stopped OpenSnitch come late. Each phase is one dsh task
branch (or a small number of them); the gate for every phase is run by the orchestrator,
not taken from the agent's report.

## P0 — Bootstrap (done by orchestrator)

Repo, docs, agent rules, formatting config.

## P1 — `netshield-core`: models, rule engine, parsers  (no privileges)

- Workspace `Cargo.toml`, `rustfmt.toml`, three member crates (GUI crate deferred to P4).
- `connection.rs`: `Connection`, `Endpoint`, `L4Proto`, `ProcessInfo`, `Attribution`.
- `rule.rs`: `Rule`, `RuleId`, `Action`, `Duration`, `AppMatcher`, `DestMatcher`,
  `ScopeRequest` (what a prompt answered), validation of user input.
- `ruleset.rs`: `RuleSet::evaluate(&Connection) -> Outcome` implementing the specificity
  table and tie-breaking from §6, plus `insert/update/remove/replace_all`, hit counting.
- `packet.rs`: bounds-checked IPv4/IPv6 + TCP/UDP/ICMP header parsing from a byte slice,
  returning endpoints and flags. No unsafe, no panics on malformed input.
- `dns.rs`: DNS message parser — header, question, answers; A/AAAA/CNAME; compression
  pointers with loop protection; TTL.
- `dns_cache.rs`: `IpAddr -> {name, expiry}`, TTL-capped, multi-name per IP.
- `config.rs`: `Config` with defaults, serde, validation (queue numbers distinct, timeout
  bounds), atomic save/load helpers.
- `ipc.rs`: the wire protocol types (§3) with serde, including version field.
- Unit tests for all of the above, including malformed/truncated inputs.

Gate: `cargo test -p netshield-core` green, `cargo check --workspace` clean, no clippy
warnings introduced (baseline captured before the change).

## P2 — netlink queue + firewall ruleset  (root; integration proof)

- `netlink/attrs.rs`: `nlattr` encode/decode with alignment, unit-tested against fixtures.
- `netlink/socket.rs`: netlink socket open/bind/send/recv, sequence numbers, ACK handling,
  `EINTR`/`EAGAIN` handling.
- `netlink/nfqueue.rs`: the §4 handshake, packet message parsing, verdict emission,
  `--queue-info` diagnostics.
- `firewall.rs`: render the §2 table, install with `nft -f -` in one transaction, verify by
  reading the ruleset back, remove by deleting only our table, and refuse to touch
  anything else. Must be idempotent and must never leave a table behind on error paths.
- A `netshieldd --probe` mode: install rules, print every queued packet (proto, 5-tuple,
  uid, pid once attribution exists), accept it, remove rules on Ctrl-C.

Gate: with OpenSnitch stopped, `--probe` shows a real `curl` SYN being queued and the
page loading after ACCEPT; `nft list ruleset` shows only our table before and nothing
after. This is the phase that proves the whole premise, so it is verified by hand.

## P3 — process attribution, DNS, daemon loop, prompts, IPC server

- `proc.rs`: `/proc/net/*` 4-tuple → inode, inode → pid with UID-scoped scan and cache,
  exe path / comm / cmdline, unknown attribution.
- DNS queue thread: parse answers into the cache (always ACCEPT).
- Verdict loop: attribution → ruleset → verdict or prompt; flow-grant cache; joining
  duplicate flows to one prompt; PID self-exclusion.
- `prompts.rs`: pending prompts, packet-id sets, deadline, timeout → deny, default-action
  fallback.
- `ipc_server.rs`: SO_PEERCRED check, subscribe/broadcast of events, rule CRUD, status.
- `store.rs`: atomic rules.json persistence, hot reload, validation on load.
- systemd unit and `install.sh`: the installer expects prebuilt binaries (`--bin-dir`),
  never builds, and the GUI is launched by the session's autostart entry.

Gate: on the live machine, an unseen binary produces exactly one prompt; Allow-forever
persists a rule; Deny drops; timeout denies; killing the daemon restores unfiltered
network via `bypass`.

## P4 — egui GUI

- `netshield-gui`: Zeus-style shell (egui-elements theme, egui-lucide icons), pages:
  Connections (live log with rule attribution), Rules (table + editor), Settings, Status
  (daemon state, queue stats, fail-open warning).
- Alert viewport: always-on-top window per prompt, Little Snitch layout (§8), duration +
  scope controls, countdown, "n pending" grouping, action buttons.
- `--mock` mode for development without root, and `--alert` mode for daemon-spawned alerts.
- Reconnect logic: the GUI may start before or after the daemon.

Gate: mock mode exercises every page and the alert; then a real prompt answered from the
GUI changes a real connection's fate.

## P5 — Packaging and docs

- `install.sh`, `.desktop` entry, icon, `README.md` (install/use/uninstall), `SECURITY.md`
  describing the trust model and the documented gaps from §2.
- Manual acceptance pass against the v1 checklist; skill updated with what was learned.
