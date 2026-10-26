# NetShield — Architecture

NetShield is a Linux outbound application firewall: a root daemon that forces every new
outbound connection through a userspace decision, and an egui desktop GUI that asks the
user what to do — with the option to scope an allow/deny to the specific domain being
contacted, which is the one thing OpenSnitch cannot do.

Status: design. v1 targets Linux only (nftables, systemd, `/proc`, Unix sockets).

## 1. Goals and non-goals

Goals:

1. **Interception that cannot be bypassed by ordinary processes.** Every new outbound
   connection (TCP and UDP, IPv4 and IPv6) is held in a kernel queue until the daemon
   issues a verdict.
2. **Per-process policy** with an allowlist/blocklist model.
3. **Root daemon started at boot, unprivileged GUI.**
4. **Interactive prompts** that let the user pick a scope: any connection, or only this
   domain (optionally including subdomains), plus a duration (once / until restart /
   forever).

Non-goals for v1: inbound filtering, system firewall configuration, blocklist
subscriptions, Windows/macOS, per-packet (established-flow) filtering, DNS encryption,
profiles/automatic switching, CLI rule scripting.

## 2. Enforcement model — what "every packet goes through NetShield" means

The kernel decides what reaches the daemon. We install one nftables table whose output
hook queues *new* flows only:

```
table inet netshield {
    chain output {
        type filter hook output priority mangle; policy accept;
        oifname "lo" return comment "netshield: loopback is not filtered"
        tcp flags & (fin|syn|rst|ack) == syn queue num 0 bypass \
            comment "netshield: tcp syn"
        ct state new queue num 0 bypass comment "netshield: non-tcp new flow"
    }
    chain dns_in {
        type filter hook input priority mangle; policy accept;
        udp sport 53 queue num 1 bypass comment "netshield: dns answers"
        tcp sport 53 queue num 1 bypass comment "netshield: dns answers over tcp"
    }
}
```

Four properties, each deliberate:

- **`priority mangle` (-150) and hook `output`** — runs before any accept/drop rule in
  the `filter` chain, in both `inet` families, so one table covers IPv4 and IPv6.
- **Two rules for flows, not one.** `ct state new` alone also matches out-of-order
  packets (a bare ACK or ACK+PSH that conntrack still considers NEW), which produces a
  prompt for a connection the user never sees as new. The SYN-flag rule is listed first
  and catches TCP precisely; `ct state new` covers UDP and the remaining cases. This is
  OpenSnitch's conclusion after the same bug, and it is worth inheriting.
- **`bypass`** — if no userspace program is listening on the queue, the kernel
  **accepts** the packet instead of holding it. That is the fail-open guarantee: a
  crashed daemon cannot freeze the network, and it is enforced by the kernel rather than
  by cleanup code that a crash never runs.
- **`policy accept`** — the chain is an interception hook, not a filter. Packets that
  match no rule (established flows) continue normally.

Established flows are *not* re-examined. The first packet of a flow is the decision
point; afterwards the kernel conntrack entry already exists, so the rest of the
connection is not interrupted mid-stream by a GUI that has gone away.

Known and documented gaps (honest limits of a userspace firewall):

- A process with `CAP_NET_RAW` can inject packets with `AF_PACKET`, which traverses
  `dev_queue_xmit` and skips the output hook entirely. Root can also flush our table or
  load modules. NetShield defends against unprivileged processes and accidental leaks; it
  is not a defence against an attacker who already has root.
- Loopback is not filtered (it would put every X11/D-Bus/IPC byte through a userspace
  round trip for no security value).
- Traffic the daemon itself generates is excluded by PID, and the GUI makes no network
  calls at all.
- DNS over HTTPS/TLS is upstream-encrypted; the daemon can see *that* a resolver
  connection happened, but not the name inside it. See §7.

## 3. Processes and data flow

```
   app connect() ──► nft output hook ──► NFQUEUE 0 ──► netshieldd
                                                          │
                       DNS answer ──► NFQUEUE 1 ──────────┤ (parse, cache, ACCEPT)
                                                          │
                                                   rule evaluation
                                                    ┌─────┴─────┐
                                              matched          no match
                                                    │               │
                                             verdict now     prompt via /run/netshield/control.sock
                                                    │               │
                                                    │        netshield-gui (unprivileged)
                                                    │               │
                                                    └──────◄── decision + scope + duration
```

- **`netshieldd`** (root, systemd) owns the netlink queue sockets, the rule store, the
  prompt lifecycle and the control socket. Threads: queue-0 reader, queue-1 reader,
  control-socket acceptor, prompt supervisor (timeouts), signal handler.
- **`netshield-gui`** (user) connects to the control socket, renders the connection log,
  the rule manager and settings, and owns the alert windows. It is started at login by an
  XDG autostart entry. The root daemon never spawns a GUI, because a root-owned GUI would
  render on the user's display with full privileges.
- **IPC** is a `SOCK_STREAM` Unix socket, newline-delimited JSON. The daemon is the
  server; it authenticates each connection with `SO_PEERCRED` and rejects any UID other
  than `allowed_uid` (default: the user who owns the session, configured at install).

## 4. The verdict path

Reading packets means speaking `NETLINK_NETFILTER` directly — no `libnetfilter_queue`,
no C, no bindgen.

Socket: `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)`, `bind` with `nl_pid = 0` so
the kernel assigns the port id. Message type is `(NFNL_SUBSYS_QUEUE << 8) | msg`, where
`NFNL_SUBSYS_QUEUE = 3`; every payload starts with `struct nfgenmsg`
(`family, version, res_id = htons(queue)`).

Handshake per queue, in order (config messages carry `NLM_F_REQUEST`):

1. `NFQNL_CFG_CMD_PF_UNBIND` for `AF_INET`, `AF_INET6` — tolerate `ENOENT`/`EINVAL`;
   kernels ≥ 3.8 auto-bind, so this is legacy and must never be fatal (OpenSnitch has
   needed extra hardening here for years).
2. `NFQNL_CFG_CMD_PF_BIND` for both families, same tolerance.
3. `NFQNL_CFG_CMD_BIND` on the queue number.
4. `NFQA_CFG_PARAMS` — `copy_mode = NFQNL_COPY_PACKET`, `copy_range = 0xFFFF`.
5. `NFQA_CFG_QUEUE_MAXLEN` — 4096.
6. `NFQA_CFG_FLAGS` with `NFQA_CFG_MASK`: `NFQA_CFG_F_UID_GID` (the kernel then attaches
   the socket's UID/GID to each packet, so we never need `/proc` for the user) and
   `NFQA_CFG_F_CONNTRACK` (conntrack state and mark). Do **not** set
   `NFQA_CFG_F_FAIL_OPEN` in v1: its behaviour surprises (it propagates across queues),
   and the nft `bypass` flag already gives us fail-open where we want it.

Incoming `NFQNL_MSG_PACKET` attributes we consume: `NFQA_PACKET_HDR` (packet id, hook),
`NFQA_PAYLOAD` (the raw IP datagram), `NFQA_MARK`, `NFQA_UID`/`NFQA_GID`,
`NFQA_IFINDEX_OUTDEV`, `NFQA_HWADDR` (for the GUI), `NFQA_TIMESTAMP`.

Verdict: `NFQNL_MSG_VERDICT` with `NFQA_VERDICT_HDR` (`verdict`, `packet_id`). v1 uses
`NF_ACCEPT` (1) and `NF_DROP` (0). Deny drops silently — the application sees a hang and
retries, which is what Little Snitch does — while `Reject` (drop plus a locally generated
TCP RST) is carried in the rule model but not generated in v1. `NF_REPEAT` and `NF_STOP`
are unused. Invalid bodies are answered with `NF_DROP`, never by omission: an unverdicted
packet id sits in the queue until the queue is destroyed.


Every queued packet id must receive exactly one verdict. A pending prompt therefore
tracks *all* packet ids belonging to the same flow — a TCP SYN retransmits about once a
second, so a 30-second prompt accumulates several — and answers them together.

## 5. Process attribution

The packet gives us a 4-tuple and a UID. To get the PID:

1. Look up the socket inode by matching the 4-tuple in `/proc/net/tcp`, `tcp6`, `udp`,
   `udp6` (field layout: index 1 local, 2 remote, 3 state, 7 uid, 9 inode).
2. Translate inode → PID by scanning `/proc/<pid>/fd/*` symlinks for `socket:[<inode>]`,
   restricted to pids owned by the packet's UID and cached (pid → fd set, 1 s TTL).
3. Read `/proc/<pid>/exe` (path to the binary — the rule key), `/proc/<pid>/cmdline` and
   `/proc/<pid>/comm`.

If step 1 or 2 fails (short-lived process, race, socket already closed) the connection is
attributed to *unknown*, is shown as such in the prompt, and is governed by an explicit
`unknown` matcher rather than being silently allowed. Silent allow is not an option: a
firewall that fails open on lookup failure is a decoration.

Root-owned sockets are excluded when the PID resolves to the daemon itself.

Future optimisation, explicitly out of scope for v1: replace step 1 with `NETLINK_SOCK_DIAG`
(no `/proc` scan) and step 2 with an eBPF probe on `connect()` for exact, race-free
attribution. The rule engine does not care which path produced `ProcessInfo`.

## 6. Rule model and matching

A rule is the unit of policy. It answers: *may this application talk to this destination?*

```rust
struct Rule {
    id: RuleId,
    enabled: bool,
    app: AppMatcher,        // Any | Path(exact) | Unknown | Exe(sha256)
    dest: DestMatcher,      // Any | Domain { host, subdomains } | Ip(Cidr) | Port(u16)
    action: Action,         // Allow | Deny  (Reject is deferred to v2)
    duration: Duration,     // Once | Session | Forever
    note: Option<String>,
    created_at: u64,
    last_matched: Option<u64>,
    hits: u64,
}
```

Specificity, highest first. The comparison is **lexicographic on (app rank, destination
rank)**: application scope is the outer dimension, so a rule about one application always
outranks a rule about all applications. That ordering is deliberate — a global
"allow * → github.com" must never punch a hole in an application-level deny.

| Rank | App matcher                        | Example                        |
|------|------------------------------------|--------------------------------|
| 2    | `Exe(path)` / `Unknown`            | `firefox` · unattributable socket |
| 0    | `Any`                              | every application              |

| Rank | Destination matcher  | Example                                   |
|------|----------------------|-------------------------------------------|
| 40   | `Domain` exact       | app X → `api.github.com`                  |
| 30   | `Domain` + subdomains| app X → `*.github.com`                    |
| 20   | `Ip` (CIDR)          | app X → `140.82.0.0/16`                   |
| 10   | `Port`               | app X → any host, port 443                |
| 0    | `Any`                | app X → anywhere                          |

Ties break by `Deny` before `Allow` (the safe default), then by most recently updated.
An application with no matching rule falls through to the configured default action:
`prompt` (v1 default), `allow` or `deny`.


Durations:

- **Once** — the decision covers this flow only; it is kept in a short-lived in-memory
  grant, never persisted, and the next distinct connection prompts again.
- **Session** — in-memory rule, lost when the daemon restarts.
- **Forever** — written to the rule store.

Domain scope is what makes this worth building. When a prompt is answered with
"only this domain", the rule's destination is the hostname learned from DNS (§7), matched
against that exact name, with an optional `subdomains` flag that also matches
`*.host`. No public-suffix guessing: `ads.example.co.uk` yields the exact host and the
user may add subdomains, but nothing silently widens to `co.uk`.

### First-run defaults

A user must never be asked about their own DNS. On first start (no rule store yet) the
daemon seeds exactly one rule — `allow`, `Forever`, application = the systemd-resolved
executable path, destination = `Port(53)` — and writes it to the store, so it appears in the
GUI's rule list and can be inspected or deleted like any other rule. It is keyed on the
binary path rather than the resolver's UID, which differs between machines. If no resolver
binary is found the seed is skipped with a `warn!`: a machine whose resolver is unattributed
will prompt, and that is better than a silent allow.


## 7. DNS attribution

Domain-scoped decisions need name ↔ address correlation. The daemon listens on queue 1
for DNS *answers* (source port 53, TCP and UDP), parses them (`A`, `AAAA`, `CNAME`, with
TTL) into an `IpAddr → { name, expires_at }` cache, and immediately accepts.

Consequences worth stating plainly:

- Answers seen on the wire give the name for the vast majority of desktop traffic.
- A resolver using DoH/DoT to a local stub (systemd-resolved with `DNSOverTLS=yes`) hides
  the answer from us, so the prompt can only show an IP. The domain option is then
  disabled rather than guessed.
- When several names map to one address, the most recently learned one is shown and the
  rest are available in the prompt's details.
- Entries expire with their record TTL (capped at 1 h) so a reassigned address does not
  inherit a stale name.

## 8. Prompt lifecycle

1. No rule matches a flow → allocate a `PromptId`, register the flow, send
   `Prompt { id, connection }` to the GUI.
2. The GUI renders an alert window (always-on-top viewport) with app name/icon, the
   destination host and address, the scope choice and a duration choice.
3. `Decide { id, action, duration, scope }` arrives → verdict every packet id of that
   flow, write the rule for the chosen duration, log the decision, broadcast the event.
4. Timeout (`prompt_timeout_secs`, default 30) → `Deny`, logged as a timeout.
5. GUI absent/unreachable → the daemon warns once per prompt and the prompt is denied when
   it times out; it never spawns a GUI.
6. Duplicate flows while a prompt is open (same app, same destination) join the open
   prompt instead of stacking new windows; the alert shows "n pending" and the decisions
   apply together.

The alert is modelled on Little Snitch's connection alert: app icon and name, "wants to
connect to *host*", a duration selector, a scope radio group ("Any connection" / "Only
*domain*" with a subdomains checkbox) and two decisions, Deny and Allow.

## 9. Storage and packaging

- `/etc/netshield/config.json` — settings, written atomically (temp file + `rename`).
- `/etc/netshield/rules.json` — `Forever` rules, same atomic-write path, hot-reloaded.
- `/run/netshield/control.sock` — `0660`, owned by `allowed_uid` and that user's primary
  group when `allowed_uid` is set (chown after bind; the `SO_PEERCRED` check is still
  enforced), `root:root` otherwise.
- `/etc/systemd/system/netshield.service` — `Type=simple` with `Restart=on-failure`,
  `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`. `NET_ADMIN` programs
  nftables and owns the NFQUEUE sockets; `SYS_PTRACE` and `DAC_READ_SEARCH` are required
  to read `/proc/<pid>/exe` and `/proc/<pid>/fd` for processes of other users (the
  resolver runs as its own uid), without which attribution degrades to `Unknown` and
  every DNS lookup would prompt.
- `install.sh` — installs prebuilt binaries (`--bin-dir`), writes the systemd unit and
  the XDG autostart entry with the invoking user's UID recorded as `allowed_uid`, enables
  the service, and refuses to run while another application firewall (OpenSnitch) is
  active. It never builds; the GUI is launched by the session's autostart entry.

## 10. Crates and dependencies

Workspace, three crates, no async runtime (blocking threads are correct here and
`tokio` would be the largest dependency in the tree):

- `netshield-core` — no I/O: models, rule engine, DNS/​packet parsers, config, IPC types.
  Deps: `serde`, `serde_json`.
- `netshield-daemon` — netlink, nftables, `/proc`, IPC server. Deps: `netshield-core`,
  `libc`, `log`, plus `serde`/`serde_json` for the rule store and the control protocol
  (both already in the tree through core; the store is JSON by design so it can be read and
  hand-edited).
- `netshield-gui` — eframe/egui + `egui-elements`, `egui-elegance`, `egui-lucide`
  (pinned to the versions Zeus uses), `netshield-core`, `log`.

Everything else is hand-written on purpose: the nfnetlink protocol, the IP/TCP/UDP header
parser, the DNS message parser, the netlink socket plumbing. Each is a few hundred lines
with unit tests, and each replaces a dependency (or a C library) that would otherwise
dominate the tree. `nft` is invoked as a process with `nft -f -` (one atomic transaction
per change) rather than linking `libnftables`; it is a required system tool, not a crate,
and going native is a later optimisation.

## 11. Testing

- **Unit, no privileges** (`netshield-core`): rule specificity and tie-breaking, duration
  semantics, DNS parsing including compression pointers and malformed input, TTL expiry,
  IP/TCP/UDP header parsing from crafted byte buffers, config round-trip.
- **Mock mode** (`netshield-gui --mock`): the GUI generates synthetic prompts and
  connection events, so the whole alert flow and every page can be developed and reviewed
  without root, without nftables and without touching the machine's real network.
- **Integration, root required**: a `netshieldd --check` self-test that installs the
  ruleset, opens both queues, proves a SYN is queued and that a verdict is honoured, then
  removes everything. Runs against a stopped OpenSnitch on Mike's machine and in CI later.
