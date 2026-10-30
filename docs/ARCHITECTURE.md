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

The daemon does not trust the table it installed for ever. Every 30 s it reads the table
back with `nft list table` and re-runs the same check as startup: both chains, both queue
numbers. A table removed or rewritten by anything else would otherwise leave the daemon
logging decisions while nothing enforces them. The read-back is one process per interval
and never per packet. A failure is logged once per transition, published through
`StatusInfo::table_verified`, and **repaired**: the daemon reinstalls the same table it installs at
startup (`force`, so a rewritten table is replaced rather than reported as a second instance) and
re-verifies it, because nothing else puts the table back and a restart is a window with no queue
bound — which the kernel accepts. A failed reinstall stays at `debug!`, so the transition error is
not buried; the flag returns to true — with one `info!` — on the next
successful check. A stalled loop catches up one interval per check rather than running
the missed probes back to back.

Established flows are *not* re-examined. The first packet of a flow is the decision
point; afterwards the kernel conntrack entry already exists, so the rest of the
connection is not interrupted mid-stream by a GUI that has gone away.

Known and documented gaps (honest limits of a userspace firewall):

- A process with `CAP_NET_RAW` can inject packets with `AF_PACKET`, which traverses
  `dev_queue_xmit` and skips the output hook entirely. Root can also flush our table or
  load modules. NetShield defends against unprivileged processes and accidental leaks; it
  is not a defence against an attacker who already has root.
- **The control socket raises the cost of a hostile local process; it does not exclude one.**
  `gui_path` is compared against `/proc/<pid>/exe`, which names a *file*: a process running as the
  same uid can execute the GUI binary with a preloaded library (`LD_PRELOAD`) and keep that path, so
  it is accepted as the GUI and can flip the mode or write a rule. Closing this needs the GUI to have
  an identity of its own plus an authenticated writer (polkit) — a design change, not a patch. Read
  the gate as "the daemon obeys the GUI shape it was configured with", never as "policy cannot be
  changed without a click".
- Loopback is not filtered (it would put every X11/D-Bus/IPC byte through a userspace
  round trip for no security value).
- Traffic the daemon itself generates is excluded by PID, and the GUI makes no network
  calls at all.
- DNS over HTTPS/TLS is upstream-encrypted; the daemon can see *that* a resolver
  connection happened, but not the name inside it. See §7.
- Every queued flow is now decided, prompted or denied; none is waved through. ICMP echo
  requests and port-less transports (SCTP, DCCP, GRE, ESP, IP-in-IP) are **denied by
  default**, because no rule can express a decision about them — an unfiltered channel is
  what this firewall exists to remove. `icmp_echo: allow` and `unmatched_transport: allow`
  restore the pass-through explicitly. ICMP error types (unreachable, time exceeded,
  parameter problem, packet too big) always pass: the kernel generates them, and dropping
  path-MTU messages breaks ordinary TCP.

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
  Authorization has two tiers: a peer of `allowed_uid` may always `Hello`, `Subscribe`,
  `ListRules` and `Status`, but only the configured GUI executable may `Decide`, edit rules
  or `SetMode`. The server compares the peer's `/proc/<pid>/exe` (with a trailing
  `" (deleted)"` stripped) to `gui_path` once at connect and again immediately before every
  state-changing request; a mismatch, an unreadable link or pid 0 is a refusal that answers
  `Error` and closes the connection. When `gui_path` is absent the historical uid-only rule
  stands and the daemon warns at startup that any process of that uid can change state; every
  state-changing request is logged at `info` with the client id, pid, executable and request.
  That comparison identifies a file, not the code running in it: the same uid can execute the GUI
  binary with `LD_PRELOAD` and keep `/proc/<pid>/exe` at the configured path, so the gate raises the
  cost of a hostile local process rather than excluding one (see the matching gap in §1).

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

Two cases are decided without a prompt, because a prompt could not change anything:

- **The socket is already gone.** When the kernel named a UID and a *complete* scan of the
  socket table and the descriptor table found no owner, the application has closed the
  descriptor: nothing is waiting for a reply, and no later scan can find an owner. A scan that
  ran out of budget or could not read a descriptor directory is not that case, and still
  prompts. Such flows are **dropped** by default
  (`unattributable_closed_flow: drop`), logged once per address and shown as denied in the
  connection log. `allow` exists for applications that send one datagram and close it
  immediately; `prompt` restores the old behaviour. An explicit `unknown` allow rule still wins,
  because the rule engine decides first — this default only applies when no rule matches.
- **Multicast destinations** (`224.0.0.0/4`, `ff02::/16`). mDNS binds its shared port with
  `SO_REUSEPORT`, so the row that exists belongs to another UID's socket and the flow is
  unattributable in principle; multicast cannot leave the link, so it is allowed once and logged
  once per application rather than prompted for.

Both defaults exist because the alternative was measured: Chromium opens and closes speculative
sockets (QUIC racing losers, cancelled preconnects) inside the ~5 ms attribution window, so the
old behaviour produced an `unknown` prompt for traffic that had already been abandoned.

A flow whose transport has no ports never reaches attribution at all: an ICMP echo request
(`icmp_echo`, default `deny`) and every port-less protocol (`unmatched_transport`, default
`deny`) are decided from the parsed packet and the owner's settings, logged at most once per
protocol and ICMP type per minute, counted in `queue_drops`, and denied unless explicitly
allowed. ICMP error types are always accepted so path-MTU discovery keeps working.

On the same machine the daemon also loads a small BPF program on the `sys_enter_sendto` and
`sys_enter_connect` tracepoints. It records `(uid, destination) -> (thread group id, timestamp)`
into a hash map at syscall time — which is before the socket can be closed — so a flow whose socket is already
gone still has a *name* for the log. **It is not an attribution source.** Its key carries no local
port, no inode and no pid, so two processes of one uid sending to the same destination are
indistinguishable in it, and a uid cross-check could never reject the confusion it looked like it
prevented — the packet's uid *is* the key's uid. Letting it answer after a failed scan therefore
handed one application's allow rule to another; a hit is now logged ("the send registry suggests pid
N") and the verdict stays whatever `unattributable_closed_flow` says. The probe is optional: no
tracefs, no `CAP_BPF`, or a tracepoint whose format no longer names its `sockaddr` argument means the
daemon runs on `/proc` alone, which is what it did before. Batching syscalls (`sendmmsg`) and `send`
on an already-connected socket are not
recorded yet; those flows keep the `/proc` behaviour.

This attribution path has a hard limit that no amount of `/proc` polling removes: it can
only attribute a socket that is still present when the scan runs, and it can only use the
UID when the kernel supplied one with the packet (`uid: null` in the connection events
means it did not). Both conditions fail at once for applications that resolve names
directly against a public resolver (`2606:4700:4700::1111`, `127.0.0.53` and the like): the
UDP socket is often already closed, and the kernel reports no UID, so the port-only UDP
fallback yields a candidate inode that no process owns. Such flows are logged as
`Unknown` — never treated as an allow; `default_action` decides them — and the durable fix
is socket-creation tracking (eBPF on `connect()`), which is deliberately out of v1 scope.
The one-second negative flow cache only makes the resulting miss cheap; it does not make a
uid-less flow attributable.

The *positive* side of that cache has to prove it is still about this flow. It is keyed by the
5-tuple, and a 5-tuple is reproducible: `/proc/net/{tcp,udp}` is world-readable, so a process can
watch an allowed application's flow disappear, bind that exact local port to the same remote and be
mistaken for it. A hit therefore also requires the socket's inode to be one the same pid still holds
— evidence only a real `/proc` scan records, and one the kernel does not recycle under a live socket.
Anything else falls through to a fresh lookup.

Both halves are now read once per **batch** of queued packets, not once per packet: `/proc/net/*` and each
descriptor directory are snapshotted at the start of a burst and every packet the kernel had already queued
is decided against that one snapshot. The evidence is unchanged in kind — it is still the kernel naming the
socket's inode — and it is valid for the whole batch, because a socket exists before any packet it sends, so
a snapshot taken after those packets were received necessarily contains the socket behind each of them.
Measured here: a 1513-row `/proc/net/udp` read costs 7.4 ms and a 1500-descriptor directory scan 5.9 ms, so
per-packet reads were ~14 ms of work for every new flow.

An attributed pid is not automatically the image that opened the socket. A process can `connect()`
and then `execve()` an allowed binary; the socket survives the exec, so `/proc` still names that pid
while the code that sends is the new image. The daemon therefore compares the socket's creation time
(the `/proc/<pid>/fd` link's `mtime`) with the moment the running image started, taken from the proc
connector's `exec` event — stamped by the kernel inside the event, not by the thread that handles it,
so the check is not paying for scheduling lag. A flow is refused only when the exec demonstrably
followed the socket; 1 ms of slack covers reading the two clocks as a pair. A refused flow is
`Unknown`, never the allowed binary's rules.

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
- When several names map to one address, the prompt shows the most recently learned one, but
  **matching** considers every live name for that address: a domain rule matches if any of
  them does, and the best match sets its rank. Otherwise a `deny evil.com` would be silently
  shadowed the moment another name on the same shared address (a CDN edge, typically) was
  learned, and an `allow bank.com` would only hold while it happened to be the newest name.
- Per-application name ownership is a v2 item: the app's own query goes over loopback, which
  this design does not filter, so the cache cannot attribute a name to the process that asked.
- Entries expire with their record TTL (capped at 1 h) so a reassigned address does not
  inherit a stale name.
- The cache accepts an answer from **any** sender: the queue matches source port 53 on the input hook,
  so a process can query a server it picked and have that server's records cached under any name it
  likes. A name is therefore a hint, never a guarantee — which is why the alert always prints the
  address beneath it. One address carries at most 16 names, and `dns_servers` restricts which source
  addresses may teach the cache at all; in both cases the answer is still delivered, only the naming is
  affected.
- Because matching considers every live name for an address, a poisoned name can only ever *widen* what
  a domain rule matches; it cannot stop a deny from matching the real answer's name.

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
7. A decision that creates a rule is applied retroactively to the prompts still queued,
   because a browser can queue dozens of flows before the first answer; queued prompts a
   rule now covers are verdicted and never shown. The prompt being answered is never swept,
   and a queued prompt a rule does not cover keeps waiting without a deadline.
8. The open prompt set is capped at 2000 (`PendingPrompts::MAX_PROMPTS`). An unbounded set
   is a same-uid memory DoS: a process that opens distinct flows keeps every one of their
   `Connection`s and packet ids alive until it is answered or times out. A flow that would
   create a prompt at the cap is denied and logged once per 60 s, never queued silently;
   a flow of an app whose prompt is already open still joins it at the cap, because that
   only adds a destination or a packet id to a prompt that exists and capping it would
   drop verdicts.

The alert is modelled on Little Snitch's connection alert: app icon and name, "wants to
connect to *host*", a duration selector, a scope radio group ("Any connection" / "Only
*domain*" with a subdomains checkbox) and two decisions, Deny and Allow.

## 9. Storage and packaging

- `/etc/netshield/config.json` — settings, written atomically (temp file + `rename`).
  `icmp_echo` (`deny` by default) decides an ICMP echo request; `unmatched_transport`
  (`deny` by default) decides a queued flow whose protocol has no ports (SCTP, DCCP, GRE,
  ESP, IP-in-IP). `allow` on either restores the pre-2026 pass-through; missing keys load as
  `deny`, so an upgrade never opens them. ICMP error types always pass.
  `gui_path` names the only executable allowed to change firewall state over the control
  socket (the installer writes `$PREFIX/bin/netshield-gui`); every other process of
  `allowed_uid` stays read-only. `gui_path: null` means any process of `allowed_uid` may
  change state, and the daemon warns prominently about it at startup. A path that does not
  exist is not a config error: it is a runtime refusal of every write.
  `dns_servers` (empty by default) lists the source addresses whose answers may teach the name cache;
  empty keeps the historical acceptance of any sender and is reported at startup, never silently assumed.
- `$XDG_CONFIG_HOME/netshield/gui.json` (`~/.config/netshield/gui.json`) — the GUI's own
  preferences: the Connections log's caps, `rows_per_app` (default 100, range 10–1000) and
  `max_apps` (default 32, range 1–128). Written atomically by the unprivileged GUI and never
  read by the daemon; a missing or unparsable file means the defaults, and out-of-range values
  are clamped.
- `/etc/netshield/rules.db` — a redb database keyed by rule id, one record per `Forever`
  rule, written per record (never rewritten wholesale) and committed with
  `Durability::Immediate`. It is opened before the firewall is installed, so loading is load
  or default: a store that cannot be opened, whose schema is unknown, or that holds a record
  which does not decode is renamed to `<name>.unreadable` and replaced with a freshly seeded
  one; a path that cannot be created falls back to an in-memory store for the session. The
  daemon always starts. The one exception is a store **open in another process** (redb locks
  the file, so `netshieldd --check` against a running service sees this): it is left untouched
  and this process runs in memory, because replacing a live database would destroy the rules
  the running daemon is serving from.
- `/run/netshield/control.sock` — `0660`, owned by `allowed_uid` and that user's primary
  group when `allowed_uid` is set (chown after bind; the `SO_PEERCRED` check is still
  enforced), `root:root` otherwise. `/run/netshield` itself is mode `0711`: traversal
  without listing for any local user, which the GUI needs to reach the socket.
- `/etc/systemd/system/netshield.service` — `Type=simple` with `Restart=on-failure`,
  `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, `CAP_CHOWN`,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`.
  `NET_ADMIN` programs nftables and owns the NFQUEUE sockets; `SYS_PTRACE` and
  `DAC_READ_SEARCH` are required to read `/proc/<pid>/exe` and `/proc/<pid>/fd` for
  processes of other users (the resolver runs as its own uid), without which attribution
  degrades to `Unknown` and every DNS lookup would prompt; `CHOWN` is required to chown
  the control socket to the GUI user.
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
  `libc`, `log`, `redb` (the rule store), plus `serde`/`serde_json` for the control protocol
  (both already in the tree through core).
- `netshield-gui` — eframe/egui + `egui-elements`, `egui-elegance`, `egui-lucide`
  (pinned to the versions Zeus uses), `netshield-core`, `log`.

Everything else is hand-written on purpose: the nfnetlink protocol, the IP/TCP/UDP header
parser, the DNS message parser, the netlink socket plumbing. Each is a few hundred lines
with unit tests, and each replaces a dependency (or a C library) that would otherwise
dominate the tree. `nft` is invoked as a process with `nft -f -` (one atomic transaction
per change) rather than linking `libnftables`; it is a required system tool, not a crate,
and going native is a later optimisation. The binary is resolved from a fixed list of
absolute paths (`/usr/sbin/nft`, `/usr/bin/nft`, `/sbin/nft`, `/bin/nft`), never through
`PATH`: the daemon runs as root, and a unit or a privileged shell that put a writable
directory on `PATH` would otherwise choose which binary programs the firewall. If none of the
four exists the result is `FirewallError::NftMissing`, which already says nftables is required.

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
