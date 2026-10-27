# `dev/` — debugging harnesses

The harnesses that found the bugs listed in `docs/DEBUGGING.md`, plus `netns-run.sh` which
runs the real daemon unprivileged. They are not a test suite: each reproduces one failure
mode, and the point is the log it prints.

**Two families, two environments.**

- **GUI-side** (`fake-daemon.py`, `iconify`, `click_at`, `check-alert-minimised.sh`) need a
  real X display and a built `netshield-gui`. They **do not work inside `agent-sandbox`**:
  winit fails there with `XMapRaised: BadDrawable`, so a window is never mapped and every
  window lookup comes back empty. Run them from a desktop session.
- **Network-side** (`netns-run.sh`, `decide-client.py` against it) work inside
  `agent-sandbox`: `unshare -rn` is available, and the daemon is perfectly happy in a
  private namespace. This is the pair to reach for when you want to watch the real daemon
  without root and without touching the host firewall.

Requirements: `python3`; `gcc` and the X11 headers for the two C tools; `wmctrl`,
`xwininfo`, `xprop`, `xwd` and a running window manager for the GUI harness; `unshare`,
`ip`, `nft` (usually at `/usr/sbin/nft`) and `curl` for the netns harness.

Nothing writes outside `target/dev/`, which is gitignored.

## `fake-daemon.py` — did the GUI answer, and with what?

Pretends to be `netshieldd` on a unix socket. No root, no nftables, no packets. It sends a
prompt (optionally a second one after the first decision, which is what proves the
hide→show cycle) and prints every frame it receives as `-> …` and every frame it sends as
`<- …`. The log **is** the assertion: `-> DECIDE {...}` with the expected action, duration
and scope is success.

It accepts several connections because the GUI opens two: one for receipt and events
(`hello`, `subscribe`) and a `Decider` for answers.

```bash
python3 dev/fake-daemon.py --socket target/dev/fake.sock --prompt-delay 3 --second-after 6 &
target/release/netshield-gui --socket target/dev/fake.sock
```

Success: `<- PROMPT id=7`, then within a few seconds `-> DECIDE {"prompt_id": 7, …}`, then
`<- PROMPT id=8 (second, …)` and a second decide. A `-> hello` with no `-> subscribe` means
the GUI never subscribed; no `-> DECIDE` at all means the alert was not answered (use
`click_at`, below). `--help` lists every option; `--app unknown --domain ""` renders the
unattributed alert, `--timeout` changes the advertised countdown.

## `decide-client.py` — answer a prompt from a script

Subscribes to a **real** daemon (or to `netns-run.sh`'s) and answers the first prompt. It
sends `hello` then `subscribe`, in that order: a client that skips `subscribe` silently
receives nothing, and one that subscribes only after the prompt opened also receives
nothing, because the daemon does not replay an already-open prompt. Subscribe first, then
create the traffic.

```bash
dev/decide-client.py --socket target/dev/netns/control.sock \
  --action allow --duration once --scope any
```

Success: `PROMPT id=… app=… domain=… dest=…`, `SENT DECIDE …`, then `PROMPT CLOSED`.
`REFUSING: the prompt has no learned domain` means `--scope domain` was asked of a prompt
the daemon cannot scope to a name; use `--scope address` or `--scope any`.

## `iconify` — put a window away the way the window manager understands

`wmctrl -b add,hidden` does not reliably iconify under Muffin, so this calls
`XIconifyWindow` directly. Build once:

```bash
gcc -O2 -o target/dev/iconify dev/iconify.c -lX11
target/dev/iconify 0x2400003
```

Success: `xprop -id 0x2400003 WM_STATE` reports `Iconic`. Exit 3 means the display could
not be opened, not that the iconify failed.

## `click_at` — click a prompt without a human

Synthetic click at window-relative coordinates. The delays between motion, press and
release are load-bearing: egui drops a zero-delay press+release.

```bash
gcc -O2 -o target/dev/click_at dev/click_at.c -lX11 -lXtst
# on a machine with only the libXtst runtime and no -dev symlink:
gcc -O2 -o target/dev/click_at dev/click_at.c -lX11 -Wl,-l:libXtst.so.6
target/dev/click_at 0x2400003 340 401   # Allow, attributed alert
```

Success: the alert closes and the daemon (or `fake-daemon.py`) logs a `DECIDE`. **The first
click on an unfocused window is eaten by focus-follows** — run it twice if nothing happens.
Button coordinates move with the layout: in a 480×440 alert the buttons sit at y≈401 when
the app is attributed with nothing queued, and y≈417 when an "N more waiting" row is shown.
An unknown app is one radio row shorter, so measure it with
`cargo test -p netshield-gui --bin netshield-gui tmp_measure_sections -- --nocapture`.

## `netns-run.sh` — the real daemon, no root, no host firewall

Starts `netshieldd` as mapped root inside a throwaway network namespace with a dummy
interface at `10.88.0.1/24`, using a generated config under `target/dev/netns/`
(`default_action: prompt`, `allowed_uid: 0`, `log_level: info`). It prints the daemon log
path and how to drive it, and on exit stops the daemon — which deletes the `inet netshield`
table — and destroys the namespace.

```bash
bash dev/netns-run.sh --demo      # subscribe, create a flow, print the decision, exit
bash dev/netns-run.sh             # hold it open and drive it by hand
```

Success: `daemon is up`, then a decision line in the log such as

```
INFO netshield_daemon::daemon: prompt 1 for unknown -> 10.88.0.2:80: allow, once, scope any connection by this app
```

and on exit `removed table inet netshield at shutdown`. `netns-run.sh` never installs a
table on the host: `unshare -rn` gives a private namespace, and the dummy interface exists
only inside it, so the `curl` that creates a flow is run there too (`echo go > …/trigger`).
It needs no root because `-r` maps your uid to root inside the namespace.

## `check-alert-minimised.sh` — the PR #5 regression test

Starts `fake-daemon.py` with a 9-second prompt delay, starts the GUI, iconifies the main
window, then asserts an alert appears within 20 s **while the main window stays `Iconic`**.

```bash
gcc -O2 -o target/dev/iconify dev/iconify.c -lX11
cargo build -p netshield-gui --release
bash dev/check-alert-minimised.sh
```

Success: `PASS: alert appeared while the main window stayed minimised`, exit 0. A `FAIL: no
alert within 20s` is the regression; `FAIL: the alert appeared but the main window was
restored` is the other half of it (the alert must not un-minimise the shell). Exit 1 with
`no X display` means it was run in `agent-sandbox`, which cannot map a window.
