# Debugging NetShield

A runbook for someone who has never debugged a windowing application. Each section is a
question with the commands that answered it during the bugs in this project, the output to
expect, and what a deviation means. It is written against the code as of the PR #5 merge.

Two vocabulary notes, because they explain most confusing output:

- **`unknown`** is a process attribution result, not an error. The daemon could not map the
  packet's 4-tuple to a PID, so policy — not the daemon — decides that flow.
- **Prompt** is one question the daemon asks the GUI. A prompt is *open* from the moment the
  daemon broadcasts it until it is decided or times out. Only the **head** prompt is on
  screen; prompts behind it are queued and have no deadline yet.

## 1. Is the daemon even running the code I think it is?

Two reported bugs were a **stale binary**: the fix was merged, but the daemon in
`/usr/local/bin` was built before the merge. Merging is not deploying.

Search the installed binary for a literal string that only the new code contains. Pick
something from the change itself:

```bash
strings /usr/local/bin/netshieldd | grep -c "scope any connection by this app"
```

Expected: `1` (or more). `0` means the installed daemon predates the change. Then compare
the binary's timestamp with the merge commit:

```bash
ls -l /usr/local/bin/netshieldd
git log -1 --format='%h %ci %s' --merges
```

The binary's time must be **after** the merge commit's time. A binary older than the merge
is stale no matter what `systemctl status netshield` says. After installing, restart the
service and re-run the `strings` check; do not trust `install.sh`'s success line as proof
that the running process changed.

The same check works on the GUI, which has no `--version` difference to spot:

```bash
strings /usr/local/bin/netshield-gui | grep -c "NETSHIELD_LOG_TARGETS"
```

## 2. What did it decide?

The daemon logs to stderr, which systemd captures into the journal. Follow it while you
reproduce:

```bash
journalctl -u netshield -f
```

Four lines matter.

**The prompt.** Emitted when a prompt becomes visible:

```
INFO netshield_daemon::daemon: prompt 1 for curl -> 93.184.216.34:443 (1 packet(s) held, 0 queued)
```

The destination is `addr:port` here, not the name; the decision line below is the one that
uses the learned domain. `held` is how many kernel packet ids the prompt owns (a TCP SYN
retransmits, so this grows); `queued` is how many prompts are behind it. `unknown` in place
of `curl` is an attribution failure — go to §5.

**The decision.** One line per answered prompt, naming the action, the duration and the
scope. This is the line to quote when reporting a bug:

```
INFO netshield_daemon::daemon: prompt 1 for curl -> example.com: allow, until restart, scope any connection by this app
```

| Field | Values | Meaning |
|---|---|---|
| action | `allow`, `deny` | the verdict sent to the kernel |
| duration | `once`, `until restart`, `forever` | `once` = this flow only; `until restart` = in-memory rule; `forever` = persisted |
| scope | `any connection by this app`, `domain HOST`, `domain HOST (+subdomains)`, `this address` | what the rule covers |

**The timeout warning.** If nothing answers, the daemon denies and says so:

```
WARN netshield_daemon::daemon: prompt 1 timed out after 30s; denied curl from 192.168.1.5 to 93.184.216.34:443
```

A timeout means no client was subscribed, or the alert was never shown. It is not a policy
decision and must not be read as one.

**A decision that arrived too late.** If a click lands after the prompt expired:

```
WARN netshield_daemon::daemon: prompt 7 is no longer open; discarding the decision and creating no rule
```

The user believes a rule was created; the log proves it was not. Seeing this means the
client's clock and the daemon's disagree, or the GUI kept a stale alert — check §3.

## 3. What is the GUI doing?

The GUI is started by XDG autostart, so it has **no terminal** and its `log::` records go to
a state file, not to stdout. That file is:

```bash
tail -f ~/.local/state/netshield/gui.log
```

It is one line per record, rotated to `gui.log.1` at 1 MiB. A GUI that starts but never
appears in this file has not installed its logger; check `$XDG_STATE_HOME` and `$HOME` are
set for the session that launched it.

For a throwaway run, raise the level and send the log somewhere else:

```bash
NETSHIELD_LOG=debug NETSHIELD_LOG_FILE=/tmp/gui-debug.log \
  target/release/netshield-gui --socket target/dev/fake.sock
tail -f /tmp/gui-debug.log
```

`NETSHIELD_LOG` accepts `off error warn info debug trace` (default `info`). `debug` is the
level that shows the IPC handshake, every frame received, and why an alert was not shown.

By default `debug` **filters out dependency targets** — wgpu and naga otherwise produce
hundreds of kilobytes of adapter dumps that bury the handful of `netshield_gui` lines.
When the bug is in a dependency (a frame that never renders, a window that never maps),
lift the filter:

```bash
NETSHIELD_LOG=debug NETSHIELD_LOG_TARGETS=all NETSHIELD_LOG_FILE=/tmp/gui-all.log \
  target/release/netshield-gui
```

A GUI that cannot open its log prints `netshield-gui: cannot open the log file …` on stderr
and continues without logging; that absence is itself a finding.

## 4. Which windows exist, and are they mapped?

This is the single most instructive example in the project, because the obvious tool does
not answer the question you are asking.

`wmctrl -lG` lists only **mapped** windows. A window that was never created and a window
that exists but is hidden (unmapped, or iconified) are both absent from its output, so it
cannot tell them apart. Use the window tree instead:

```bash
xwininfo -root -tree | grep -i netshield
```

This lists every window, mapped or not. Then ask one window for its map state:

```bash
xwininfo -id 0x2400003 | grep 'Map State'
xprop -id 0x2400003 WM_STATE
```

`Map State: IsViewable` means on screen. `Map State: IsUnMapped` with `WM_STATE` showing
`Iconic` means the window exists and the window manager has minimised it. A window that is
absent from the tree was never created at all. Do not confuse the two `WM_STATE` spellings:
the alert itself is `Iconic` when hidden, while the *main* window is `Normal` when it has
been restored — which is exactly the third cause below.

### "No alert while minimised": three distinct causes, one discriminator

All three looked identical from the user's side — a prompt arrived, nothing appeared, and the
requesting process hung until the main window was restored. What separated them was **whether a
window existed at all, and whether it was mapped**.

| # | Cause | Window tree | Map state | What it meant |
|---|---|---|---|---|
| 1 | The alert viewport was registered lazily, only once a prompt existed | no second NetShield window, ever | n/a | `show_viewport_deferred` is a **no-op while the root viewport is iconified**: a viewport that does not already exist cannot be created in that state |
| 2 | The viewport was pre-created, but the show command went through the alert's own `Context` | alert window present at 480×440, never mapped | `IsUnMapped` for the whole life of the prompt | that context is published from the viewport's paint callback, and egui never runs the callback for an unmapped viewport — a circular dependency, so nothing was ever sent |
| 3 | Alert shown, but showing it restored or raised the main window | both windows mapped | alert `IsViewable`, main `WM_STATE: Normal` | the alert path was commanding the root viewport (`Minimized`, `Visible`, `Focus`), so the WM un-minimised the owner |

Note what does **not** cause this: `App::update()` does run while the window is iconified — the app
keeps polling `status`/`listrules` in that state, so "the event is never drained" is the wrong
hypothesis, and waking the UI with `ctx.request_repaint()` from the socket thread fixes nothing on
its own.

The fix for 1 and 2 is to **pre-create** the alert viewport at startup (hidden) and address its
commands **by id** — `ctx.send_viewport_cmd_to(alert_viewport_id(), ViewportCommand::Visible(true))`
— from the root context; viewport commands do not need the target viewport's own context. The fix
for 3 is to never send root-viewport commands while in floating mode.

That is why the regression test asserts *both* halves — an alert appeared **and** the main window
stayed `Iconic`:

```bash
bash dev/check-alert-minimised.sh   # needs a real X display, not agent-sandbox
```

Two layout facts that make the window lookup unambiguous: the main shell is 980 px wide and
the alert is 480 px (`alert::WIDTH`), so `wmctrl -lG | awk '$5 == 480'` selects the alert
and `$5 != 480` selects the shell.

## 5. Why is a connection `unknown`?

Attribution resolves the packet's 4-tuple to a PID through `/proc`: find the socket inode in
`/proc/net/tcp` (or `tcp6`, `udp`, `udp6`), then find that inode among `/proc/<pid>/fd/*`
links, restricted to the packet's uid. When any step fails the connection is `unknown` and
the daemon logs a one-line diagnostic at `debug`:

```
DEBUG netshield_daemon::proc: attribution failed: tcp 192.168.1.5:32768 -> 93.184.216.34:443 uid=Some(1000) table=tcp cand=1: no /proc fd link holds the inode
```

Read it field by field:

| Field | Meaning | What a bad value means |
|---|---|---|
| `tcp` / `udp` | the socket table searched (`no-table` = none for this protocol, e.g. ICMP) | `no-table` means v1 does not attribute that transport |
| `uid=Some(1000)` | the kernel attached the socket owner's uid to the packet | `uid=none`: no uid from the kernel; the scan cannot filter by owner and usually misses |
| `table=tcp` `cand=1` | which table matched, and candidate inodes found | `cand=0`: no socket row (socket closed, or address/port mismatch); `cand=1` plus a later failure: process gone |
| the reason after the colon | the exact step that failed | read it literally; it names the table, the fd scan or the budget |

After repeated misses the daemon escalates to a `warn` that names the class of flow:

```
WARN netshield_daemon::proc: attribution cannot map tcp flows destined to 93.184.216.34:443 (uid=Some(1000)) to a process: these flows stay unknown and policy decides them, not the daemon
```

A `uid=none` in that line is the resolver case: applications that query a public resolver
directly often close the UDP socket before the scan runs, and the kernel reports no uid. It
is a documented limit, not a regression; see `docs/ARCHITECTURE.md` §5.

Two further traps:

- **`Until restart` rules are memory-only.** Choosing *until restart* (wire value `session`)
  deliberately does **not** reach the rule store; the database staying unchanged is correct. Only
  `forever` persists. If you expected a rule on disk, check the decision line in §2 for the
  duration, not the store. The store is a redb database (`/etc/netshield/rules.db` by default), so
  it cannot be read with `cat`; ask the daemon (`listrules` on the control socket) instead of
  inspecting the file.
- **`stat` follows the link; `lstat` gives the descriptor's own time.** `/proc/<pid>/fd/*`
  entries are symlinks, and the two calls do not mean the same thing:

  | Call | Rust | On a live socket fd |
  |---|---|---|
  | `stat` | `fs::metadata` | follows `socket:[N]`; the **target's** time is `0` (epoch) or the boot time, depending on the socket kind — never the descriptor's, so there is no usable age |
  | `lstat` | `fs::symlink_metadata`, `DirEntry::metadata` | does not follow; the **descriptor's** own time |

  Measured on this machine:

  ```
  $ stat -c 'stat %Y'    /proc/$$/fd/2   # stat follows the link
  stat 0                                 # epoch: the target has no time
  $ stat -L -c 'statL %Y' /proc/$$/fd/2  # same, -L is explicit
  statL 0
  $ ls -l --time-style=full-iso /proc/$$/fd/2
  lrwx------ 1 cion cion 64 2026-10-27 16:34:02 … 2 -> socket:[21969718]
  ```

  The scan sorts descriptors newest-first by that age, so following the link sorts exactly
  the sockets it is looking for into the untimed bucket and inverts the intended order —
  that was the `fix(daemon): order /proc fd entries by link time` bug. In Rust, use
  `fs::symlink_metadata` or `DirEntry::metadata` (which calls `fstatat` with
  `AT_SYMLINK_NOFOLLOW`, i.e. `lstat`), never `fs::metadata`/`Path::metadata`.

## 6. Clicking a prompt without a human

`dev/click_at.c` injects an XTest click at window-relative coordinates. Build it and click
the Allow button. The window is 480 wide with two equal columns, so Deny is around x≈120 and
Allow around x≈340:

```bash
gcc -O2 -o target/dev/click_at dev/click_at.c -lX11 -lXtst
# on a machine with only the libXtst runtime and no -dev symlink:
gcc -O2 -o target/dev/click_at dev/click_at.c -lX11 -Wl,-l:libXtst.so.6
target/dev/click_at 0x2400003 340 401
```

Use the second form when the first fails with `ld: cannot find -lXtst`: it links the
runtime `libXtst.so.6` directly, which is all some machines install.

Three things make this work or not:

1. **The first click on an unfocused window is eaten by focus-follows.** The window manager
   spends the first click giving the window focus, so the button never sees it. Run the
   command twice, or focus the window first.
2. **The delays are required.** A press+release delivered with zero delay is dropped by
   egui; `click_at.c` spaces motion, press and release by 250/150/150 ms, and that timing
   is what makes the click land. Do not "simplify" it.
3. **The buttons move with the layout.** They are at the bottom of the alert, after the
   duration and scope sections. Measured with the layout dump below, in a 480×440 alert:

   | Alert shape | Buttons (`y`) | Click the middle at |
   |---|---|---|
   | attributed app, nothing queued | 382–420 | `y≈401` |
   | attributed app with "N more waiting" | 398–436 | `y≈417` |
   | unknown app | one radio row shorter (no domain/subdomains rows) | measure it |

   Do not trust a remembered coordinate; the sections above the buttons change it. Measure
   it:

   ```bash
   cargo test -p netshield-gui --bin netshield-gui tmp_measure_sections -- --nocapture
   ```

   The `buttons at … h=38` line gives the exact band for the current layout. The two
   `pending` variants it prints cover the attributed cases; an unknown app drops the domain
   radio and its subdomains checkbox, so its buttons sit roughly one radio row higher than
   the `pending = 0` figure.

Confirm the click landed by reading the answer, not the screen: `fake-daemon.py` prints
`-> DECIDE {...}`, and a real daemon prints the decision line from §2.
