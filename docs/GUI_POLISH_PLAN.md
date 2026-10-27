# GUI polish — overnight plan (2026-10-27)

Working document for the overnight GUI pass. If a later session is unsure what to do, **this file
wins** over anything recalled from conversation.

## The owner's instructions, verbatim

1. The connections UI will show the unique connection per process in a nice `CollapsingHeader` per
   process, this will be much easier to inspect the connections each app is doing. For reference
   check the little snitch screenshots.
   - a) For the `ScrollArea` use the `show_rows` method which only renders the visible part of the
     scroll area (perf).
   - b) The Rule column doesn't show a human readable reason, rather something like a hash — either
     fix it or remove it.
   - c) Optional: implement the traffic column as shown in little snitch.
   - d) Implement the activity column as shown in little snitch.
2. Use the widgets such as buttons, labels etc. from `egui-elements` instead, they already inherit
   the active theme visuals from the egui ctx, so there is no need to override its visuals.
3. In the Rules UI in the Application column only keep the process name, the process path will be
   shown on hover only.
4. Improve the left menu — currently too much y space between items (see the Zeus left menu for
   reference, `egui-lucide` is optional).
5. Fix any invalid characters where the default font doesn't show anything, for example in the left
   panel at the bottom you can use an `Indicator` from `egui-elegance`.
6. Operation mode should be a switch at the top panel, always easily accessible.
7. In the Rules UI we need an edit button where we can inspect and change the rules for a process.
8. Add system tray functionality, use the `egui-system-tray` skill. Create an icon using Python only
   (no AI generation); don't focus too much on the icon, it will be polished later. NetShield must
   minimise to tray on the close button too.

General: take screenshots while working to see how it actually looks, keep everything nice and
aligned so the GUI is easy to read and operate.

## Hard constraints for this run

- **No sudo, no user input.** Everything must work unprivileged: `cargo build`, `dev/fake-daemon.py`,
  `dev/iconify`, `x11grab`/`xwd`, `unshare -rn` for daemon work. The installed system service is the
  owner's; never touch it.
- **Kill every process you spawn.** `pkill -x netshield-gui` (never `pkill -f`, which self-matches).
  Check with `pgrep -x` afterwards. Leave no daemon, no GUI, no namespace behind.
- **Verify with pixels, not assertions.** The monitor is off; capture still works (see the
  `x11-gui-screenshot-verification` skill): `wmctrl -a`, `ffmpeg -f x11grab`, then `vision_analyze`
  on the crop. Restore `xset dpms force on` only if DPMS was forced off.
- **At most 4 PRs**, each independently mergeable into `master`, each with a truthful report.
- Style: 3-space indent, 100 columns, `rustfmt --edition 2024 --config-path rustfmt.toml --config
  skip_children=true <file>` for touched files only. **Never `cargo fmt`.**
- No behaviour changes outside the GUI surfaces listed here.

## PR breakdown

| # | Branch | Scope |
|---|---|---|
| 1 | `feat/gui-connections` | Connections page: grouped by process in `CollapsingHeader`s, virtualised with `show_rows`, human-readable Rule column, per-app Activity sparkline. Traffic column deferred (see below). |
| 2 | `feat/gui-shell` | `egui-elements` widgets at the call sites, compact left nav, glyph fixes (`Indicator`), mode switch in an always-visible top panel. |
| 3 | `feat/gui-rules` | Rules: application column shows the process name only (path on hover), an Edit button per rule opening an editor that can change and save the rule (`UpsertRule`). |
| 4 | `feat/system-tray` | `tray-icon` (Linux `ksni` feature only), Python-generated icon, hide-to-tray on window close, tray menu (Show / Rules / Quit). |

## Connections page — spec taken from the owner's Little Snitch screenshots

The reference is Little Snitch for Linux's Connections view. What it actually shows, transcribed:

- **Columns:** `CONNECTION | RULE | TRAFFIC | ACTIVITY`. `ACTIVITY` is the sort key and is a
  **relative-time pill**, not a graph: `now` (green pill), `50 s ago`, `2 min ago`, `18 min ago`
  (grey pill as it ages).
- **Group rows** are processes, collapsed by default: a right-pointing disclosure chevron, the process
  name, a rule status dot (green = allowed), the process's total traffic, and its activity pill.
- **Expanding** indents child rows under the process — `↳ bitwarden.com`, `↳ github.com`,
  `↳ IP Addresses` — each with its own rule dot, traffic and activity. When a process has too many
  children it shows a final **`6 more...`** row instead of all of them.
- **Selecting a row** fills a right-hand **CONNECTION DETAILS** panel: `Process: /usr/sbin/lightdm`,
  bytes received/sent, `Last allowed: …`, then a **MATCHING RULES** section.
- A traffic-over-time chart fills the bottom of the window.

### What NetShield can and cannot mirror

| Reference element | NetShield |
|---|---|
| Relative-time activity pill | **Yes** — derive from `Row.at`. This replaces the sparkline idea. |
| Rule status dot | **Yes** — green when the connection was allowed, red when denied. |
| `N more...` under a group | **Yes** — cap children per process and show the overflow count. |
| Right-hand details panel | **Yes** — process path (`exe`, currently dropped by `connlog::Row` — keep it), last seen, connections count, matching rule text. |
| TRAFFIC column (bytes) | **No** — see the byte-accounting limitation above. The column is omitted, not faked. |
| Traffic chart | **No** — same reason. |
| `↳` child glyph | Paint a small elbow with the painter instead; the bundled font is not guaranteed to have it. |



## Technical findings (already investigated — do not re-derive)

- **The Rule column shows a hash because the daemon sends a `RuleId`**, whose `Display` is a hex
  string. The GUI already fetches the full `Vec<Rule>` (`ListRules`), so the fix is to resolve
  `matched_rule` against that list at render time and print e.g. `allow brave → anywhere`. When the
  rule no longer exists (deleted), show `—`.
- **Traffic (bytes in/out) is not available in this design.** `ConnectionEvent` carries no byte
  counts, and NFQUEUE only sees the packets of a connection's *first* flow — the daemon never sees
  the payload packets afterwards, so it cannot count bytes per connection. Implementing the Little
  Snitch traffic column honestly would need nftables/quota accounting per rule as a separate daemon
  feature. **Decision: implement Activity now (derived from the log we already have) and state the
  traffic limitation in the PR** rather than faking a number.
- **Activity** can be derived with no new data: bucket each app's events into per-minute counts over
  a fixed window (e.g. 30 minutes) and draw a sparkline with `ui.painter()` — no plotting dependency.
- `egui-elements` 1.4.0 exports: `Badge`, `BadgeCorner`, `Button`, `ComboBox`, `Frame`, `Label`,
  `Modal`, `MultiLabel`, `Window` (+ `SecureTextEdit` under a feature). `Theme`/`ThemeKind` from
  `egui_elements`. `egui-elegance` 0.17 provides `Indicator`, `Card`, `Callout`, `Accordion`,
  `Checkbox`, `Collapsing`, `Avatar` among others.
- **`●` (U+25CF) is not in the bundled font** — that is the tofu in the left panel footer
  (`eframe` logs `No font has "●"`). Replace with an `egui_elegance::Indicator`, and audit the other
  non-ASCII glyphs used (`·`, `—`, `…`, `○`) for the same problem.
- Shell layout today: `Panel::left("nav")` (exact 180 px) + `CentralPanel`, plus a top panel used
  only for the offline banner. There is no always-visible toolbar; the mode switch lives on the
  Settings page (`ui::settings::show` → `Request::SetMode`).
- `eframe` 0.37 has the `logic(ctx)` / `ui(ui)` split the tray skill relies on, and
  `ViewportCommand::CancelClose` exists for intercepting the close button.
- Repo has `dev/` harnesses (PR #7, stacked on #6): `dev/fake-daemon.py` drives the GUI with no root
  and no filtering — use it for every visual check.

## Progress

- [ ] PR 1 — connections page
- [ ] PR 2 — shell: widgets, nav, glyphs, mode switch
- [ ] PR 3 — rules: hover path + edit
- [ ] PR 4 — system tray
- [ ] Final sweep: all gates green, no stray processes, every PR reported with evidence

## Verification recipes

```bash
# build + run against the fake daemon (no root, no filtering)
cargo build --release -p netshield-gui
python3 dev/fake-daemon.py --socket /tmp/ns.sock --duration 120 --prompt-delay 2 &
DISPLAY=:0 ./target/release/netshield-gui --socket /tmp/ns.sock &

# capture
WID=$(wmctrl -lG | awk '/NetShield/ && $5!=480 {print $1; exit}')
DISPLAY=:0 wmctrl -i -a "$WID"; sleep 0.4
ffmpeg -loglevel error -f x11grab -video_size 1920x1080 -i :0.0 -frames:v 1 -y /tmp/shot.png

# always clean up
pkill -x netshield-gui
```
