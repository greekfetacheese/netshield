//! The Connections page: one collapsible row per application, its connections underneath,
//! and a detail pane for the selected row.
//!
//! The log is flattened into an owned [`Line`] vector and drawn with
//! [`egui::ScrollArea::show_rows`], which paints only the visible window of a uniform row
//! height. Collapsing a process therefore costs one rebuild of that vector, not a frame of
//! hidden widgets.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use egui::text::{LayoutJob, TextFormat, TextWrapping};
use egui::{Color32, FontId, Rect, Response, RichText, Sense, Shape, Stroke, Ui, pos2, vec2};
use netshield_core::rule::{Rule, RuleId};

use crate::connlog::{ConnectionLog, Row, clock};
use crate::ui::rules::{action_label, dest_label};

/// The fixed height of every line, group or connection; `show_rows` depends on it.
const LINE_HEIGHT: f32 = 24.0;

/// The column-header line above the list.
const HEADER_HEIGHT: f32 = 18.0;

/// Whitespace between two columns.
const COLUMN_GAP: f32 = 12.0;

/// How far a connection line is indented past the list's left edge: the child row's text
/// starts here, past the chevron gutter.
const INDENT: f32 = 18.0;

/// Where an application row's name starts, past the painted chevron: four pixels right of
/// [`INDENT`], so the parent's name sits just above the child text it owns. The verdict dot
/// is measured from the end of that `name count` text, not from a fixed column.
const APP_NAME_X: f32 = INDENT + 4.0;

/// Where the verdict dot's centre sits past the end of the `<name> <count>` text.
const DOT_GAP: f32 = 7.0;

/// The painted verdict dot's diameter; it stays a 3.5 radius circle.
const DOT_SIZE: f32 = 7.0;

/// Room the name galley leaves for the gap and the dot, so the dot cannot fall outside the
/// Connection column however long the name is.
const DOT_SPACE: f32 = 18.0;

/// Width of the chevron's click target at the start of a group line.
const CHEVRON_HIT: f32 = 22.0;

/// Right-hand padding inside a row.
const ROW_PAD: f32 = 8.0;

/// The Rule column: enough for `deny 140.82.121.6/32`.
const RULE_WIDTH: f32 = 190.0;

/// The Activity pill.
const ACTIVITY_WIDTH: f32 = 64.0;
const ACTIVITY_HEIGHT: f32 = 18.0;

/// The Connection column never shrinks below this.
const CONNECTION_MIN: f32 = 140.0;

/// The width of the right-hand detail pane while a row is selected.
const DETAIL_WIDTH: f32 = 260.0;

/// How many connection lines one group shows before the `N more…` line.
const MAX_CHILDREN: usize = 8;

/// A timestamp this recent reads `now`; anything older gets a relative label.
const NOW_SECS: u64 = 10;

/// Verdict colour for an allowed connection.
const ALLOWED: Color32 = Color32::from_rgb(0x6C, 0xC0, 0x7A);

/// Whole-row colour for a denied connection: muted red so a scan still reads as text.
const DENIED: Color32 = Color32::from_rgb(0xC0, 0x6A, 0x6A);

/// Text colour on the accent `now` pill.
const NOW_INK: Color32 = Color32::from_rgb(0x0E, 0x1B, 0x10);

/// Shown when the deciding rule is no longer in the daemon's list.
///
/// U+2014 is present in both bundled text fonts (Ubuntu-Light and Hack), so it is safe.
const DASH: &str = "—";

/// The sentence the pane uses when no rule decided a denied connection.
const PROMPT_RULE: &str = "no rule — decided by the prompt";

/// Which applications are expanded. Keyed by the row's `app` label.
///
/// The set holds the *open* apps, so a never-seen app is collapsed: the page starts with
/// every group folded and opens only what the user clicked.
#[derive(Default)]
pub struct Expanded(HashSet<String>);

impl Expanded {
   /// Flips one application between open and collapsed.
   fn toggle(&mut self, app: &str) {
      if !self.0.remove(app) {
         self.0.insert(app.to_owned());
      }
   }

   /// Whether the application is open, i.e. its connections are drawn.
   fn contains(&self, app: &str) -> bool {
      self.0.contains(app)
   }
}

/// Which applications are showing every connection rather than the first [`MAX_CHILDREN`].
///
/// Kept beside [`Expanded`]: a group only draws its children while open, and this set only
/// widens the cap for the ones the user clicked through.
#[derive(Default)]
pub struct ShowingAll(HashSet<String>);

impl ShowingAll {
   /// Opens one application's full history past the child cap.
   fn insert(&mut self, app: &str) {
      self.0.insert(app.to_owned());
   }

   /// Forgets that one application was showing all, so it falls back to the child cap.
   fn remove(&mut self, app: &str) {
      self.0.remove(app);
   }

   fn contains(&self, app: &str) -> bool {
      self.0.contains(app)
   }
}

/// What the detail pane shows. Owned by `App` beside [`Expanded`] and [`LinesCache`].
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub enum Selection {
   #[default]
   None,
   App(String),
   Conn {
      app: String,
      at: u64,
   },
}

/// Cached derived lines, rebuilt only when the log, the rules or the group state changes.
#[derive(Default)]
pub struct LinesCache {
   version: u64,
   rule_count: usize,
   expanded: HashSet<String>,
   showing_all: HashSet<String>,
   lines: Vec<Line>,
}

impl LinesCache {
   /// Rebuilds the lines when any input moved; an unchanged frame reuses the old vector.
   fn refresh(
      &mut self,
      log: &ConnectionLog,
      rules: &[Rule],
      expanded: &Expanded,
      showing_all: &ShowingAll,
   ) {
      let unchanged = self.version == log.version()
         && self.rule_count == rules.len()
         && self.expanded == expanded.0
         && self.showing_all == showing_all.0;
      if unchanged {
         return;
      }
      self.lines = build_lines(log, rules, expanded, showing_all);
      self.version = log.version();
      self.rule_count = rules.len();
      self.expanded = expanded.0.clone();
      self.showing_all = showing_all.0.clone();
   }
}

/// One line of the virtualised list. Owned and flat, because `show_rows` needs a uniform
/// index space rather than a tree of widgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
   /// One application: its name, connection count, newest rule and activity, and whether
   /// any of its connections was denied.
   Group {
      app: String,
      count: usize,
      last_at: u64,
      rule: String,
      denied: bool,
      exe: Option<String>,
   },
   /// One connection belonging to the group above it.
   Conn(Conn),
   /// The overflow row under a group with more than [`MAX_CHILDREN`] connections.
   More { remaining: usize },
}

/// One flattened connection row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conn {
   pub app: String,
   pub at: u64,
   pub dest: String,
   pub addr: String,
   pub proto: String,
   /// Whether `dest` came from a resolved domain rather than an address.
   pub domain: bool,
   pub allowed: bool,
   pub via_prompt: bool,
   pub candidate: Option<String>,
   /// `allow example.com`, `deny anywhere`, … or `—` when the rule is gone.
   pub rule: String,
   pub exe: Option<String>,
}

/// Draws the heading, the detail pane and the virtualised per-application list.
pub fn show(
   ui: &mut Ui,
   log: &ConnectionLog,
   rules: &[Rule],
   expanded: &mut Expanded,
   showing_all: &mut ShowingAll,
   cache: &mut LinesCache,
   selection: &mut Selection,
) {
   cache.refresh(log, rules, expanded, showing_all);

   let apps = cache.lines.iter().filter(|line| matches!(line, Line::Group { .. })).count();
   heading(ui, log, apps);

   if log.is_empty() {
      *selection = Selection::None;
      ui.label(
         RichText::new("No connections yet — the daemon reports them as they happen.").weak(),
      );
      return;
   }

   detail_pane(ui, &cache.lines, selection);

   let columns = Columns::new(ui.available_width());
   header_row(ui, &columns);
   let now = unix_now();
   // The activity pills read relative to the wall clock, so the page needs a frame even
   // when no connection arrives; one a second is enough for a label in whole seconds.
   ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));

   // `show_rows` reads the spacing before the closure runs, so zero it out here: the rows
   // are exactly `LINE_HEIGHT` tall and must not be pushed apart by the default gap.
   ui.spacing_mut().item_spacing.y = 0.0;
   egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
      ui,
      LINE_HEIGHT,
      cache.lines.len(),
      |ui, range| {
         for index in range {
            let line = &cache.lines[index];
            let (rect, response) = ui.allocate_exact_size(
               vec2(ui.available_width(), LINE_HEIGHT),
               Sense::click(),
            );
            match line {
               Line::Group { app, .. } => {
                  if response.clicked()
                     && let Some(pointer) = response.interact_pointer_pos()
                  {
                     click_group(
                        app,
                        rect,
                        pointer,
                        expanded,
                        showing_all,
                        selection,
                     );
                     // The cache still holds the pre-click lines; one more frame turns the
                     // toggle into the rows it opens or hides.
                     ui.ctx().request_repaint();
                  }
                  group_row(
                     ui,
                     &response,
                     &columns,
                     line,
                     expanded.contains(app),
                     *selection == Selection::App(app.clone()),
                     now,
                  );
               }
               Line::Conn(conn) => {
                  if response.clicked() {
                     *selection = Selection::Conn {
                        app: conn.app.clone(),
                        at: conn.at,
                     };
                     ui.ctx().request_repaint();
                  }
                  let selected = matches!(
                     selection,
                     Selection::Conn { app, at } if app == &conn.app && *at == conn.at
                  );
                  conn_row(ui, rect, &columns, conn, selected, now);
               }
               Line::More { remaining } => {
                  if response.clicked()
                     && let Some(more) = more_app(&cache.lines, index)
                  {
                     showing_all.insert(more);
                     ui.ctx().request_repaint();
                  }
                  more_row(ui, response, &columns, *remaining);
               }
            }
         }
      },
   );
}

/// The page heading: total, distinct apps and how many rows the log dropped.
fn heading(ui: &mut Ui, log: &ConnectionLog, apps: usize) {
   ui.horizontal(|ui| {
      ui.heading("Connections");
      ui.add_space(8.0);
      ui.label(
         RichText::new(format!(
            "{} connections · {} apps",
            log.len(),
            apps
         ))
         .weak(),
      );
      if log.dropped() > 0 {
         ui.label(RichText::new(format!("· {} dropped", log.dropped())).weak());
      }
   });
   ui.add_space(4.0);
}

/// Column widths and left edges, computed once per frame from the available width.
struct Columns {
   connection: f32,
   rule: f32,
   rule_x: f32,
   activity_x: f32,
}

impl Columns {
   fn new(width: f32) -> Self {
      let activity_x = (width - ROW_PAD - ACTIVITY_WIDTH).max(0.0);
      let rule_x = (activity_x - COLUMN_GAP - RULE_WIDTH).max(INDENT + CONNECTION_MIN);
      let rule = (activity_x - COLUMN_GAP - rule_x).max(0.0);
      let connection = (rule_x - COLUMN_GAP).max(0.0);
      Self {
         connection,
         rule,
         rule_x,
         activity_x,
      }
   }
}

/// Paints one row's cells, clipped to their columns and centred vertically.
///
/// Column offsets are relative to the row's left edge, so the header and the rows share
/// one geometry.
struct Cells<'a> {
   painter: &'a egui::Painter,
   rect: Rect,
}

impl Cells<'_> {
   fn text(&self, x: f32, width: f32, text: &str, font: &FontId, color: Color32, italics: bool) {
      let format = TextFormat {
         italics,
         ..TextFormat::simple(font.clone(), color)
      };
      let mut job = LayoutJob::single_section(text.to_owned(), format);
      job.wrap = TextWrapping::truncate_at_width(width.max(0.0));
      let galley = self.painter.layout_job(job);
      let y = self.rect.center().y - galley.size().y / 2.0;
      self.painter.galley(pos2(self.rect.left() + x, y), galley, color);
   }
}

/// The width a group line's `<name> <count>` galley may use, i.e. the Connection column
/// less the name's start and the room the verdict dot needs.
fn name_width_limit(columns: &Columns) -> f32 {
   (columns.connection - APP_NAME_X - DOT_SPACE).max(0.0)
}

/// The verdict dot's rectangle on a group line.
///
/// Measured from the row's left edge like every other cell, and from the end of the laid-out
/// `name count` text: a dot pinned to a column instead sits in the middle of the row and,
/// once the detail pane narrows the columns, on top of the application's own name.
fn dot_rect(row: Rect, name_width: f32) -> Rect {
   Rect::from_center_size(
      pos2(
         row.left() + APP_NAME_X + name_width + DOT_GAP,
         row.center().y,
      ),
      vec2(DOT_SIZE, DOT_SIZE),
   )
}

/// The `Connection Rule Activity` labels above the list.
fn header_row(ui: &mut Ui, columns: &Columns) {
   let (rect, _) = ui.allocate_exact_size(
      vec2(ui.available_width(), HEADER_HEIGHT),
      Sense::hover(),
   );
   let cells = Cells {
      painter: ui.painter(),
      rect,
   };
   let font = FontId::proportional(11.0);
   let color = ui.visuals().weak_text_color();
   cells.text(
      APP_NAME_X,
      (columns.connection - APP_NAME_X).max(0.0),
      "Connection",
      &font,
      color,
      false,
   );
   cells.text(
      columns.rule_x,
      (columns.rule).max(0.0),
      "Rule",
      &font,
      color,
      false,
   );
   let galley = cells.painter.layout_no_wrap("Activity".to_owned(), font, color);
   let x = columns.activity_x + ACTIVITY_WIDTH - galley.size().x;
   let y = rect.center().y - galley.size().y / 2.0;
   cells.painter.galley(pos2(rect.left() + x, y), galley, color);
}

/// One application row: chevron, name, count, rule dot and text, activity pill.
fn group_row(
   ui: &mut Ui,
   response: &Response,
   columns: &Columns,
   line: &Line,
   expanded: bool,
   selected: bool,
   now: u64,
) {
   let Line::Group {
      app,
      count,
      last_at,
      rule,
      denied,
      ..
   } = line
   else {
      return;
   };
   let rect = response.rect;
   let visuals = ui.visuals();
   let fill = if selected {
      visuals.selection.bg_fill
   } else if response.hovered() {
      visuals.widgets.hovered.weak_bg_fill
   } else {
      visuals.faint_bg_color
   };
   let painter = ui.painter();
   painter.rect_filled(rect, 0.0, fill);

   let weak = visuals.weak_text_color();
   let strong = visuals.strong_text_color();
   let center_y = rect.center().y;

   // The disclosure triangle is painted, not glyph-rendered: the bundled font is not
   // guaranteed to carry a chevron.
   let tip = pos2(rect.left() + 11.0, center_y);
   let points = if expanded {
      vec![
         pos2(tip.x - 4.5, tip.y - 3.0),
         pos2(tip.x + 4.5, tip.y - 3.0),
         pos2(tip.x, tip.y + 3.0),
      ]
   } else {
      vec![
         pos2(tip.x - 3.0, tip.y - 4.5),
         pos2(tip.x - 3.0, tip.y + 4.5),
         pos2(tip.x + 3.0, tip.y),
      ]
   };
   painter.add(Shape::convex_polygon(points, weak, Stroke::NONE));

   let body = FontId::proportional(13.0);
   let small = FontId::proportional(11.0);

   // The name is strong; the count trails it as a weak small label.
   let mut name = LayoutJob {
      wrap: TextWrapping::truncate_at_width(name_width_limit(columns)),
      ..LayoutJob::default()
   };
   name.append(app, 0.0, TextFormat::simple(body.clone(), strong));
   let count_label = if *count == 1 {
      "1 connection".to_owned()
   } else {
      count.to_string()
   };
   name.append(
      &count_label,
      8.0,
      TextFormat::simple(small.clone(), weak),
   );
   let galley = painter.layout_job(name);
   let name_width = galley.size().x;
   painter.galley(
      pos2(
         rect.left() + APP_NAME_X,
         center_y - galley.size().y / 2.0,
      ),
      galley,
      strong,
   );

   let dot_colour = if *denied { DENIED } else { ALLOWED };
   let dot = dot_rect(rect, name_width);
   painter.circle_filled(dot.center(), 3.5, dot_colour);
   let cells = Cells { painter, rect };
   cells.text(
      columns.rule_x,
      (columns.rule).max(0.0),
      rule,
      &body,
      visuals.text_color(),
      false,
   );

   activity_pill(painter, columns, rect, *last_at, now, visuals);
}

/// One connection row. The destination reads in the normal text colour, the protocol part
/// weak and the verdict strong in its verdict colour.
fn conn_row(ui: &mut Ui, rect: Rect, columns: &Columns, conn: &Conn, selected: bool, now: u64) {
   let visuals = ui.visuals();
   if selected {
      ui.painter().rect_filled(rect, 0.0, visuals.selection.bg_fill);
   }
   let base = visuals.text_color();
   let weak = visuals.weak_text_color();
   let verdict_colour = if conn.allowed { ALLOWED } else { DENIED };
   let painter = ui.painter();
   let body = FontId::proportional(13.0);

   let mut job = LayoutJob {
      wrap: TextWrapping::truncate_at_width((columns.connection - INDENT).max(0.0)),
      ..LayoutJob::default()
   };
   match &conn.candidate {
      // A candidate is a name the daemon guessed but did not resolve; the `?` keeps that
      // distinction visible while the row keeps the existing italic treatment.
      Some(candidate) => job.append(
         &format!("{candidate} ?"),
         0.0,
         TextFormat {
            italics: true,
            ..TextFormat::simple(body.clone(), weak)
         },
      ),
      // No resolved name: show the address with its port, as the reference does.
      None => job.append(
         if conn.domain { &conn.dest } else { &conn.addr },
         0.0,
         TextFormat::simple(body.clone(), base),
      ),
   }
   let detail = if conn.domain {
      format!(" · {} {}", conn.proto, port_of(&conn.addr))
   } else {
      format!(" · {}", conn.proto)
   };
   job.append(
      &detail,
      0.0,
      TextFormat::simple(body.clone(), weak),
   );
   let verdict = if conn.allowed { "ALLOWED" } else { "DENIED" };
   let verdict = if conn.via_prompt {
      format!("{verdict} (prompt)")
   } else {
      verdict.to_owned()
   };
   job.append(
      &format!(" · {verdict}"),
      0.0,
      TextFormat::simple(body, verdict_colour),
   );
   let galley = painter.layout_job(job);
   painter.galley(
      pos2(
         rect.left() + INDENT,
         rect.center().y - galley.size().y / 2.0,
      ),
      galley,
      base,
   );

   activity_pill(painter, columns, rect, conn.at, now, visuals);
}

/// The `N more…` line: weak and indented like the connection lines it stands in for. Like a
/// row it highlights under the pointer, and a click opens the rest of the group.
fn more_row(ui: &mut Ui, response: Response, columns: &Columns, remaining: usize) {
   let rect = response.rect;
   if response.hovered() {
      let fill = ui.visuals().widgets.hovered.weak_bg_fill;
      ui.painter().rect_filled(rect, 0.0, fill);
   }
   response.on_hover_cursor(egui::CursorIcon::PointingHand);
   let cells = Cells {
      painter: ui.painter(),
      rect,
   };
   cells.text(
      INDENT,
      (columns.connection - INDENT).max(0.0),
      &format!("{remaining} more…"),
      &FontId::proportional(13.0),
      ui.visuals().weak_text_color(),
      false,
   );
}

/// The app whose `N more…` row is at `index`: the nearest group above it, since the list is
/// flattened group-first.
fn more_app(lines: &[Line], index: usize) -> Option<&str> {
   lines[..index].iter().rev().find_map(|line| match line {
      Line::Group { app, .. } => Some(app.as_str()),
      _ => None,
   })
}

/// The Activity pill's rectangle for one row.
///
/// `columns` holds row-relative offsets, so the pill's centre is measured from `row.left()`;
/// using the raw offset would paint it at absolute screen x and land it over the Rule column.
fn pill_rect(row: Rect, columns: &Columns) -> Rect {
   Rect::from_center_size(
      pos2(
         row.left() + columns.activity_x + ACTIVITY_WIDTH / 2.0,
         row.center().y,
      ),
      vec2(ACTIVITY_WIDTH, ACTIVITY_HEIGHT),
   )
}

/// A right-aligned relative-time pill in the Activity column.
fn activity_pill(
   painter: &egui::Painter,
   columns: &Columns,
   rect: Rect,
   at: u64,
   now: u64,
   visuals: &egui::Visuals,
) {
   let label = relative(at, now);
   let fresh = label == "now";
   let pill = pill_rect(rect, columns);
   let (fill, ink) = if fresh {
      (ALLOWED, NOW_INK)
   } else {
      (visuals.faint_bg_color, visuals.weak_text_color())
   };
   painter.rect_filled(pill, ACTIVITY_HEIGHT / 2.0, fill);
   let galley = painter.layout_no_wrap(label, FontId::proportional(11.0), ink);
   painter.galley(pill.center() - galley.size() / 2.0, galley, ink);
}

/// `now` for a fresh event, then `9 s ago`, `1 min ago`, `2 h ago`.
fn relative(at: u64, now: u64) -> String {
   let age = now.saturating_sub(at);
   if age < NOW_SECS {
      "now".to_owned()
   } else if age < 60 {
      format!("{age} s ago")
   } else if age < 3_600 {
      format!("{} min ago", age / 60)
   } else {
      format!("{} h ago", age / 3_600)
   }
}

/// The port out of an `ip:port` / `[v6]:port` address.
fn port_of(addr: &str) -> &str {
   addr.rsplit_once(':').map_or("", |(_, port)| port)
}

/// Seconds since the unix epoch, for the relative activity labels.
fn unix_now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs())
}

/// Applies a click on a group line: the chevron toggles the group, the rest selects the
/// application. They are deliberately separate, as in the reference.
///
/// Collapsing also forgets the `showing all` entry, so reopening the group starts from
/// [`MAX_CHILDREN`] again rather than jumping straight to the full history.
fn click_group(
   app: &str,
   rect: Rect,
   pointer: egui::Pos2,
   expanded: &mut Expanded,
   showing_all: &mut ShowingAll,
   selection: &mut Selection,
) {
   let chevron = Rect::from_min_max(
      rect.left_top(),
      pos2(rect.left() + CHEVRON_HIT, rect.bottom()),
   );
   if chevron.contains(pointer) {
      expanded.toggle(app);
      if !expanded.contains(app) {
         showing_all.remove(app);
      }
   } else {
      *selection = Selection::App(app.to_owned());
   }
}

/// What the right-hand pane shows, resolved from the current line list.
struct Detail<'a> {
   process: Option<&'a str>,
   connections: usize,
   last_seen: u64,
   /// The selected connection's verdict; `None` when the selection is a whole app.
   verdict: Option<bool>,
   rule: &'a str,
   via_prompt: bool,
   denied: bool,
}

impl<'a> Detail<'a> {
   fn resolve(lines: &'a [Line], selection: &Selection) -> Option<Self> {
      match selection {
         Selection::None => None,
         Selection::App(app) => Self::app(lines, app),
         Selection::Conn { app, at } => lines
            .iter()
            .find_map(|line| match line {
               Line::Conn(conn) if &conn.app == app && conn.at == *at => Some(Self {
                  process: conn.exe.as_deref(),
                  connections: Self::app(lines, app).map_or(1, |detail| detail.connections),
                  last_seen: conn.at,
                  verdict: Some(conn.allowed),
                  rule: &conn.rule,
                  via_prompt: conn.via_prompt,
                  denied: !conn.allowed,
               }),
               _ => None,
            })
            // The connection may be collapsed or past the child cap; the app's own details
            // are still the honest answer, so the pane does not blink out of existence.
            .or_else(|| Self::app(lines, app)),
      }
   }

   /// The details of a whole application, as its group line knows them.
   fn app(lines: &'a [Line], app: &str) -> Option<Self> {
      lines.iter().find_map(|line| match line {
         Line::Group {
            app: name,
            count,
            last_at,
            rule,
            denied,
            exe,
         } if name == app => Some(Self {
            process: exe.as_deref(),
            connections: *count,
            last_seen: *last_at,
            verdict: None,
            rule,
            via_prompt: false,
            denied: *denied,
         }),
         _ => None,
      })
   }
}

/// The right-hand `CONNECTION DETAILS` pane, shown while a row is selected.
fn detail_pane(ui: &mut Ui, lines: &[Line], selection: &mut Selection) {
   let Some(detail) = Detail::resolve(lines, selection) else {
      *selection = Selection::None;
      return;
   };
   egui::Panel::right("connection_details")
      .exact_size(DETAIL_WIDTH)
      .resizable(false)
      .show(ui, |ui| {
         ui.add_space(8.0);
         ui.label(RichText::new("CONNECTION DETAILS").small().strong());
         ui.add_space(8.0);
         egui::Grid::new("connection_details_fields")
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
               ui.label(RichText::new("Process:").weak());
               ui.add(egui::Label::new(detail.process.unwrap_or("not identified")).truncate());
               ui.end_row();

               ui.label(RichText::new("Connections:").weak());
               ui.label(detail.connections.to_string());
               ui.end_row();

               ui.label(RichText::new("Last seen:").weak());
               ui.label(clock(detail.last_seen));
               ui.end_row();

               if let Some(allowed) = detail.verdict {
                  ui.label(RichText::new("Verdict:").weak());
                  let colour = if allowed { ALLOWED } else { DENIED };
                  let verdict = if allowed { "allowed" } else { "denied" };
                  ui.label(RichText::new(verdict).color(colour));
                  ui.end_row();
               }
            });

         ui.add_space(12.0);
         ui.label(RichText::new("MATCHING RULE").small().strong());
         ui.add_space(6.0);
         ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(12.0, 12.0), Sense::hover());
            let dot = if detail.denied { DENIED } else { ALLOWED };
            ui.painter().circle_filled(rect.center(), 3.5, dot);
            let text = if detail.rule == DASH && detail.via_prompt {
               PROMPT_RULE
            } else {
               detail.rule
            };
            ui.add(egui::Label::new(text).truncate());
         });
      });
}

/// Groups the log per app, newest first, and flattens the open groups into lines.
///
/// The log is scanned newest-first, so each group collects its rows in that order. Groups
/// are then sorted on their newest event rather than on arrival alone: `at` is what the
/// page promises to order by, and a burst can reach the log slightly out of order.
///
/// Only apps in `expanded` emit children; a group showing all skips the [`MAX_CHILDREN`]
/// cap and therefore has no `More` row.
fn build_lines(
   log: &ConnectionLog,
   rules: &[Rule],
   expanded: &Expanded,
   showing_all: &ShowingAll,
) -> Vec<Line> {
   #[cfg(test)]
   tests::bump_builds();

   let mut groups: Vec<(&str, Vec<&Row>)> = Vec::new();
   let mut index: HashMap<&str, usize> = HashMap::new();
   for row in log.rows().rev() {
      match index.get(row.app.as_str()).copied() {
         Some(slot) => groups[slot].1.push(row),
         None => {
            index.insert(row.app.as_str(), groups.len());
            groups.push((row.app.as_str(), vec![row]));
         }
      }
   }
   groups.sort_by_key(|(_, rows)| Reverse(rows.first().map_or(0, |row| row.at)));

   let mut lines = Vec::with_capacity(log.len() + groups.len());
   for (app, rows) in &groups {
      let newest = rows.first().copied();
      lines.push(Line::Group {
         app: (*app).to_owned(),
         count: rows.len(),
         last_at: newest.map_or(0, |row| row.at),
         rule: newest.map_or_else(
            || DASH.to_owned(),
            |row| rule_label(row.rule_id.as_ref(), rules),
         ),
         denied: rows.iter().any(|row| !row.allowed),
         exe: newest.and_then(|row| row.exe.clone()),
      });
      if !expanded.contains(app) {
         continue;
      }
      let shown = if showing_all.contains(app) {
         rows.len()
      } else {
         MAX_CHILDREN.min(rows.len())
      };
      for row in rows.iter().take(shown) {
         lines.push(Line::Conn(conn(row, rules)));
      }
      if rows.len() > shown {
         lines.push(Line::More {
            remaining: rows.len() - shown,
         });
      }
   }
   lines
}

/// Flattens one log row, resolving its rule id against the current rule list.
fn conn(row: &Row, rules: &[Rule]) -> Conn {
   Conn {
      app: row.app.clone(),
      at: row.at,
      dest: row.dest.clone(),
      addr: row.addr.clone(),
      proto: row.proto.clone(),
      domain: row.dest.parse::<std::net::IpAddr>().is_err(),
      allowed: row.allowed,
      via_prompt: row.via_prompt,
      candidate: row.candidate.clone(),
      rule: rule_label(row.rule_id.as_ref(), rules),
      exe: row.exe.clone(),
   }
}

/// `allow example.com`, `deny anywhere`, … or [`DASH`] when the rule is gone.
fn rule_label(id: Option<&RuleId>, rules: &[Rule]) -> String {
   let Some(id) = id else {
      return DASH.to_owned();
   };
   match rules.iter().find(|rule| &rule.id == id) {
      Some(rule) => format!(
         "{} {}",
         action_label(rule.action),
         dest_label(&rule.dest)
      ),
      None => DASH.to_owned(),
   }
}

#[cfg(test)]
mod tests {
   use std::cell::Cell;

   use netshield_core::connection::{Family, L4Proto};
   use netshield_core::ipc::{ConnectionEvent, ConnectionView};
   use netshield_core::rule::{Action, AppMatcher, DestMatcher, Duration};

   use super::*;

   thread_local! {
      /// Counts `build_lines` calls on this thread so the cache test can assert on real work.
      static BUILDS: Cell<usize> = const { Cell::new(0) };
   }

   /// Called from `build_lines` under `cfg(test)` so the cache can be observed, not guessed.
   pub(super) fn bump_builds() {
      BUILDS.with(|builds| builds.set(builds.get() + 1));
   }

   fn event(at: u64, app: &str, domain: &str) -> ConnectionEvent {
      ConnectionEvent {
         at,
         connection: ConnectionView {
            app_name: app.to_owned(),
            exe: None,
            pid: None,
            uid: None,
            family: Family::V4,
            proto: L4Proto::Tcp,
            remote_ip: "93.184.216.34".parse().unwrap(),
            remote_port: 443,
            local_port: 51_000,
            domain: Some(domain.to_owned()),
            domain_candidates: Vec::new(),
         },
         allowed: true,
         matched_rule: None,
         via_prompt: false,
      }
   }

   fn rule(dest: DestMatcher, action: Action) -> Rule {
      Rule {
         id: RuleId::new_unique(),
         enabled: true,
         app: AppMatcher::Any,
         dest,
         action,
         duration: Duration::Forever,
         note: None,
         created_at: 0,
         updated_at: 0,
         last_matched: None,
         hits: 0,
      }
   }

   fn log(events: &[(u64, &str, &str)]) -> ConnectionLog {
      let mut log = ConnectionLog::new(100);
      for (at, app, domain) in events {
         log.push(&event(*at, app, domain));
      }
      log
   }

   fn group(lines: &[Line], index: usize) -> (&str, usize, u64) {
      match &lines[index] {
         Line::Group {
            app,
            count,
            last_at,
            ..
         } => (app, *count, *last_at),
         other => panic!("expected a group at {index}, got {other:?}"),
      }
   }

   fn conn(lines: &[Line], index: usize) -> &Conn {
      match &lines[index] {
         Line::Conn(conn) => conn,
         other => panic!("expected a connection at {index}, got {other:?}"),
      }
   }

   fn builds() -> usize {
      BUILDS.with(Cell::get)
   }

   /// The expansion set for the named apps, i.e. the ones whose children should be drawn.
   fn expanded_set(apps: &[&str]) -> Expanded {
      let mut expanded = Expanded::default();
      for app in apps {
         expanded.toggle(app);
      }
      expanded
   }

   /// The `showing all` set for the named apps.
   fn showing_all_set(apps: &[&str]) -> ShowingAll {
      let mut showing_all = ShowingAll::default();
      for app in apps {
         showing_all.insert(app);
      }
      showing_all
   }

   #[test]
   fn the_activity_pill_sits_in_the_activity_column() {
      let columns = Columns::new(900.0);
      let row = Rect::from_min_size(pos2(100.0, 0.0), vec2(900.0, LINE_HEIGHT));

      let pill = pill_rect(row, &columns);

      // The offsets are row-relative: measure the pill from the row's left edge, not from
      // the screen's. This is the assertion the pre-fix code failed.
      assert!(
         (pill.left() - (row.left() + columns.activity_x)).abs() < 0.01,
         "the pill starts at the Activity column: {pill:?}"
      );
      assert!(
         (pill.right() - (row.right() - ROW_PAD)).abs() < 0.01,
         "the pill ends at the row's right padding: {pill:?}"
      );
      assert!(
         pill.left() >= row.left() && pill.right() <= row.right(),
         "the pill stays inside the row"
      );
      assert!(
         pill.top() >= row.top() && pill.bottom() <= row.bottom(),
         "the pill stays inside the row vertically"
      );
   }

   #[test]
   fn a_never_seen_app_is_collapsed() {
      let lines = build_lines(
         &log(&[(10, "firefox", "a.example")]),
         &[],
         &Expanded::default(),
         &ShowingAll::default(),
      );

      assert_eq!(lines.len(), 1, "only the group line is emitted");
      assert!(matches!(lines[0], Line::Group { .. }));
   }

   #[test]
   fn groups_are_ordered_by_their_newest_connection() {
      let log = log(&[
         (10, "firefox", "a.example"),
         (20, "curl", "b.example"),
         (30, "firefox", "c.example"),
      ]);

      let lines = build_lines(
         &log,
         &[],
         &expanded_set(&["firefox", "curl"]),
         &ShowingAll::default(),
      );

      assert_eq!(group(&lines, 0), ("firefox", 2, 30));
      assert_eq!(conn(&lines, 1).dest, "c.example");
      assert_eq!(conn(&lines, 2).dest, "a.example");
      assert_eq!(group(&lines, 3), ("curl", 1, 20));
      assert_eq!(lines.len(), 5);
   }

   #[test]
   fn an_expanded_app_shows_its_connections_until_collapsed() {
      let log = log(&[(20, "firefox", "a.example"), (10, "curl", "b.example")]);
      let mut expanded = expanded_set(&["firefox", "curl"]);
      let open = build_lines(&log, &[], &expanded, &ShowingAll::default());
      assert_eq!(open.len(), 4);

      expanded.toggle("firefox");
      let shut = build_lines(&log, &[], &expanded, &ShowingAll::default());
      assert_eq!(shut.len(), 3);
      assert_eq!(group(&shut, 0), ("firefox", 1, 20));
      assert_eq!(group(&shut, 1), ("curl", 1, 10));
      assert!(
         matches!(shut[2], Line::Conn(_)),
         "curl's own row follows"
      );

      expanded.toggle("firefox");
      let reopened = build_lines(&log, &[], &expanded, &ShowingAll::default());
      assert_eq!(reopened.len(), open.len());
      assert_eq!(conn(&reopened, 1).dest, "a.example");
   }

   #[test]
   fn relative_time_is_a_short_age() {
      let now = 1_000_000;
      assert_eq!(relative(now, now), "now");
      assert_eq!(relative(now - 9, now), "now");
      assert_eq!(relative(now - 59, now), "59 s ago");
      assert_eq!(relative(now - 60, now), "1 min ago");
      assert_eq!(relative(now - 59 * 60, now), "59 min ago");
      assert_eq!(relative(now - 2 * 3_600, now), "2 h ago");
   }

   #[test]
   fn the_group_rule_is_the_newest_connections_rule() {
      let allow = rule(DestMatcher::Any, Action::Allow);
      let deny = rule(
         DestMatcher::Domain {
            host: "example.com".to_owned(),
            subdomains: false,
         },
         Action::Deny,
      );
      let rules = vec![allow, deny];

      let mut older = event(10, "firefox", "example.com");
      older.allowed = false;
      older.matched_rule = Some(rules[1].id.clone());
      let mut newer = event(20, "firefox", "other.example");
      newer.matched_rule = Some(rules[0].id.clone());
      let mut history = ConnectionLog::new(8);
      history.push(&older);
      history.push(&newer);

      let lines = build_lines(
         &history,
         &rules,
         &expanded_set(&["firefox"]),
         &ShowingAll::default(),
      );
      let Line::Group { rule, denied, .. } = &lines[0] else {
         panic!("expected a group first");
      };
      assert_eq!(
         rule, "allow anywhere",
         "the newest row picks the rule"
      );
      assert!(
         *denied,
         "the older denied row still turns the dot red"
      );

      let clean = build_lines(
         &log(&[(30, "curl", "b.example")]),
         &rules,
         &expanded_set(&["curl"]),
         &ShowingAll::default(),
      );
      let Line::Group { denied, .. } = &clean[0] else {
         panic!("expected a group first");
      };
      assert!(
         !*denied,
         "an all-allowed group keeps its dot green"
      );
   }

   #[test]
   fn a_group_shows_eight_connections_then_the_remainder() {
      let eight: Vec<(u64, &str, &str)> = (0..8).map(|at| (at, "firefox", "a.example")).collect();
      let lines = build_lines(
         &log(&eight),
         &[],
         &expanded_set(&["firefox"]),
         &ShowingAll::default(),
      );
      assert_eq!(
         lines.len(),
         9,
         "eight connection lines, no overflow"
      );
      assert!(matches!(lines[8], Line::Conn(_)));

      let nine: Vec<(u64, &str, &str)> = (0..9).map(|at| (at, "firefox", "a.example")).collect();
      let lines = build_lines(
         &log(&nine),
         &[],
         &expanded_set(&["firefox"]),
         &ShowingAll::default(),
      );
      assert_eq!(
         lines.len(),
         10,
         "eight connection lines plus one overflow"
      );
      assert!(matches!(lines[9], Line::More { remaining: 1 }));

      let ten: Vec<(u64, &str, &str)> = (0..10).map(|at| (at, "firefox", "a.example")).collect();
      let lines = build_lines(
         &log(&ten),
         &[],
         &expanded_set(&["firefox"]),
         &ShowingAll::default(),
      );
      assert!(
         matches!(lines[9], Line::More { remaining: 2 }),
         "the remainder is the count past the cap"
      );
   }

   #[test]
   fn eleven_connections_are_capped_with_an_exact_remainder() {
      let events: Vec<(u64, &str, &str)> = (0..11).map(|at| (at, "firefox", "a.example")).collect();
      let lines = build_lines(
         &log(&events),
         &[],
         &expanded_set(&["firefox"]),
         &ShowingAll::default(),
      );

      // The group, `MAX_CHILDREN` connections, then one `More` line with the leftover.
      assert_eq!(lines.len(), 1 + MAX_CHILDREN + 1);
      assert!(matches!(lines[0], Line::Group { .. }));
      for (offset, line) in lines[1..=MAX_CHILDREN].iter().enumerate() {
         assert!(
            matches!(line, Line::Conn(_)),
            "child {offset} is a connection line"
         );
      }
      assert_eq!(
         lines[MAX_CHILDREN + 1],
         Line::More { remaining: 3 }
      );
      assert_eq!(
         more_app(&lines, MAX_CHILDREN + 1),
         Some("firefox"),
         "the More row resolves to the group above it"
      );
   }

   #[test]
   fn showing_all_reveals_every_connection_and_no_more_line() {
      let events: Vec<(u64, &str, &str)> = (0..11).map(|at| (at, "firefox", "a.example")).collect();
      let lines = build_lines(
         &log(&events),
         &[],
         &expanded_set(&["firefox"]),
         &showing_all_set(&["firefox"]),
      );

      assert_eq!(
         lines.len(),
         12,
         "the group plus all eleven connections"
      );
      assert!(
         !lines.iter().any(|line| matches!(line, Line::More { .. })),
         "a group showing all has no overflow row"
      );
      assert_eq!(
         lines.iter().filter(|line| matches!(line, Line::Conn(_))).count(),
         11
      );
   }

   #[test]
   fn clicking_a_group_selects_it_and_only_the_chevron_collapses() {
      let rect = Rect::from_min_size(pos2(0.0, 0.0), vec2(300.0, LINE_HEIGHT));
      let mut expanded = Expanded::default();
      let mut showing_all = ShowingAll::default();
      let mut selection = Selection::default();

      click_group(
         "firefox",
         rect,
         pos2(120.0, 12.0),
         &mut expanded,
         &mut showing_all,
         &mut selection,
      );
      assert_eq!(selection, Selection::App("firefox".to_owned()));
      assert!(
         !expanded.contains("firefox"),
         "clicking the name must not collapse the group"
      );

      click_group(
         "firefox",
         rect,
         pos2(6.0, 12.0),
         &mut expanded,
         &mut showing_all,
         &mut selection,
      );
      assert!(
         expanded.contains("firefox"),
         "the chevron toggles the group"
      );
      assert_eq!(
         selection,
         Selection::App("firefox".to_owned()),
         "the chevron leaves the selection alone"
      );
   }

   #[test]
   fn collapsing_a_group_forgets_that_it_was_showing_all() {
      let rect = Rect::from_min_size(pos2(0.0, 0.0), vec2(300.0, LINE_HEIGHT));
      let mut expanded = expanded_set(&["firefox"]);
      let mut showing_all = showing_all_set(&["firefox"]);
      let mut selection = Selection::default();

      // The chevron collapses the open group and drops its `showing all` entry.
      click_group(
         "firefox",
         rect,
         pos2(6.0, 12.0),
         &mut expanded,
         &mut showing_all,
         &mut selection,
      );
      assert!(!expanded.contains("firefox"));
      assert!(
         !showing_all.contains("firefox"),
         "reopening starts from MAX_CHILDREN again"
      );
   }

   #[test]
   fn the_rule_column_names_the_matching_rule() {
      let allow = rule(DestMatcher::Any, Action::Allow);
      let deny = rule(
         DestMatcher::Domain {
            host: "example.com".to_owned(),
            subdomains: false,
         },
         Action::Deny,
      );
      let rules = vec![allow, deny];

      assert_eq!(
         rule_label(Some(&rules[0].id), &rules),
         "allow anywhere"
      );
      assert_eq!(
         rule_label(Some(&rules[1].id), &rules),
         "deny only example.com"
      );
      assert_eq!(
         rule_label(Some(&RuleId::new_unique()), &rules),
         DASH
      );
      assert_eq!(rule_label(None, &rules), DASH);

      // And through the flattened row, which is what the detail pane reads.
      let mut matched = event(0, "firefox", "a.example");
      matched.matched_rule = Some(rules[0].id.clone());
      let mut log = ConnectionLog::new(8);
      log.push(&matched);
      let lines = build_lines(
         &log,
         &rules,
         &expanded_set(&["firefox"]),
         &ShowingAll::default(),
      );
      assert_eq!(conn(&lines, 1).rule, "allow anywhere");
   }

   #[test]
   fn the_cache_rebuilds_only_when_an_input_changes() {
      let mut log = log(&[(10, "firefox", "a.example")]);
      let mut expanded = Expanded::default();
      let mut showing_all = ShowingAll::default();
      let mut cache = LinesCache::default();

      let before = builds();
      cache.refresh(&log, &[], &expanded, &showing_all);
      assert_eq!(
         cache.lines.len(),
         1,
         "a never-seen app is collapsed"
      );
      assert_eq!(
         builds(),
         before + 1,
         "the first frame builds the lines"
      );

      cache.refresh(&log, &[], &expanded, &showing_all);
      assert_eq!(
         builds(),
         before + 1,
         "an unchanged frame reuses them"
      );

      log.push(&event(20, "curl", "b.example"));
      cache.refresh(&log, &[], &expanded, &showing_all);
      assert_eq!(builds(), before + 2, "a new row rebuilds");
      assert_eq!(cache.lines.len(), 2, "both groups stay collapsed");

      expanded.toggle("firefox");
      cache.refresh(&log, &[], &expanded, &showing_all);
      assert_eq!(builds(), before + 3, "expanding rebuilds");
      assert_eq!(cache.lines.len(), 3);

      showing_all.insert("firefox");
      cache.refresh(&log, &[], &expanded, &showing_all);
      assert_eq!(
         builds(),
         before + 4,
         "turning on showing all rebuilds the list"
      );

      let rules = vec![rule(DestMatcher::Any, Action::Allow)];
      cache.refresh(&log, &rules, &expanded, &showing_all);
      assert_eq!(builds(), before + 5, "a rule list rebuilds too");
   }

   #[test]
   fn the_verdict_dot_follows_the_count() {
      let row = Rect::from_min_size(pos2(100.0, 0.0), vec2(900.0, LINE_HEIGHT));

      let dot = dot_rect(row, 50.0);

      // Row-relative and text-relative: the pre-fix code painted at an absolute column x, so
      // the dot sat ~195px from its column and landed on the name once the columns shrank.
      assert_eq!(
         dot.center().x,
         100.0 + APP_NAME_X + 50.0 + DOT_GAP
      );
      assert!(
         dot.left() > 100.0 + APP_NAME_X,
         "the dot trails the name, it does not sit on it: {dot:?}"
      );
      assert_eq!(
         dot.center().y,
         row.center().y,
         "the dot is vertically centred"
      );
   }

   #[test]
   fn the_name_width_leaves_room_for_the_dot() {
      let columns = Columns::new(900.0);

      let limit = name_width_limit(&columns);

      assert!(
         limit + APP_NAME_X + DOT_SPACE == columns.connection,
         "the galley must stop short of the dot: limit {limit}, column {}",
         columns.connection
      );
      assert!(limit > 0.0, "a 900px row has room for a name");
   }
}
