//! The Connections page: one collapsible row per application, its connections underneath,
//! and a detail pane for the selected row.
//!
//! The log is flattened into an owned [`Line`] vector and drawn with
//! [`egui::ScrollArea::show_rows`], which paints only the visible window of a uniform row
//! height. Collapsing a process therefore costs one rebuild of that vector, not a frame of
//! hidden widgets.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use egui::text::{LayoutJob, TextFormat, TextWrapping};
use egui::{Color32, FontId, Rect, Response, RichText, Sense, Shape, Stroke, Ui, pos2, vec2};
use elegance::{Indicator, IndicatorState};
use netshield_core::rule::{Rule, RuleId};

use crate::connlog::{ConnectionLog, Row, clock};
use crate::ruleset::Ruleset;
use crate::ui::rules::{action_label, dest_label};
use crate::work::{Done, Job, Worker};

/// The fixed height of every line, group or connection; `show_rows` depends on it.
const LINE_HEIGHT: f32 = 24.0;

/// The column-header line above the list.
const HEADER_HEIGHT: f32 = 18.0;

/// Whitespace between the Rule and Activity columns; Activity holds short labels.
const COLUMN_GAP: f32 = 12.0;

/// Whitespace between the Connection and Rule columns: names and rule labels are both long,
/// so the boundary needs to read as a boundary rather than as another space inside a cell.
const CONNECTION_GAP: f32 = 32.0;

/// The chevron's tip on an application line: the centre of its click band.
const APP_CHEVRON_X: f32 = 11.0;

/// Where an application row's name starts, past the painted chevron: the click band's right
/// edge, so the name sits just above the destination text it owns. The verdict indicator is
/// measured from the end of that `name count` text, not from a fixed column.
const APP_NAME_X: f32 = 22.0;

/// The chevron's tip and the name's start on a destination line: one level in from an
/// application's, so the tree reads as a ladder.
const DEST_CHEVRON_X: f32 = 33.0;
const DEST_NAME_X: f32 = 44.0;

/// Where a connection line's text starts: under the destination it belongs to.
const CONN_TEXT_X: f32 = 56.0;

/// Where the verdict indicator's centre sits past the end of the `<name> <count>` text.
const DOT_GAP: f32 = 8.0;

/// The verdict indicator's diameter: the same 9 points the shell's own indicator uses.
const DOT_SIZE: f32 = 9.0;

/// Room the name galley leaves for the gap and the indicator, so it cannot fall outside the
/// Connection column however long the name is.
const DOT_SPACE: f32 = 22.0;

/// Width of the chevron's click band on a group line; it ends at the row's name.
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
const DETAIL_WIDTH: f32 = 208.0;

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

/// A node of the tree below the page: an application, or one of its destinations.
///
/// Both levels share one key type so the open and showing-all state stay two sets instead
/// of one per depth.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Node {
   App(String),
   Dest { app: String, dest: String },
}

impl Node {
   fn app(app: &str) -> Self {
      Self::App(app.to_owned())
   }

   fn dest(app: &str, dest: &str) -> Self {
      Self::Dest {
         app: app.to_owned(),
         dest: dest.to_owned(),
      }
   }
}

/// Which nodes are expanded.
///
/// The set holds the *open* nodes, so a never-seen app is collapsed: the page starts with
/// every group folded and opens only what the user clicked.
#[derive(Default)]
pub struct Expanded(HashSet<Node>);

impl Expanded {
   /// Flips one node between open and collapsed.
   fn toggle(&mut self, node: &Node) {
      if !self.0.remove(node) {
         self.0.insert(node.clone());
      }
   }

   /// Whether the node is open, i.e. its children are drawn.
   fn contains(&self, node: &Node) -> bool {
      self.0.contains(node)
   }
}

/// Which nodes are showing every child rather than the first [`MAX_CHILDREN`].
///
/// Kept beside [`Expanded`]: a node only draws its children while open, and this set only
/// widens the cap for the ones the user clicked through.
#[derive(Default)]
pub struct ShowingAll(HashSet<Node>);

impl ShowingAll {
   /// Opens one node's full history past the child cap.
   fn insert(&mut self, node: Node) {
      self.0.insert(node);
   }

   fn contains(&self, node: &Node) -> bool {
      self.0.contains(node)
   }

   /// Drops a node's showing-all entry, and an application's destinations' too: reopening a
   /// closed group starts from [`MAX_CHILDREN`] again rather than jumping to the full history.
   fn forget(&mut self, node: &Node) {
      self.0.retain(|open| match (open, node) {
         (Node::Dest { app, .. }, Node::App(closed)) => app != closed,
         _ => open != node,
      });
   }
}

/// What the detail pane shows. Owned by `App` beside [`Expanded`] and [`LinesCache`].
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub enum Selection {
   #[default]
   None,
   App(String),
   Dest {
      app: String,
      dest: String,
   },
   Conn {
      app: String,
      at: u64,
      addr: String,
      proto: String,
   },
}

/// Everything one rebuild reads, and therefore part of a rebuild's identity: opening a group
/// changes nothing about the log or the rules, and it still has to rebuild.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Inputs {
   log: u64,
   rules: u64,
   expanded: HashSet<Node>,
   showing_all: HashSet<Node>,
}

impl Inputs {
   /// Whether these are the inputs described by `self`.
   fn matches(
      &self,
      log: u64,
      rules: u64,
      expanded: &HashSet<Node>,
      showing_all: &HashSet<Node>,
   ) -> bool {
      self.log == log
         && self.rules == rules
         && &self.expanded == expanded
         && &self.showing_all == showing_all
   }
}

/// One rebuild's work: an owned snapshot, because the GUI thread keeps pushing events into the
/// log while the worker reads it.
#[derive(Debug)]
pub struct LinesJob {
   log: ConnectionLog,
   rules: Arc<Vec<Rule>>,
   inputs: Inputs,
}

/// The finished lines, tagged with the inputs they were derived from.
#[derive(Debug)]
pub struct LinesReady {
   lines: Vec<Line>,
   inputs: Inputs,
}

/// Builds one job's lines; the worker thread's entry point.
pub(crate) fn derive(job: &LinesJob) -> LinesReady {
   LinesReady {
      lines: build_lines(
         &job.log,
         &job.rules,
         &Expanded(job.inputs.expanded.clone()),
         &ShowingAll(job.inputs.showing_all.clone()),
      ),
      inputs: job.inputs.clone(),
   }
}

/// The owned snapshot one rebuild reads, taken from the live state at this instant.
fn take_job(log: &ConnectionLog, rules: &Ruleset, inputs: Inputs) -> LinesJob {
   LinesJob {
      log: log.snapshot(),
      rules: rules.shared(),
      inputs,
   }
}

/// What the cache does next for the inputs it was handed.
#[derive(Debug, PartialEq, Eq)]
enum Step {
   /// The installed lines, or the job in flight, already match these inputs.
   Current,
   /// The inputs moved and nothing is in flight.
   Submit,
   /// The inputs moved but a job is in flight; its result re-runs this decision.
   Wait,
}

/// Cached derived lines, rebuilt on the worker thread when the log, the rules or the group
/// state moves.
#[derive(Default)]
pub struct LinesCache {
   lines: Vec<Line>,
   /// The inputs the installed lines were built from.
   installed: Inputs,
   /// The inputs of the job in flight, if one is.
   in_flight: Option<Inputs>,
   /// `None` in tests, and when the thread could not be started: the cache then derives
   /// synchronously, so the page is correct rather than silently stale.
   worker: Option<Worker>,
}

impl LinesCache {
   /// A cache that derives on the worker thread, or on the GUI thread when it is `None`.
   pub fn new(worker: Option<Worker>) -> Self {
      Self {
         worker,
         ..Self::default()
      }
   }

   /// Drains a finished rebuild and, when the inputs moved again, queues the next one.
   fn refresh(
      &mut self,
      log: &ConnectionLog,
      rules: &Ruleset,
      expanded: &Expanded,
      showing_all: &ShowingAll,
   ) {
      // The result is taken first, so this frame paints what the worker finished. The poll
      // comes before the marker is cleared: a running job must stay marked as in flight.
      if let Some(worker) = &self.worker
         && let Some(Done::Lines(ready)) = worker.poll()
         && let Some(pending) = self.in_flight.take()
      {
         self.install(*ready, &pending);
      }
      if self.step(
         log.version(),
         rules.rev(),
         &expanded.0,
         &showing_all.0,
      ) != Step::Submit
      {
         return;
      }
      let inputs = Inputs {
         log: log.version(),
         rules: rules.rev(),
         expanded: expanded.0.clone(),
         showing_all: showing_all.0.clone(),
      };
      if let Some(worker) = &self.worker
         && worker.submit(Job::Lines(Box::new(take_job(
            log,
            rules,
            inputs.clone(),
         ))))
      {
         self.in_flight = Some(inputs);
         return;
      }
      // No thread, or it is gone: derive here rather than show a stale list. Readiness is worth
      // more than one frame's jank, and `Worker::spawn` has already logged the cause.
      let job = take_job(log, rules, inputs.clone());
      self.install(derive(&job), &inputs);
   }

   /// One job at a time: a second submission would rebuild a snapshot the first already made
   /// obsolete, and its result re-runs this decision, so the newest inputs still win.
   fn step(
      &self,
      log: u64,
      rules: u64,
      expanded: &HashSet<Node>,
      showing_all: &HashSet<Node>,
   ) -> Step {
      if let Some(in_flight) = &self.in_flight {
         return if in_flight.matches(log, rules, expanded, showing_all) {
            Step::Current
         } else {
            Step::Wait
         };
      }
      if self.installed.matches(log, rules, expanded, showing_all) {
         Step::Current
      } else {
         Step::Submit
      }
   }

   /// Installs a result only when it belongs to the job being waited for: a superseded one must
   /// not replace newer lines.
   fn install(&mut self, ready: LinesReady, pending: &Inputs) {
      if &ready.inputs != pending {
         return;
      }
      self.lines = ready.lines;
      self.installed = ready.inputs;
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
   /// One destination of the application above it: the resolved name, else the address, with
   /// the count, newest rule and activity of the connections it groups.
   Dest {
      app: String,
      dest: String,
      count: usize,
      last_at: u64,
      rule: String,
      denied: bool,
      exe: Option<String>,
   },
   /// One connection belonging to the destination above it.
   Conn(Conn),
   /// The overflow row under an app or a destination with more than [`MAX_CHILDREN`] children;
   /// `node` is what a click opens.
   More { remaining: usize, node: Node },
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
   /// How many identical flows this row stands for: `1` for a single connection, `N` when `N`
   /// flows shared the same endpoint, protocol and verdict.
   pub repeat: usize,
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
   rules: &Ruleset,
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
                  let node = Node::app(app);
                  if response.clicked()
                     && let Some(pointer) = response.interact_pointer_pos()
                  {
                     click_node(
                        node.clone(),
                        rect,
                        pointer,
                        APP_NAME_X,
                        expanded,
                        showing_all,
                        selection,
                     );
                     // The cache still holds the pre-click lines; one more frame turns the
                     // toggle into the rows it opens or hides.
                     ui.ctx().request_repaint();
                  }
                  app_row(
                     ui,
                     &response,
                     &columns,
                     line,
                     expanded.contains(&node),
                     *selection == Selection::App(app.clone()),
                     now,
                  );
               }
               Line::Dest { app, dest, .. } => {
                  let node = Node::dest(app, dest);
                  if response.clicked()
                     && let Some(pointer) = response.interact_pointer_pos()
                  {
                     click_node(
                        node.clone(),
                        rect,
                        pointer,
                        DEST_NAME_X,
                        expanded,
                        showing_all,
                        selection,
                     );
                     ui.ctx().request_repaint();
                  }
                  dest_row(
                     ui,
                     &response,
                     &columns,
                     line,
                     expanded.contains(&node),
                     *selection
                        == Selection::Dest {
                           app: app.clone(),
                           dest: dest.clone(),
                        },
                     now,
                  );
               }
               Line::Conn(conn) => {
                  if response.clicked() {
                     *selection = Selection::Conn {
                        app: conn.app.clone(),
                        at: conn.at,
                        addr: conn.addr.clone(),
                        proto: conn.proto.clone(),
                     };
                     ui.ctx().request_repaint();
                  }
                  let selected = matches!(
                     selection,
                     Selection::Conn { app, at, addr, proto }
                        if app == &conn.app
                           && *at == conn.at
                           && addr == &conn.addr
                           && proto == &conn.proto
                  );
                  conn_row(ui, &response, &columns, conn, selected, now);
               }
               Line::More { remaining, node } => {
                  if response.clicked() {
                     showing_all.insert(node.clone());
                     ui.ctx().request_repaint();
                  }
                  more_row(
                     ui,
                     response,
                     &columns,
                     *remaining,
                     more_row_x(node),
                  );
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
      let rule_x = (activity_x - COLUMN_GAP - RULE_WIDTH).max(CONN_TEXT_X + CONNECTION_MIN);
      let rule = (activity_x - COLUMN_GAP - rule_x).max(0.0);
      let connection = (rule_x - CONNECTION_GAP).max(0.0);
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
/// less the name's start and the room the verdict indicator needs.
fn name_width_limit(columns: &Columns, name_x: f32) -> f32 {
   (columns.connection - name_x - DOT_SPACE).max(0.0)
}

/// Shows `text` while `response` is hovered, but only when it did not fit in `width`.
///
/// Every column truncates with an ellipsis, so the full value has to live somewhere: the
/// hint is drawn only when the row is hovered *and* the text is genuinely clipped, which
/// keeps a value that fits from nagging the pointer.
fn truncation_hint(
   response: &Response,
   painter: &egui::Painter,
   width: f32,
   text: &str,
   font: &FontId,
) {
   if !response.hovered() {
      return;
   }
   let needed = painter.layout_no_wrap(text.to_owned(), font.clone(), Color32::WHITE).size().x;
   if needed > width {
      response.clone().on_hover_text(text.to_owned());
   }
}

/// The verdict indicator's rectangle on a group line.
///
/// Measured from the row's left edge like every other cell, and from the end of the laid-out
/// `name count` text; `center_y` is the *count label's* centre, not the row's, because the
/// label is a smaller font sharing the name's baseline and therefore sits lower.
fn indicator_rect(row: Rect, name_x: f32, name_width: f32, center_y: f32) -> Rect {
   Rect::from_center_size(
      pos2(
         row.left() + name_x + name_width + DOT_GAP,
         center_y,
      ),
      vec2(DOT_SIZE, DOT_SIZE),
   )
}

/// The centre of a glyph's own box: its ascent above the baseline, its descent below.
fn glyph_center_y(baseline: f32, ascent: f32, height: f32) -> f32 {
   baseline - ascent + height / 2.0
}

/// The screen-space centre of a group line's trailing count label.
///
/// The trailing glyph carries the small font's own metrics — `pos.y` is its baseline, and
/// `font_ascent` / `font_height` give its box — so the light can sit on the label's line.
/// Falls back to the galley's own centre for an empty or fully truncated line.
fn count_center_y(galley: &egui::Galley, text_top: f32) -> f32 {
   let centre = text_top + galley.size().y / 2.0;
   let Some(row) = galley.rows.first() else {
      return centre;
   };
   let Some(glyph) = row.row.glyphs.last() else {
      return centre;
   };
   glyph_center_y(
      text_top + row.pos.y + glyph.pos.y,
      glyph.font_ascent,
      glyph.font_height,
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

/// What a group line says, and where: an application's row and a destination's row differ
/// only in indent, colour and font.
struct GroupLine<'a> {
   name: &'a str,
   count: usize,
   rule: &'a str,
   denied: bool,
   last_at: u64,
   chevron_x: f32,
   name_x: f32,
   name_colour: Color32,
   name_font: FontId,
}

/// One application row: strong text at the top of its tree.
fn app_row(
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
   group_row(
      ui,
      response,
      columns,
      &GroupLine {
         name: app,
         count: *count,
         rule,
         denied: *denied,
         last_at: *last_at,
         chevron_x: APP_CHEVRON_X,
         name_x: APP_NAME_X,
         name_colour: ui.visuals().strong_text_color(),
         name_font: FontId::proportional(13.0),
      },
      expanded,
      selected,
      now,
   );
}

/// One destination row: the same cells as its application, one indent in and quieter.
fn dest_row(
   ui: &mut Ui,
   response: &Response,
   columns: &Columns,
   line: &Line,
   expanded: bool,
   selected: bool,
   now: u64,
) {
   let Line::Dest {
      dest,
      count,
      last_at,
      rule,
      denied,
      ..
   } = line
   else {
      return;
   };
   group_row(
      ui,
      response,
      columns,
      &GroupLine {
         name: dest,
         count: *count,
         rule,
         denied: *denied,
         last_at: *last_at,
         chevron_x: DEST_CHEVRON_X,
         name_x: DEST_NAME_X,
         name_colour: ui.visuals().text_color(),
         name_font: FontId::proportional(13.0),
      },
      expanded,
      selected,
      now,
   );
}

/// Paints a group line's cells: chevron, `name count`, verdict indicator, rule and activity
/// pill.
fn group_row(
   ui: &mut Ui,
   response: &Response,
   columns: &Columns,
   line: &GroupLine<'_>,
   expanded: bool,
   selected: bool,
   now: u64,
) {
   let rect = response.rect;
   let visuals = ui.visuals().clone();
   let fill = if selected {
      visuals.selection.bg_fill
   } else if response.hovered() {
      visuals.widgets.hovered.weak_bg_fill
   } else {
      visuals.faint_bg_color
   };
   let painter = ui.painter().clone();
   painter.rect_filled(rect, 0.0, fill);

   let weak = visuals.weak_text_color();
   let center_y = rect.center().y;

   // The disclosure triangle is painted, not glyph-rendered: the bundled font is not
   // guaranteed to carry a chevron.
   let tip = pos2(rect.left() + line.chevron_x, center_y);
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

   // The name is the row's own weight; the count trails it as a weak small label.
   let name_limit = name_width_limit(columns, line.name_x);
   let mut name = LayoutJob {
      wrap: TextWrapping::truncate_at_width(name_limit),
      ..LayoutJob::default()
   };
   name.append(
      line.name,
      0.0,
      TextFormat::simple(line.name_font.clone(), line.name_colour),
   );
   let count = count_label(line.count);
   name.append(
      &count,
      8.0,
      TextFormat::simple(small.clone(), weak),
   );
   let galley = painter.layout_job(name);
   let name_width = galley.size().x;
   let text_top = center_y - galley.size().y / 2.0;
   painter.galley(
      pos2(rect.left() + line.name_x, text_top),
      galley.clone(),
      line.name_colour,
   );
   truncation_hint(
      response,
      &painter,
      name_limit,
      &format!("{} {}", line.name, count),
      &line.name_font,
   );

   let indicator = indicator_rect(
      rect,
      line.name_x,
      name_width,
      count_center_y(&galley, text_top),
   );
   let state = if line.denied {
      IndicatorState::Off
   } else {
      IndicatorState::On
   };
   // A child ui, not `ui.put`: placing a widget with `put` moves the row's own cursor to
   // the widget's bottom, so every following row would start inside this one and the list
   // would lose its `LINE_HEIGHT` pitch.
   let mut light = ui.new_child(egui::UiBuilder::new().max_rect(indicator));
   light.add(Indicator::new(state).size(DOT_SIZE));
   let cells = Cells {
      painter: &painter,
      rect,
   };
   let rule_width = (columns.rule).max(0.0);
   cells.text(
      columns.rule_x,
      rule_width,
      line.rule,
      &body,
      visuals.text_color(),
      false,
   );
   truncation_hint(response, &painter, rule_width, line.rule, &body);

   activity_pill(
      &painter,
      columns,
      rect,
      line.last_at,
      now,
      &visuals,
   );
}

/// One connection row. The endpoint reads in the normal text colour, the protocol part weak
/// and the verdict strong in its verdict colour.
///
/// The destination line above already names the host, so the row starts at `addr:port`; the
/// first `domain_candidates` name stays on [`Conn`] for a later tooltip.
fn conn_row(
   ui: &mut Ui,
   response: &Response,
   columns: &Columns,
   conn: &Conn,
   selected: bool,
   now: u64,
) {
   let rect = response.rect;
   let visuals = ui.visuals();
   if selected {
      ui.painter().rect_filled(rect, 0.0, visuals.selection.bg_fill);
   }
   let base = visuals.text_color();
   let weak = visuals.weak_text_color();
   let verdict_colour = if conn.allowed { ALLOWED } else { DENIED };
   let painter = ui.painter();
   let body = FontId::proportional(13.0);

   let width = (columns.connection - CONN_TEXT_X).max(0.0);
   let mut job = LayoutJob {
      wrap: TextWrapping::truncate_at_width(width),
      ..LayoutJob::default()
   };
   job.append(
      &conn.addr,
      0.0,
      TextFormat::simple(body.clone(), base),
   );
   job.append(
      &format!(" · {}", conn.proto),
      0.0,
      TextFormat::simple(body.clone(), weak),
   );
   let verdict = verdict_label(conn);
   job.append(
      &format!(" · {verdict}"),
      0.0,
      TextFormat::simple(body.clone(), verdict_colour),
   );
   if conn.repeat > 1 {
      job.append(
         &format!(" ×{}", conn.repeat),
         0.0,
         TextFormat::simple(body.clone(), weak),
      );
   }
   let galley = painter.layout_job(job);
   painter.galley(
      pos2(
         rect.left() + CONN_TEXT_X,
         rect.center().y - galley.size().y / 2.0,
      ),
      galley,
      base,
   );
   truncation_hint(
      response,
      painter,
      width,
      &conn_line_text(conn),
      &body,
   );

   activity_pill(painter, columns, rect, conn.at, now, visuals);
}

/// Where an `N more…` row sits: level with the children it stands in for, so a hidden
/// destination's marker lines up with the destinations and a hidden connection's with the
/// connections.
fn more_row_x(node: &Node) -> f32 {
   match node {
      Node::App(_) => DEST_NAME_X,
      Node::Dest { .. } => CONN_TEXT_X,
   }
}

/// The `N more…` line: weak and indented like the child lines it stands in for. Like a row
/// it highlights under the pointer, and a click opens the rest of its node.
fn more_row(ui: &mut Ui, response: Response, columns: &Columns, remaining: usize, name_x: f32) {
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
      name_x,
      (columns.connection - name_x).max(0.0),
      &format!("{remaining} more…"),
      &FontId::proportional(13.0),
      ui.visuals().weak_text_color(),
      false,
   );
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

/// Seconds since the unix epoch, for the relative activity labels.
fn unix_now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs())
}

/// Applies a click on a group line: the chevron band toggles the node, the rest selects it.
///
/// Collapsing also forgets the `showing all` entry, so reopening the group starts from
/// [`MAX_CHILDREN`] again rather than jumping straight to the full history.
fn click_node(
   node: Node,
   rect: Rect,
   pointer: egui::Pos2,
   name_x: f32,
   expanded: &mut Expanded,
   showing_all: &mut ShowingAll,
   selection: &mut Selection,
) {
   let chevron = Rect::from_min_max(
      pos2(rect.left() + name_x - CHEVRON_HIT, rect.top()),
      pos2(rect.left() + name_x, rect.bottom()),
   );
   if chevron.contains(pointer) {
      expanded.toggle(&node);
      if !expanded.contains(&node) {
         showing_all.forget(&node);
      }
   } else {
      *selection = match &node {
         Node::App(app) => Selection::App(app.clone()),
         Node::Dest { app, dest } => Selection::Dest {
            app: app.clone(),
            dest: dest.clone(),
         },
      };
   }
}

/// What the right-hand pane shows, resolved from the current line list.
struct Detail<'a> {
   process: Option<&'a str>,
   /// The destination group the selection belongs to, when it has one.
   dest: Option<&'a str>,
   connections: usize,
   last_seen: u64,
   /// The selected connection's verdict; `None` when the selection is a whole node.
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
         Selection::Dest { app, dest } => lines
            .iter()
            .find_map(|line| match line {
               Line::Dest {
                  app: owner,
                  dest: host,
                  count,
                  last_at,
                  rule,
                  denied,
                  exe,
               } if owner == app && host == dest => Some(Self {
                  process: exe.as_deref(),
                  dest: Some(host),
                  connections: *count,
                  last_seen: *last_at,
                  verdict: None,
                  rule,
                  via_prompt: false,
                  denied: *denied,
               }),
               _ => None,
            })
            // The destination may be past the app's child cap; the app's own details are
            // still the honest answer, so the pane does not blink out of existence.
            .or_else(|| Self::app(lines, app)),
         Selection::Conn {
            app,
            at,
            addr,
            proto,
         } => lines
            .iter()
            .find_map(|line| match line {
               Line::Conn(conn)
                  if &conn.app == app
                     && conn.at == *at
                     && &conn.addr == addr
                     && &conn.proto == proto =>
               {
                  Some(Self {
                     process: conn.exe.as_deref(),
                     dest: Some(&conn.dest),
                     connections: Self::app(lines, app).map_or(1, |detail| detail.connections),
                     last_seen: conn.at,
                     verdict: Some(conn.allowed),
                     rule: &conn.rule,
                     via_prompt: conn.via_prompt,
                     denied: !conn.allowed,
                  })
               }
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
            dest: None,
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
         ui.add_space(6.0);
         ui.label(RichText::new("CONNECTION DETAILS").small().strong());
         ui.add_space(8.0);
         egui::Grid::new("connection_details_fields")
            .num_columns(2)
            .spacing([8.0, 3.0])
            .show(ui, |ui| {
               if let Some(dest) = detail.dest {
                  ui.label(RichText::new("Destination:").weak());
                  ui.add(egui::Label::new(dest).truncate()).on_hover_text(dest);
                  ui.end_row();
               }

               ui.label(RichText::new("Process:").weak());
               let process = detail.process.unwrap_or("not identified");
               ui.add(egui::Label::new(process).truncate()).on_hover_text(process);
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

         ui.add_space(10.0);
         ui.label(RichText::new("MATCHING RULE").small().strong());
         ui.add_space(4.0);
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

/// Groups the log per app and flattens the open groups into lines.
///
/// The order is entirely the list's own: applications alphabetical and case-insensitive,
/// destinations the same, and a destination's connections by address. Activity decides no
/// row's position, only the `at` a group reports, so a burst of flows cannot move a row the
/// user is about to click.
///
/// Only nodes in `expanded` emit children; a node showing all skips the [`MAX_CHILDREN`]
/// cap and therefore has no `More` row. The app's own `count` stays its total, the sum over
/// its destinations.
fn build_lines(
   log: &ConnectionLog,
   rules: &[Rule],
   expanded: &Expanded,
   showing_all: &ShowingAll,
) -> Vec<Line> {
   #[cfg(test)]
   tests::bump_builds();

   // One index per rebuild: `rule_label` used to scan the whole rule list for every line.
   let rule_index: HashMap<&RuleId, &Rule> = rules.iter().map(|rule| (&rule.id, rule)).collect();

   let mut groups: Vec<(&str, Vec<&Row>)> = Vec::new();
   let mut index: HashMap<&str, usize> = HashMap::new();
   for row in log.rows() {
      match index.get(row.app.as_str()).copied() {
         Some(slot) => groups[slot].1.push(row),
         None => {
            index.insert(row.app.as_str(), groups.len());
            groups.push((row.app.as_str(), vec![row]));
         }
      }
   }
   // Applications are alphabetical and case-insensitive, never ordered by activity: a row that
   // moves the moment a flow arrives cannot be clicked.
   groups.sort_by_cached_key(|(app, _)| app.to_ascii_lowercase());

   let mut lines = Vec::with_capacity(log.len() + groups.len());
   for (app, rows) in &groups {
      let newest = rows.iter().copied().max_by_key(|row| row.at);
      let app_node = Node::app(app);
      lines.push(Line::Group {
         app: (*app).to_owned(),
         count: rows.len(),
         last_at: newest.map_or(0, |row| row.at),
         rule: newest.map_or_else(
            || DASH.to_owned(),
            |row| rule_label(row.rule_id.as_ref(), &rule_index),
         ),
         denied: rows.iter().any(|row| !row.allowed),
         exe: newest.and_then(|row| row.exe.clone()),
      });
      if !expanded.contains(&app_node) {
         continue;
      }

      let dests = dest_groups(rows);
      let shown = if showing_all.contains(&app_node) {
         dests.len()
      } else {
         MAX_CHILDREN.min(dests.len())
      };
      for (dest, conns) in dests.iter().take(shown) {
         let newest = conns.iter().copied().max_by_key(|row| row.at);
         let dest_node = Node::dest(app, dest);
         lines.push(Line::Dest {
            app: (*app).to_owned(),
            dest: (*dest).to_owned(),
            count: conns.len(),
            last_at: newest.map_or(0, |row| row.at),
            rule: newest.map_or_else(
               || DASH.to_owned(),
               |row| rule_label(row.rule_id.as_ref(), &rule_index),
            ),
            denied: conns.iter().any(|row| !row.allowed),
            exe: newest.and_then(|row| row.exe.clone()),
         });
         if !expanded.contains(&dest_node) {
            continue;
         }
         let unique = unique_conns(conns);
         let shown_conns = if showing_all.contains(&dest_node) {
            unique.len()
         } else {
            MAX_CHILDREN.min(unique.len())
         };
         for (row, repeat) in unique.iter().take(shown_conns) {
            lines.push(Line::Conn(conn(row, *repeat, &rule_index)));
         }
         if unique.len() > shown_conns {
            lines.push(Line::More {
               remaining: unique.len() - shown_conns,
               node: dest_node,
            });
         }
      }
      if dests.len() > shown {
         lines.push(Line::More {
            remaining: dests.len() - shown,
            node: app_node,
         });
      }
   }
   lines
}

/// Splits one application's rows into destination groups, alphabetical and case-insensitive.
///
/// `Row::dest` is already "the resolved name, else the address", so the key needs no extra
/// resolution. The order is the destination's own, never its newest connection's: a peer that
/// appears must not push every other destination down a row.
fn dest_groups<'a>(rows: &[&'a Row]) -> Vec<(&'a str, Vec<&'a Row>)> {
   let mut groups: Vec<(&str, Vec<&Row>)> = Vec::new();
   let mut index: HashMap<&str, usize> = HashMap::new();
   for row in rows {
      match index.get(row.dest.as_str()).copied() {
         Some(slot) => groups[slot].1.push(row),
         None => {
            index.insert(row.dest.as_str(), groups.len());
            groups.push((row.dest.as_str(), vec![row]));
         }
      }
   }
   groups.sort_by_cached_key(|(dest, _)| dest.to_ascii_lowercase());
   groups
}

/// One destination's connections collapsed to unique flows, sorted by address then protocol.
///
/// A resolver or a browser opens the same `addr:port` flow dozens of times, and dozens of
/// identical rows bury the one that is new. Each entry is the newest row of its group plus how
/// many flows it stands for; the destination line keeps the raw total on its own count. The
/// representative is chosen by `at`, so this does not depend on the order it is handed.
fn unique_conns<'a>(conns: &[&'a Row]) -> Vec<(&'a Row, usize)> {
   let mut unique: Vec<(&'a Row, usize)> = Vec::new();
   let mut index: HashMap<(String, String, bool, bool), usize> = HashMap::new();
   for row in conns {
      let key = (
         row.addr.clone(),
         row.proto.clone(),
         row.allowed,
         row.via_prompt,
      );
      match index.get(&key).copied() {
         Some(slot) => {
            let (kept, repeat) = unique[slot];
            unique[slot] = (
               if row.at > kept.at { row } else { kept },
               repeat + 1,
            );
         }
         None => {
            index.insert(key, unique.len());
            unique.push((row, 1));
         }
      }
   }
   // Address, then protocol, then a denial before an allow: a stable sort is what makes the
   // rows stop moving as new flows arrive.
   unique.sort_by(|(left, _), (right, _)| {
      left
         .addr
         .cmp(&right.addr)
         .then_with(|| left.proto.cmp(&right.proto))
         .then_with(|| left.allowed.cmp(&right.allowed))
   });
   unique
}

/// Flattens one log row, resolving its rule id against the current rule list.
fn conn(row: &Row, repeat: usize, rules: &HashMap<&RuleId, &Rule>) -> Conn {
   Conn {
      app: row.app.clone(),
      at: row.at,
      dest: row.dest.clone(),
      addr: row.addr.clone(),
      proto: row.proto.clone(),
      domain: row.dest.parse::<std::net::IpAddr>().is_err(),
      allowed: row.allowed,
      repeat,
      via_prompt: row.via_prompt,
      candidate: row.candidate.clone(),
      rule: rule_label(row.rule_id.as_ref(), rules),
      exe: row.exe.clone(),
   }
}

/// `allow example.com`, `deny anywhere`, … or [`DASH`] when the rule is gone.
fn rule_label(id: Option<&RuleId>, rules: &HashMap<&RuleId, &Rule>) -> String {
   match id.and_then(|id| rules.get(id)) {
      Some(rule) => format!(
         "{} {}",
         action_label(rule.action),
         dest_label(&rule.dest)
      ),
      None => DASH.to_owned(),
   }
}

/// The trailing count on a group line.
fn count_label(count: usize) -> String {
   count.to_string()
}

/// One connection line's full text, untruncated: the endpoint, the protocol and the verdict.
fn conn_line_text(conn: &Conn) -> String {
   let mut text = format!(
      "{} · {} · {}",
      conn.addr,
      conn.proto,
      verdict_label(conn)
   );
   if conn.repeat > 1 {
      text.push_str(&format!(" ×{}", conn.repeat));
   }
   text
}

/// `ALLOWED`, `ALLOWED (prompt)`, `DENIED`, or `DENIED (prompt)`.
fn verdict_label(conn: &Conn) -> String {
   let verdict = if conn.allowed { "ALLOWED" } else { "DENIED" };
   if conn.via_prompt {
      format!("{verdict} (prompt)")
   } else {
      verdict.to_owned()
   }
}

#[cfg(test)]
mod tests {
   use std::cell::Cell;

   use netshield_core::connection::{Family, L4Proto};
   use netshield_core::ipc::{ConnectionEvent, ConnectionView};
   use netshield_core::rule::{Action, AppMatcher, DestMatcher, Duration};

   use super::*;
   use crate::ruleset::Ruleset;

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
      let mut log = ConnectionLog::new(100, 32);
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

   fn dest(lines: &[Line], index: usize) -> (&str, usize, u64) {
      match &lines[index] {
         Line::Dest {
            dest,
            count,
            last_at,
            ..
         } => (dest, *count, *last_at),
         other => panic!("expected a destination at {index}, got {other:?}"),
      }
   }

   /// The expansion set for the named nodes, i.e. the ones whose children should be drawn.
   fn expanded_set(nodes: &[Node]) -> Expanded {
      let mut expanded = Expanded::default();
      for node in nodes {
         expanded.toggle(node);
      }
      expanded
   }

   /// The `showing all` set for the named nodes.
   fn showing_all_set(nodes: &[Node]) -> ShowingAll {
      let mut showing_all = ShowingAll::default();
      for node in nodes {
         showing_all.insert(node.clone());
      }
      showing_all
   }

   #[test]
   fn the_activity_pill_is_positioned_from_the_row() {
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
   fn the_indicator_is_positioned_from_the_text() {
      let row = Rect::from_min_size(pos2(100.0, 0.0), vec2(900.0, LINE_HEIGHT));

      let indicator = indicator_rect(row, APP_NAME_X, 50.0, row.center().y + 1.5);

      // Row-relative and text-relative: the pre-fix code painted at an absolute column x.
      assert_eq!(
         indicator.center().x,
         100.0 + APP_NAME_X + 50.0 + DOT_GAP
      );
      assert_eq!(
         indicator.width(),
         DOT_SIZE,
         "the widget's own diameter is the rect's width"
      );
      assert!(
         indicator.center().y > row.center().y,
         "the caller's centre is honoured, not the row's"
      );
   }

   #[test]
   fn the_tree_is_grouped_ordered_and_collapsed_until_opened() {
      // A never-seen app is collapsed: only its Group line is emitted.
      let lines = build_lines(
         &log(&[(10, "firefox", "a.example")]),
         &[],
         &Expanded::default(),
         &ShowingAll::default(),
      );
      assert_eq!(lines.len(), 1, "only the group line is emitted");
      assert!(matches!(lines[0], Line::Group { .. }));

      // Apps are alphabetical whatever their activity: curl above firefox.
      let history = log(&[
         (10, "firefox", "a.example"),
         (20, "curl", "b.example"),
         (30, "firefox", "c.example"),
         (40, "firefox", "b.example"),
      ]);
      let lines = build_lines(
         &history,
         &[],
         &expanded_set(&[Node::app("firefox"), Node::app("curl")]),
         &ShowingAll::default(),
      );
      assert_eq!(group(&lines, 0), ("curl", 1, 20));
      assert_eq!(dest(&lines, 1), ("b.example", 1, 20));
      assert_eq!(group(&lines, 2), ("firefox", 3, 40));
      // Then firefox's own destinations, alphabetical: a, b, c.
      assert_eq!(dest(&lines, 3), ("a.example", 1, 10));
      assert_eq!(dest(&lines, 4), ("b.example", 1, 40));
      assert_eq!(dest(&lines, 5), ("c.example", 1, 30));
      assert_eq!(lines.len(), 6);

      // Destinations group under their app, and an open app on its own emits only Dest lines.
      let grouped = log(&[
         (10, "firefox", "a.example"),
         (20, "firefox", "a.example"),
         (30, "firefox", "b.example"),
      ]);
      let lines = build_lines(
         &grouped,
         &[],
         &expanded_set(&[Node::app("firefox")]),
         &ShowingAll::default(),
      );
      assert_eq!(
         lines.len(),
         3,
         "a closed app emits no connections"
      );
      assert_eq!(group(&lines, 0), ("firefox", 3, 30));
      assert_eq!(dest(&lines, 1), ("a.example", 2, 20));
      assert_eq!(dest(&lines, 2), ("b.example", 1, 30));
      assert!(matches!(lines[1], Line::Dest { .. }));
      assert!(matches!(lines[2], Line::Dest { .. }));

      // A closed destination paints no connection lines; an open one lists its rows, and its
      // identical flows collapse.
      let host = Node::dest("firefox", "a.example");
      let closed = build_lines(
         &grouped,
         &[],
         &expanded_set(&[Node::app("firefox")]),
         &ShowingAll::default(),
      );
      assert!(
         !closed.iter().any(|line| matches!(line, Line::Conn(_))),
         "a closed destination paints no connection lines"
      );
      let open = build_lines(
         &grouped,
         &[],
         &expanded_set(&[Node::app("firefox"), host]),
         &ShowingAll::default(),
      );
      assert_eq!(
         open.iter().filter(|line| matches!(line, Line::Conn(_))).count(),
         1,
         "only the open destination's rows are drawn, and its identical flows collapse"
      );
      let listed = conn(&open, 2);
      assert_eq!(listed.dest, "a.example");
      assert_eq!(
         listed.repeat, 2,
         "both of a.example's flows are counted"
      );

      // Re-collapsing hides the rows again.
      let log = log(&[(20, "firefox", "a.example"), (10, "curl", "b.example")]);
      let mut expanded = expanded_set(&[Node::app("firefox"), Node::app("curl")]);
      let open = build_lines(&log, &[], &expanded, &ShowingAll::default());
      assert_eq!(
         open.len(),
         4,
         "an expanded app shows its destinations"
      );
      assert_eq!(dest(&open, 1), ("b.example", 1, 10));
      assert_eq!(dest(&open, 3), ("a.example", 1, 20));

      expanded.toggle(&Node::dest("firefox", "a.example"));
      let opened = build_lines(&log, &[], &expanded, &ShowingAll::default());
      assert_eq!(
         opened.len(),
         5,
         "an expanded destination shows its connections"
      );
      assert_eq!(conn(&opened, 4).dest, "a.example");
      assert!(
         opened.iter().filter(|line| matches!(line, Line::Conn(_))).count() == 1,
         "curl's destination is still closed"
      );

      expanded.toggle(&Node::app("firefox"));
      let shut = build_lines(&log, &[], &expanded, &ShowingAll::default());
      assert_eq!(shut.len(), 3);
      assert_eq!(group(&shut, 0), ("curl", 1, 10));
      assert_eq!(dest(&shut, 1), ("b.example", 1, 10));
      assert_eq!(
         group(&shut, 2),
         ("firefox", 1, 20),
         "curl's destination follows its own group"
      );

      expanded.toggle(&Node::app("firefox"));
      let reopened = build_lines(&log, &[], &expanded, &ShowingAll::default());
      assert_eq!(reopened.len(), opened.len());
      assert_eq!(conn(&reopened, 4).dest, "a.example");
   }

   /// Every line's identity, so a reordering is visible as a changed list.
   fn identities(lines: &[Line]) -> Vec<String> {
      lines
         .iter()
         .map(|line| match line {
            Line::Group { app, .. } => format!("group {app}"),
            Line::Dest { dest, .. } => format!("dest {dest}"),
            Line::Conn(conn) => format!("conn {}", conn.addr),
            Line::More { remaining, .. } => format!("more {remaining}"),
         })
         .collect()
   }

   #[test]
   fn the_app_order_is_alphabetical_and_never_moves() {
      // Arrival order is deliberately not alphabetical, and the chattiest app speaks last.
      let mut history = log(&[
         (10, "spotify", "a.example"),
         (20, "curl", "b.example"),
         (30, "Brave", "c.example"),
         (40, "spotify", "b.example"),
      ]);
      let apps = history
         .rows()
         .map(|row| row.app.clone())
         .collect::<std::collections::BTreeSet<_>>();
      assert_eq!(
         apps.into_iter().collect::<Vec<_>>(),
         vec!["Brave".to_owned(), "curl".to_owned(), "spotify".to_owned()],
         "four flows over three apps"
      );

      let order = identities(&build_lines(
         &history,
         &[],
         &Expanded::default(),
         &ShowingAll::default(),
      ));
      assert_eq!(
         order,
         vec!["group Brave", "group curl", "group spotify"],
         "the case-insensitive alphabetical order is the drawn order"
      );

      // A burst of flows for the chattiest app changes its count, not the row order.
      for at in 50..56 {
         history.push(&event(at, "spotify", "d.example"));
      }
      assert_eq!(
         identities(&build_lines(
            &history,
            &[],
            &Expanded::default(),
            &ShowingAll::default()
         )),
         order,
         "no flow can move an application row"
      );
   }

   #[test]
   fn a_destination_lists_its_connections_by_address() {
      let mut third = event(10, "firefox", "a.example");
      third.connection.remote_ip = "203.0.113.30".parse().unwrap();
      let mut first = event(20, "firefox", "a.example");
      first.connection.remote_ip = "203.0.113.10".parse().unwrap();
      let mut second = event(30, "firefox", "a.example");
      second.connection.remote_ip = "203.0.113.20".parse().unwrap();

      let mut history = ConnectionLog::new(100, 32);
      history.push(&third);
      history.push(&first);
      history.push(&second);

      let rows: Vec<&Row> = history.rows().collect();
      let addrs: Vec<&str> = unique_conns(&rows).iter().map(|(row, _)| row.addr.as_str()).collect();
      assert_eq!(
         addrs,
         vec!["203.0.113.10:443", "203.0.113.20:443", "203.0.113.30:443"],
         "arrival order does not decide the row order"
      );

      // The newest row of each flow is still the one kept, so the activity column stays honest.
      let mut repeated = event(40, "firefox", "a.example");
      repeated.connection.remote_ip = "203.0.113.10".parse().unwrap();
      history.push(&repeated);
      let rows: Vec<&Row> = history.rows().collect();
      let unique = unique_conns(&rows);
      assert_eq!(
         unique[0].0.at, 40,
         "the newest flow is the row kept"
      );
      assert_eq!(unique[0].1, 2, "and both flows are counted");
   }

   /// A log of `count` flows to one destination, each with its own address, so none collapse.
   fn distinct_flows(count: u64) -> ConnectionLog {
      let mut history = ConnectionLog::new(64, 32);
      for at in 0..count {
         let mut row = event(at, "firefox", "a.example");
         row.connection.remote_ip = format!("203.0.113.{}", at + 1).parse().unwrap();
         history.push(&row);
      }
      history
   }

   #[test]
   fn each_level_caps_its_children_and_reports_the_remainder() {
      // Eight distinct flows fill the cap exactly; the ninth adds one More row.
      let app = Node::app("firefox");
      let host = Node::dest("firefox", "a.example");
      let lines = build_lines(
         &distinct_flows(8),
         &[],
         &expanded_set(&[app.clone(), host.clone()]),
         &ShowingAll::default(),
      );
      assert_eq!(
         lines.len(),
         10,
         "group, destination and eight connections"
      );
      assert!(matches!(lines[9], Line::Conn(_)));

      let nine = build_lines(
         &distinct_flows(9),
         &[],
         &expanded_set(&[app.clone(), host.clone()]),
         &ShowingAll::default(),
      );
      assert_eq!(
         nine.len(),
         11,
         "eight connection lines plus one overflow"
      );
      assert_eq!(
         nine[10],
         Line::More {
            remaining: 1,
            node: host.clone()
         }
      );

      let ten = build_lines(
         &distinct_flows(10),
         &[],
         &expanded_set(&[app.clone(), host.clone()]),
         &ShowingAll::default(),
      );
      assert_eq!(
         ten[10],
         Line::More {
            remaining: 2,
            node: host.clone()
         },
         "the remainder is the count past the cap"
      );

      // The destination's cap: group and destination, `MAX_CHILDREN` connections, then More.
      let lines = build_lines(
         &distinct_flows(11),
         &[],
         &expanded_set(&[app.clone(), host.clone()]),
         &ShowingAll::default(),
      );
      assert_eq!(lines.len(), 2 + MAX_CHILDREN + 1);
      assert!(matches!(lines[0], Line::Group { .. }));
      assert!(matches!(lines[1], Line::Dest { .. }));
      for (offset, line) in lines[2..=MAX_CHILDREN + 1].iter().enumerate() {
         assert!(
            matches!(line, Line::Conn(_)),
            "child {offset} is a connection line"
         );
      }
      let more = MAX_CHILDREN + 2;
      assert_eq!(
         lines[more],
         Line::More {
            remaining: 3,
            node: host.clone()
         },
         "the More row opens its destination"
      );

      // The app's cap: the group, `MAX_CHILDREN` destinations, then its own More row.
      let dests: Vec<String> = (0..10).map(|at| format!("d{at}.example")).collect();
      let events: Vec<(u64, &str, &str)> = dests
         .iter()
         .enumerate()
         .map(|(at, dest)| (at as u64, "firefox", dest.as_str()))
         .collect();
      let lines = build_lines(
         &log(&events),
         &[],
         &expanded_set(&[Node::app("firefox")]),
         &ShowingAll::default(),
      );
      assert_eq!(lines.len(), 1 + MAX_CHILDREN + 1);
      assert_eq!(
         lines[MAX_CHILDREN + 1],
         Line::More {
            remaining: 2,
            node: Node::app("firefox")
         },
         "the app's More row opens the app"
      );

      // Showing all reveals every connection and leaves no More row.
      let lines = build_lines(
         &distinct_flows(11),
         &[],
         &expanded_set(&[Node::app("firefox"), Node::dest("firefox", "a.example")]),
         &showing_all_set(&[Node::app("firefox"), Node::dest("firefox", "a.example")]),
      );
      assert_eq!(
         lines.len(),
         13,
         "the group, its destination and all eleven connections"
      );
      assert!(
         !lines.iter().any(|line| matches!(line, Line::More { .. })),
         "a group showing all has no overflow row"
      );
      assert_eq!(
         lines.iter().filter(|line| matches!(line, Line::Conn(_))).count(),
         11
      );

      // The cap counts unique flows: ten identical flows are one row and fit under it.
      let identical: Vec<(u64, &str, &str)> =
         (0..10).map(|at| (at, "firefox", "a.example")).collect();
      let lines = build_lines(
         &log(&identical),
         &[],
         &expanded_set(&[app.clone(), host.clone()]),
         &ShowingAll::default(),
      );
      assert_eq!(
         lines.iter().filter(|line| matches!(line, Line::Conn(_))).count(),
         1,
         "ten identical flows are one collapsed row"
      );
      assert!(
         !lines.iter().any(|line| matches!(line, Line::More { .. })),
         "one unique flow fits under the cap"
      );

      let mut distinct = ConnectionLog::new(16, 32);
      for at in 0..10 {
         let mut row = event(at, "firefox", "a.example");
         row.connection.remote_ip = format!("203.0.113.{}", at + 1).parse().unwrap();
         distinct.push(&row);
      }
      let lines = build_lines(
         &distinct,
         &[],
         &expanded_set(&[app, host.clone()]),
         &ShowingAll::default(),
      );
      assert_eq!(
         lines.iter().filter(|line| matches!(line, Line::Conn(_))).count(),
         MAX_CHILDREN,
         "ten distinct addresses still fill the cap"
      );
      assert_eq!(
         lines[MAX_CHILDREN + 2],
         Line::More {
            remaining: 2,
            node: host
         },
         "the remainder counts the unique flows past the cap"
      );
   }

   #[test]
   fn an_address_without_a_name_is_its_own_destination() {
      let mut unnamed = event(10, "firefox", "a.example");
      unnamed.connection.domain = None;
      unnamed.connection.remote_ip = "203.0.113.9".parse().unwrap();
      let mut history = ConnectionLog::new(8, 32);
      history.push(&unnamed);

      let lines = build_lines(
         &history,
         &[],
         &expanded_set(&[Node::app("firefox"), Node::dest("firefox", "203.0.113.9")]),
         &ShowingAll::default(),
      );

      assert_eq!(dest(&lines, 1), ("203.0.113.9", 1, 10));
      assert_eq!(conn(&lines, 2).addr, "203.0.113.9:443");
   }

   #[test]
   fn clicking_a_row_selects_it_and_only_its_chevron_toggles_it() {
      let rect = Rect::from_min_size(pos2(0.0, 0.0), vec2(300.0, LINE_HEIGHT));
      let mut expanded = Expanded::default();
      let mut showing_all = ShowingAll::default();
      let mut selection = Selection::default();

      // Clicking a group's name selects it and leaves the group alone.
      click_node(
         Node::app("firefox"),
         rect,
         pos2(120.0, 12.0),
         APP_NAME_X,
         &mut expanded,
         &mut showing_all,
         &mut selection,
      );
      assert_eq!(selection, Selection::App("firefox".to_owned()));
      assert!(
         !expanded.contains(&Node::app("firefox")),
         "clicking the name must not collapse the group"
      );

      // Its chevron toggles the group and leaves the selection alone.
      click_node(
         Node::app("firefox"),
         rect,
         pos2(6.0, 12.0),
         APP_NAME_X,
         &mut expanded,
         &mut showing_all,
         &mut selection,
      );
      assert!(
         expanded.contains(&Node::app("firefox")),
         "the chevron toggles the group"
      );
      assert_eq!(
         selection,
         Selection::App("firefox".to_owned()),
         "the chevron leaves the selection alone"
      );

      // A destination: the chevron toggles it without selecting, a name click selects it.
      let node = Node::dest("firefox", "a.example");
      let mut expanded = Expanded::default();
      let mut showing_all = ShowingAll::default();
      let mut selection = Selection::default();
      click_node(
         node.clone(),
         rect,
         pos2(rect.left() + 30.0, 12.0),
         DEST_NAME_X,
         &mut expanded,
         &mut showing_all,
         &mut selection,
      );
      assert!(
         expanded.contains(&node),
         "a click in [22,44) toggles the destination"
      );
      assert_eq!(
         selection,
         Selection::default(),
         "the chevron does not select"
      );

      click_node(
         node,
         rect,
         pos2(rect.left() + 100.0, 12.0),
         DEST_NAME_X,
         &mut expanded,
         &mut showing_all,
         &mut selection,
      );
      assert_eq!(
         selection,
         Selection::Dest {
            app: "firefox".to_owned(),
            dest: "a.example".to_owned()
         }
      );

      // Collapsing an open group forgets that it was showing all.
      let mut expanded = expanded_set(&[Node::app("firefox")]);
      let mut showing_all = showing_all_set(&[Node::app("firefox")]);
      let mut selection = Selection::default();
      click_node(
         Node::app("firefox"),
         rect,
         pos2(6.0, 12.0),
         APP_NAME_X,
         &mut expanded,
         &mut showing_all,
         &mut selection,
      );
      assert!(!expanded.contains(&Node::app("firefox")));
      assert!(
         !showing_all.contains(&Node::app("firefox")),
         "reopening starts from MAX_CHILDREN again"
      );

      // And collapsing an app forgets its destinations' showing-all entries, without closing
      // the destinations themselves.
      let app = Node::app("firefox");
      let first = Node::dest("firefox", "a.example");
      let second = Node::dest("firefox", "b.example");
      let expanded = expanded_set(&[app.clone(), first.clone(), second.clone()]);
      let mut showing_all = showing_all_set(&[app.clone(), first.clone(), second.clone()]);

      showing_all.forget(&app);

      assert!(!showing_all.contains(&app));
      assert!(!showing_all.contains(&first));
      assert!(!showing_all.contains(&second));
      assert!(
         expanded.contains(&first) && expanded.contains(&second),
         "the destinations stay open"
      );
   }

   #[test]
   fn a_connection_is_selected_by_its_address_and_protocol() {
      let mut first = event(10, "firefox", "a.example");
      first.connection.remote_ip = "203.0.113.9".parse().unwrap();
      // The second row has no resolved name, so its destination is the address itself: the
      // two selections share an app and a timestamp and differ only in `addr`.
      let mut second = event(10, "firefox", "a.example");
      second.connection.domain = None;
      second.connection.remote_ip = "203.0.113.10".parse().unwrap();
      let mut history = ConnectionLog::new(8, 32);
      history.push(&first);
      history.push(&second);
      let lines = build_lines(
         &history,
         &[],
         &expanded_set(&[
            Node::app("firefox"),
            Node::dest("firefox", "a.example"),
            Node::dest("firefox", "203.0.113.10"),
         ]),
         &ShowingAll::default(),
      );

      let first = Detail::resolve(
         &lines,
         &Selection::Conn {
            app: "firefox".to_owned(),
            at: 10,
            addr: "203.0.113.9:443".to_owned(),
            proto: "tcp".to_owned(),
         },
      )
      .expect("the first connection resolves");
      let second = Detail::resolve(
         &lines,
         &Selection::Conn {
            app: "firefox".to_owned(),
            at: 10,
            addr: "203.0.113.10:443".to_owned(),
            proto: "tcp".to_owned(),
         },
      )
      .expect("the second connection resolves");

      assert_eq!(first.dest, Some("a.example"));
      assert_eq!(second.dest, Some("203.0.113.10"));

      // Same app and timestamp, same address, other protocol: no connection matches, so the
      // pane falls back to the app rather than to the address's row.
      let other_proto = Detail::resolve(
         &lines,
         &Selection::Conn {
            app: "firefox".to_owned(),
            at: 10,
            addr: "203.0.113.9:443".to_owned(),
            proto: "udp".to_owned(),
         },
      )
      .expect("the app's own details are the fallback");
      assert_eq!(
         other_proto.dest, None,
         "the protocol disambiguates the address"
      );

      // Two rows on the same address and timestamp, one per protocol: the protocol picks the
      // row, and its verdict with it.
      let mut tcp = event(10, "firefox", "a.example");
      tcp.connection.remote_ip = "203.0.113.9".parse().unwrap();
      let mut udp = event(10, "firefox", "a.example");
      udp.connection.remote_ip = "203.0.113.9".parse().unwrap();
      udp.connection.proto = L4Proto::Udp;
      udp.allowed = false;
      let mut history = ConnectionLog::new(8, 32);
      history.push(&tcp);
      history.push(&udp);
      let lines = build_lines(
         &history,
         &[],
         &expanded_set(&[Node::app("firefox"), Node::dest("firefox", "a.example")]),
         &ShowingAll::default(),
      );

      let tcp_detail = Detail::resolve(
         &lines,
         &Selection::Conn {
            app: "firefox".to_owned(),
            at: 10,
            addr: "203.0.113.9:443".to_owned(),
            proto: "tcp".to_owned(),
         },
      )
      .expect("the tcp connection resolves");
      let udp_detail = Detail::resolve(
         &lines,
         &Selection::Conn {
            app: "firefox".to_owned(),
            at: 10,
            addr: "203.0.113.9:443".to_owned(),
            proto: "udp".to_owned(),
         },
      )
      .expect("the udp connection resolves");

      assert_eq!(tcp_detail.verdict, Some(true));
      assert_eq!(udp_detail.verdict, Some(false));
   }

   #[test]
   fn the_lines_cache_rebuilds_only_when_an_input_changes() {
      let no_rules = Ruleset::default();
      let mut log = log(&[(10, "firefox", "a.example")]);
      let mut expanded = Expanded::default();
      let mut showing_all = ShowingAll::default();
      let mut cache = LinesCache::default();

      let before = builds();
      cache.refresh(&log, &no_rules, &expanded, &showing_all);
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

      cache.refresh(&log, &no_rules, &expanded, &showing_all);
      assert_eq!(
         builds(),
         before + 1,
         "an unchanged frame reuses them"
      );

      log.push(&event(20, "curl", "b.example"));
      cache.refresh(&log, &no_rules, &expanded, &showing_all);
      assert_eq!(builds(), before + 2, "a new row rebuilds");
      assert_eq!(cache.lines.len(), 2, "both groups stay collapsed");

      expanded.toggle(&Node::app("firefox"));
      cache.refresh(&log, &no_rules, &expanded, &showing_all);
      assert_eq!(builds(), before + 3, "expanding rebuilds");
      assert_eq!(
         cache.lines.len(),
         3,
         "group, destination, connection"
      );

      expanded.toggle(&Node::dest("firefox", "a.example"));
      cache.refresh(&log, &no_rules, &expanded, &showing_all);
      assert_eq!(
         builds(),
         before + 4,
         "opening a destination rebuilds"
      );
      assert_eq!(cache.lines.len(), 4);

      showing_all.insert(Node::app("firefox"));
      cache.refresh(&log, &no_rules, &expanded, &showing_all);
      assert_eq!(
         builds(),
         before + 5,
         "turning on showing all rebuilds the list"
      );

      let mut rules = Ruleset::default();
      rules.install(vec![rule(DestMatcher::Any, Action::Allow)]);
      cache.refresh(&log, &rules, &expanded, &showing_all);
      assert_eq!(builds(), before + 6, "a rule list rebuilds too");
   }

   #[test]
   fn a_rule_edit_that_keeps_the_count_rebuilds_the_lines() {
      let log = log(&[(10, "firefox", "a.example")]);
      let mut cache = LinesCache::default();
      let mut rules = Ruleset::default();
      rules.install(vec![rule(DestMatcher::Any, Action::Allow)]);
      let expanded = Expanded::default();
      let showing_all = ShowingAll::default();

      cache.refresh(&log, &rules, &expanded, &showing_all);
      let before = builds();
      cache.refresh(&log, &rules, &expanded, &showing_all);
      assert_eq!(
         builds(),
         before,
         "the same revision reuses the lines"
      );

      // A rule switched off, a duration changed: same count, different content.
      rules.install(vec![rule(DestMatcher::Any, Action::Allow)]);
      cache.refresh(&log, &rules, &expanded, &showing_all);
      assert_eq!(
         builds(),
         before + 1,
         "a rule edit rebuilds even at the same count"
      );
   }

   #[test]
   fn one_rebuild_is_in_flight_at_a_time() {
      let mut cache = LinesCache::default();
      let none = HashSet::new();
      let inputs = |log: u64| Inputs {
         log,
         ..Inputs::default()
      };

      cache.in_flight = Some(inputs(1));
      assert_eq!(
         cache.step(1, 0, &none, &none),
         Step::Current,
         "these inputs are already being built"
      );
      assert_eq!(
         cache.step(2, 0, &none, &none),
         Step::Wait,
         "a newer input waits for the job in flight"
      );

      cache.in_flight = None;
      cache.installed = inputs(2);
      assert_eq!(
         cache.step(2, 0, &none, &none),
         Step::Current,
         "the installed lines match"
      );
      assert_eq!(
         cache.step(3, 0, &none, &none),
         Step::Submit,
         "a moved input submits"
      );
   }

   #[test]
   fn a_result_is_only_installed_for_the_job_that_asked_for_it() {
      let none = HashSet::new();
      let pending = Inputs {
         log: 1,
         ..Inputs::default()
      };
      let job = take_job(
         &log(&[(10, "firefox", "a.example"), (20, "curl", "b.example")]),
         &Ruleset::default(),
         pending.clone(),
      );
      let mut cache = LinesCache::default();
      cache.install(derive(&job), &pending);
      assert_eq!(
         cache.lines.len(),
         2,
         "the pending job's result is installed"
      );
      assert!(
         cache.installed.matches(1, 0, &none, &none),
         "the installed inputs are the ones the job was built for"
      );

      // A result for inputs the cache is not waiting for must change nothing.
      cache.install(
         LinesReady {
            lines: Vec::new(),
            inputs: Inputs {
               log: 2,
               ..Inputs::default()
            },
         },
         &pending,
      );
      assert_eq!(
         cache.lines.len(),
         2,
         "a superseded result is dropped"
      );
      assert!(
         cache.installed.matches(1, 0, &none, &none),
         "and the installed inputs stay put"
      );
   }

   #[test]
   fn opening_a_group_rebuilds_even_when_the_log_stands_still() {
      let log = log(&[(10, "firefox", "a.example")]);
      let rules = Ruleset::default();
      let mut cache = LinesCache::default();
      let mut expanded = Expanded::default();
      let showing_all = ShowingAll::default();

      cache.refresh(&log, &rules, &expanded, &showing_all);
      assert_eq!(
         cache.lines.len(),
         1,
         "a never-seen app starts collapsed"
      );

      expanded.toggle(&Node::app("firefox"));
      cache.refresh(&log, &rules, &expanded, &showing_all);
      assert_eq!(
         cache.lines.len(),
         2,
         "opening the app shows its group and its destination"
      );
   }

   /// Four flows to one destination: one older udp flow and three identical tcp ones.
   fn repeated_flows() -> ConnectionLog {
      let mut udp = event(5, "firefox", "a.example");
      udp.connection.proto = L4Proto::Udp;
      let mut history = ConnectionLog::new(8, 32);
      history.push(&udp);
      for at in [10, 20, 30] {
         history.push(&event(at, "firefox", "a.example"));
      }
      history
   }

   #[test]
   fn repeated_flows_collapse_and_totals_stay_raw() {
      let history = repeated_flows();
      let rows: Vec<&Row> = history.rows().collect();
      let unique = unique_conns(&rows);
      assert_eq!(unique.len(), 2, "two distinct flows");
      assert_eq!(unique[0].1, 3, "three identical tcp flows");
      assert_eq!(
         unique[0].0.at, 30,
         "the group keeps its newest row"
      );

      let lines = build_lines(
         &history,
         &[],
         &expanded_set(&[Node::app("firefox"), Node::dest("firefox", "a.example")]),
         &ShowingAll::default(),
      );
      let conns: Vec<&Conn> = lines
         .iter()
         .filter_map(|line| match line {
            Line::Conn(conn) => Some(conn),
            _ => None,
         })
         .collect();
      assert_eq!(conns.len(), 2, "one row per distinct flow");
      assert_eq!(conns[0].repeat, 3);
      assert_eq!(conns[0].at, 30);
      assert_eq!(conns[1].repeat, 1);

      // The group and destination totals stay raw even though the third level collapses.
      assert_eq!(group(&lines, 0), ("firefox", 4, 30));
      assert_eq!(dest(&lines, 1), ("a.example", 4, 30));
      assert_eq!(
         lines.iter().filter(|line| matches!(line, Line::Conn(_))).count(),
         2,
         "the third level collapses even though the totals do not"
      );
   }
}
