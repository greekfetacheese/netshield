//! The Connections page: one collapsible row per application, its connections underneath.
//!
//! The log is flattened into an owned [`Line`] vector and drawn with
//! [`egui::ScrollArea::show_rows`], which paints only the visible window of a uniform row
//! height. Collapsing a process therefore costs one rebuild of that vector, not a frame of
//! hidden widgets.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

use egui::text::{LayoutJob, TextFormat, TextWrapping};
use egui::{Color32, FontId, Rect, Response, RichText, Sense, Shape, Stroke, Ui, pos2};
use netshield_core::rule::{Rule, RuleId};

use crate::connlog::{ConnectionLog, Row, clock};
use crate::ui::rules::{action_label, dest_label};

/// The fixed height of every line, group or connection; `show_rows` depends on it.
const LINE_HEIGHT: f32 = 24.0;

/// The column-header line above the list.
const HEADER_HEIGHT: f32 = 18.0;

/// Whitespace between two columns.
const COLUMN_GAP: f32 = 12.0;

/// How far connection rows and group content are indented past the chevron.
const INDENT: f32 = 16.0;

/// Right-hand padding inside a row.
const ROW_PAD: f32 = 8.0;

const TIME_WIDTH: f32 = 62.0;
const ADDRESS_WIDTH: f32 = 150.0;
const PROTO_WIDTH: f32 = 44.0;
const RESULT_WIDTH: f32 = 120.0;
const RULE_WIDTH: f32 = 150.0;

/// The destination column takes whatever is left, but never shrinks below this.
const DESTINATION_MIN: f32 = 120.0;

/// Activity window: 30 one-minute buckets, oldest first.
const ACTIVITY_BUCKETS: usize = 30;
const BUCKET_SECS: u64 = 60;
const BAR_WIDTH: f32 = 2.0;
const BAR_GAP: f32 = 2.0;
const ACTIVITY_HEIGHT: f32 = 14.0;

/// Verdict colour for an allowed connection.
const ALLOWED: Color32 = Color32::from_rgb(0x6C, 0xC0, 0x7A);

/// Whole-row colour for a denied connection: muted red so a scan still reads as text.
const DENIED: Color32 = Color32::from_rgb(0xC0, 0x6A, 0x6A);

/// Shown when the deciding rule is no longer in the daemon's list.
///
/// U+2014 is present in both bundled text fonts (Ubuntu-Light and Hack), so it is safe.
const DASH: &str = "—";

/// Which applications are collapsed. Keyed by the row's `app` label.
#[derive(Default)]
pub struct Collapsed(HashSet<String>);

impl Collapsed {
   /// Flips one application between collapsed and open.
   fn toggle(&mut self, app: &str) {
      if !self.0.remove(app) {
         self.0.insert(app.to_owned());
      }
   }

   fn contains(&self, app: &str) -> bool {
      self.0.contains(app)
   }
}

/// Cached derived lines, rebuilt only when the log, the rules or the collapse set change.
#[derive(Default)]
pub struct LinesCache {
   version: u64,
   rule_count: usize,
   collapsed: HashSet<String>,
   lines: Vec<Line>,
}

impl LinesCache {
   /// Rebuilds the lines when any input moved; an unchanged frame reuses the old vector.
   fn refresh(&mut self, log: &ConnectionLog, rules: &[Rule], collapsed: &Collapsed) {
      let unchanged = self.version == log.version()
         && self.rule_count == rules.len()
         && self.collapsed == collapsed.0;
      if unchanged {
         return;
      }
      self.lines = build_lines(log, rules, collapsed);
      self.version = log.version();
      self.rule_count = rules.len();
      self.collapsed = collapsed.0.clone();
   }
}

/// One line of the virtualised list. Owned and flat, because `show_rows` needs a uniform
/// index space rather than a tree of widgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
   /// One application: its name, how many connections it has, when it was last active and its
   /// per-minute activity.
   Group {
      app: String,
      count: usize,
      last_at: u64,
      activity: Vec<u16>,
   },
   /// One connection belonging to the group above it.
   Conn(Conn),
}

/// One flattened connection row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conn {
   pub time: String,
   pub dest: String,
   pub addr: String,
   pub proto: String,
   pub allowed: bool,
   pub via_prompt: bool,
   pub candidate: Option<String>,
   /// `allow example.com`, `deny anywhere`, … or `—` when the rule is gone.
   pub rule: String,
}

/// Draws the heading and the virtualised per-application list.
pub fn show(
   ui: &mut Ui,
   log: &ConnectionLog,
   rules: &[Rule],
   collapsed: &mut Collapsed,
   cache: &mut LinesCache,
) {
   cache.refresh(log, rules, collapsed);

   let apps = cache.lines.iter().filter(|line| matches!(line, Line::Group { .. })).count();
   heading(ui, log, apps);

   if log.is_empty() {
      ui.label(
         RichText::new("No connections yet — the daemon reports them as they happen.").weak(),
      );
      return;
   }

   let columns = Columns::new(ui.available_width());
   header_row(ui, &columns);

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
            let width = ui.available_width();
            let sense = match line {
               Line::Group { .. } => Sense::click(),
               Line::Conn(_) => Sense::hover(),
            };
            let (rect, response) = ui.allocate_exact_size(egui::vec2(width, LINE_HEIGHT), sense);
            match line {
               Line::Group {
                  app,
                  count,
                  last_at,
                  activity,
               } => {
                  if response.clicked() {
                     collapsed.toggle(app);
                     // The cache still holds the pre-click lines; one more frame turns the
                     // toggle into the rows it opens or hides.
                     ui.ctx().request_repaint();
                  }
                  group_row(
                     ui,
                     &response,
                     app,
                     *count,
                     *last_at,
                     activity,
                     collapsed.contains(app),
                  );
               }
               Line::Conn(conn) => conn_row(ui, rect, &columns, conn),
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
   time: f32,
   dest: f32,
   addr: f32,
   proto: f32,
   result: f32,
   rule: f32,
   time_x: f32,
   dest_x: f32,
   addr_x: f32,
   proto_x: f32,
   result_x: f32,
   rule_x: f32,
}

impl Columns {
   fn new(width: f32) -> Self {
      let time = TIME_WIDTH;
      let addr = ADDRESS_WIDTH;
      let proto = PROTO_WIDTH;
      let result = RESULT_WIDTH;
      let rule = RULE_WIDTH;
      let used = INDENT + time + addr + proto + result + rule + COLUMN_GAP * 5.0;
      let dest = (width - used).max(DESTINATION_MIN);
      let time_x = INDENT;
      let dest_x = time_x + time + COLUMN_GAP;
      let addr_x = dest_x + dest + COLUMN_GAP;
      let proto_x = addr_x + addr + COLUMN_GAP;
      let result_x = proto_x + proto + COLUMN_GAP;
      let rule_x = result_x + result + COLUMN_GAP;
      Self {
         time,
         dest,
         addr,
         proto,
         result,
         rule,
         time_x,
         dest_x,
         addr_x,
         proto_x,
         result_x,
         rule_x,
      }
   }
}

/// Paints one row's cells, clipped to their columns and centred vertically.
///
/// Column offsets are relative to the row's left edge, so the header and the rows share
/// one geometry even where the list is horizontally scrolled.
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

/// The `Time Destination Address Proto Result Rule` labels above the list.
fn header_row(ui: &mut Ui, columns: &Columns) {
   let width = ui.available_width();
   let (rect, _) = ui.allocate_exact_size(egui::vec2(width, HEADER_HEIGHT), Sense::hover());
   let cells = Cells {
      painter: ui.painter(),
      rect,
   };
   let font = FontId::proportional(11.0);
   let color = ui.visuals().weak_text_color();
   let headers = [
      (columns.time_x, columns.time, "Time (UTC)"),
      (columns.dest_x, columns.dest, "Destination"),
      (columns.addr_x, columns.addr, "Address"),
      (columns.proto_x, columns.proto, "Proto"),
      (columns.result_x, columns.result, "Result"),
      (columns.rule_x, columns.rule, "Rule"),
   ];
   for (x, width, text) in headers {
      cells.text(x, width, text, &font, color, false);
   }
}

/// One application row: chevron, name, count, last-seen time and the activity sparkline.
fn group_row(
   ui: &mut Ui,
   response: &Response,
   app: &str,
   count: usize,
   last_at: u64,
   activity: &[u16],
   collapsed: bool,
) {
   let rect = response.rect;
   let visuals = ui.visuals();
   let fill = if response.hovered() {
      visuals.widgets.hovered.weak_bg_fill
   } else {
      visuals.faint_bg_color
   };
   let painter = ui.painter();
   painter.rect_filled(rect, 0.0, fill);

   let weak = visuals.weak_text_color();
   let strong = visuals.strong_text_color();
   let center_y = rect.center().y;
   let right = rect.right() - ROW_PAD;

   // The disclosure triangle is painted, not glyph-rendered: the bundled font is not
   // guaranteed to carry a chevron.
   let tip = pos2(rect.left() + 11.0, center_y);
   let points = if collapsed {
      vec![
         pos2(tip.x - 3.0, tip.y - 4.5),
         pos2(tip.x - 3.0, tip.y + 4.5),
         pos2(tip.x + 3.0, tip.y),
      ]
   } else {
      vec![
         pos2(tip.x - 4.5, tip.y - 3.0),
         pos2(tip.x + 4.5, tip.y - 3.0),
         pos2(tip.x, tip.y + 3.0),
      ]
   };
   painter.add(Shape::convex_polygon(points, weak, Stroke::NONE));

   let activity_span =
      ACTIVITY_BUCKETS as f32 * BAR_WIDTH + (ACTIVITY_BUCKETS - 1) as f32 * BAR_GAP;
   let spark_left = right - activity_span;
   let max = activity.iter().copied().max().unwrap_or(0);
   if max > 0 {
      let bottom = center_y + ACTIVITY_HEIGHT / 2.0;
      for (index, value) in activity.iter().enumerate() {
         if *value == 0 {
            continue;
         }
         let height = f32::from(*value) / f32::from(max) * ACTIVITY_HEIGHT;
         let x = spark_left + index as f32 * (BAR_WIDTH + BAR_GAP);
         painter.rect_filled(
            Rect::from_min_max(
               pos2(x, bottom - height),
               pos2(x + BAR_WIDTH, bottom),
            ),
            0.0,
            weak,
         );
      }
   }

   let small = FontId::monospace(12.0);
   let body = FontId::proportional(13.0);

   let time = painter.layout_no_wrap(clock(last_at), small.clone(), weak);
   let time_x = spark_left - COLUMN_GAP - time.size().x;
   let time_height = time.size().y;
   painter.galley(
      pos2(time_x, center_y - time_height / 2.0),
      time,
      weak,
   );

   let count = painter.layout_no_wrap(format!("{count} connections"), body.clone(), weak);
   let count_x = time_x - COLUMN_GAP - count.size().x;
   let count_height = count.size().y;
   painter.galley(
      pos2(count_x, center_y - count_height / 2.0),
      count,
      weak,
   );

   let name_x = rect.left() + INDENT;
   let name_width = (count_x - COLUMN_GAP - name_x).max(40.0);
   let cells = Cells { painter, rect };
   cells.text(INDENT, name_width, app, &body, strong, false);
}

/// One connection row. A denied row keeps every cell in the muted red.
fn conn_row(ui: &mut Ui, rect: Rect, columns: &Columns, conn: &Conn) {
   let visuals = ui.visuals();
   let base = if conn.allowed {
      visuals.text_color()
   } else {
      DENIED
   };
   let weak = if conn.allowed {
      visuals.weak_text_color()
   } else {
      DENIED
   };
   let verdict_colour = if conn.allowed { ALLOWED } else { DENIED };
   let cells = Cells {
      painter: ui.painter(),
      rect,
   };
   let time_font = FontId::monospace(12.0);
   let body_font = FontId::proportional(13.0);

   cells.text(
      columns.time_x,
      columns.time,
      &conn.time,
      &time_font,
      base,
      false,
   );
   match &conn.candidate {
      // A candidate is a name the daemon guessed but did not resolve; the `?` keeps that
      // distinction visible while the row keeps the existing italic treatment.
      Some(candidate) => cells.text(
         columns.dest_x,
         columns.dest,
         &format!("{candidate} ?"),
         &body_font,
         weak,
         true,
      ),
      None => cells.text(
         columns.dest_x,
         columns.dest,
         &conn.dest,
         &body_font,
         base,
         false,
      ),
   }
   cells.text(
      columns.addr_x,
      columns.addr,
      &conn.addr,
      &time_font,
      base,
      false,
   );
   cells.text(
      columns.proto_x,
      columns.proto,
      &conn.proto,
      &body_font,
      base,
      false,
   );

   let verdict = if conn.allowed { "ALLOWED" } else { "DENIED" };
   let verdict = if conn.via_prompt {
      format!("{verdict} (prompt)")
   } else {
      verdict.to_owned()
   };
   cells.text(
      columns.result_x,
      columns.result,
      &verdict,
      &body_font,
      verdict_colour,
      false,
   );
   cells.text(
      columns.rule_x,
      columns.rule,
      &conn.rule,
      &body_font,
      base,
      false,
   );
}

/// Groups the log per app, newest first, and flattens the open groups into lines.
///
/// The log is scanned newest-first, so each group collects its rows in that order. Groups
/// are then sorted on their newest event rather than on arrival alone: `at` is what the
/// page promises to order by, and a burst can reach the log slightly out of order.
fn build_lines(log: &ConnectionLog, rules: &[Rule], collapsed: &Collapsed) -> Vec<Line> {
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
      let newest = rows.first().map_or(0, |row| row.at);
      lines.push(Line::Group {
         app: (*app).to_owned(),
         count: rows.len(),
         last_at: newest,
         activity: activity(rows, newest),
      });
      if collapsed.contains(app) {
         continue;
      }
      for row in rows {
         lines.push(Line::Conn(conn(row, rules)));
      }
   }
   lines
}

/// Counts an app's events into 30 one-minute buckets ending at its newest event.
fn activity(rows: &[&Row], newest: u64) -> Vec<u16> {
   let mut buckets = vec![0u16; ACTIVITY_BUCKETS];
   for row in rows {
      let bucket = (newest.saturating_sub(row.at) / BUCKET_SECS) as usize;
      if bucket < ACTIVITY_BUCKETS {
         let slot = ACTIVITY_BUCKETS - 1 - bucket;
         buckets[slot] = buckets[slot].saturating_add(1);
      }
   }
   buckets
}

/// Flattens one log row, resolving its rule id against the current rule list.
fn conn(row: &Row, rules: &[Rule]) -> Conn {
   Conn {
      time: row.time.clone(),
      dest: row.dest.clone(),
      addr: row.addr.clone(),
      proto: row.proto.clone(),
      allowed: row.allowed,
      via_prompt: row.via_prompt,
      candidate: row.candidate.clone(),
      rule: rule_label(row.rule_id.as_ref(), rules),
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

   #[test]
   fn groups_are_ordered_by_their_newest_connection() {
      let log = log(&[
         (10, "firefox", "a.example"),
         (20, "curl", "b.example"),
         (30, "firefox", "c.example"),
      ]);

      let lines = build_lines(&log, &[], &Collapsed::default());

      assert_eq!(group(&lines, 0), ("firefox", 2, 30));
      assert_eq!(conn(&lines, 1).dest, "c.example");
      assert_eq!(conn(&lines, 2).dest, "a.example");
      assert_eq!(group(&lines, 3), ("curl", 1, 20));
      assert_eq!(lines.len(), 5);
   }

   #[test]
   fn a_collapsed_app_hides_its_connections_until_expanded() {
      let log = log(&[(20, "firefox", "a.example"), (10, "curl", "b.example")]);
      let mut collapsed = Collapsed::default();
      let open = build_lines(&log, &[], &collapsed);
      assert_eq!(open.len(), 4);

      collapsed.toggle("firefox");
      let shut = build_lines(&log, &[], &collapsed);
      assert_eq!(shut.len(), 3);
      assert_eq!(group(&shut, 0), ("firefox", 1, 20));
      assert_eq!(group(&shut, 1), ("curl", 1, 10));
      assert!(
         matches!(shut[2], Line::Conn(_)),
         "curl's own row follows"
      );

      collapsed.toggle("firefox");
      let reopened = build_lines(&log, &[], &collapsed);
      assert_eq!(reopened.len(), open.len());
      assert_eq!(conn(&reopened, 1).dest, "a.example");
   }

   #[test]
   fn activity_buckets_per_minute_ending_at_the_newest_event() {
      let base = 60_000;
      let log = log(&[
         (base, "firefox", "a.example"),
         (base + 10, "firefox", "b.example"),
         (base + 59, "firefox", "c.example"),
         (base + 60, "firefox", "d.example"),
         (base + 300, "firefox", "e.example"),
      ]);
      let lines = build_lines(&log, &[], &Collapsed::default());
      let Line::Group { activity, .. } = &lines[0] else {
         panic!("expected a group first");
      };

      assert_eq!(activity.len(), ACTIVITY_BUCKETS);
      let bucket = |minutes_ago: usize| activity[ACTIVITY_BUCKETS - 1 - minutes_ago];
      assert_eq!(
         bucket(0),
         1,
         "the newest event is in the last bucket"
      );
      assert_eq!(
         bucket(4),
         3,
         "the three events within one minute share a bucket"
      );
      assert_eq!(
         bucket(5),
         1,
         "the oldest event is five buckets back"
      );
      let total: u32 = activity.iter().map(|count| u32::from(*count)).sum();
      assert_eq!(total, 5, "every event lands in a bucket");
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

      // And through the flattened row, which is what the table actually paints.
      let mut matched = event(0, "firefox", "a.example");
      matched.matched_rule = Some(rules[0].id.clone());
      let mut log = ConnectionLog::new(8);
      log.push(&matched);
      let lines = build_lines(&log, &rules, &Collapsed::default());
      assert_eq!(conn(&lines, 1).rule, "allow anywhere");
   }

   #[test]
   fn the_cache_rebuilds_only_when_an_input_changes() {
      let mut log = log(&[(10, "firefox", "a.example")]);
      let mut collapsed = Collapsed::default();
      let mut cache = LinesCache::default();

      let before = builds();
      cache.refresh(&log, &[], &collapsed);
      assert_eq!(cache.lines.len(), 2);
      assert_eq!(
         builds(),
         before + 1,
         "the first frame builds the lines"
      );

      cache.refresh(&log, &[], &collapsed);
      assert_eq!(
         builds(),
         before + 1,
         "an unchanged frame reuses them"
      );

      log.push(&event(20, "curl", "b.example"));
      cache.refresh(&log, &[], &collapsed);
      assert_eq!(builds(), before + 2, "a new row rebuilds");
      assert_eq!(cache.lines.len(), 4);

      collapsed.toggle("firefox");
      cache.refresh(&log, &[], &collapsed);
      assert_eq!(builds(), before + 3, "collapsing rebuilds");
      assert_eq!(cache.lines.len(), 3);

      let rules = vec![rule(DestMatcher::Any, Action::Allow)];
      cache.refresh(&log, &rules, &collapsed);
      assert_eq!(builds(), before + 4, "a rule list rebuilds too");
   }
}
