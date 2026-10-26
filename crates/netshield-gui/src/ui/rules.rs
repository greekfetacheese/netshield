//! The Rules page: the policy table and the delete-confirmation state.

use egui::{Color32, RichText, Ui};
use netshield_core::rule::{Action, AppMatcher, DestMatcher, Duration, Rule, RuleId};

/// Verdict colour for an enabled allow rule.
const ALLOWED: Color32 = Color32::from_rgb(0x6C, 0xC0, 0x7A);

/// Verdict colour for an enabled deny rule.
const DENIED: Color32 = Color32::from_rgb(0xC0, 0x6A, 0x6A);

/// Seconds in a day; the clock is UTC because the GUI has no timezone dependency.
const SECS_PER_DAY: u64 = 86_400;

const HEADERS: [&str; 8] = [
   "On",
   "Application",
   "Destination",
   "Action",
   "Duration",
   "Hits",
   "Last matched",
   "",
];

/// Human-readable application scope: "any application", the exe basename, or "unknown".
pub fn app_label(app: &AppMatcher) -> String {
   match app {
      AppMatcher::Any => "any application".to_owned(),
      AppMatcher::Exe(path) => path.file_name().map_or_else(
         || path.display().to_string(),
         |name| name.to_string_lossy().into_owned(),
      ),
      AppMatcher::Unknown => "unknown".to_owned(),
   }
}

/// Human-readable destination scope: "anywhere", "only api.github.com", "*.github.com",
/// "140.82.0.0/16", "port 443".
pub fn dest_label(dest: &DestMatcher) -> String {
   match dest {
      DestMatcher::Any => "anywhere".to_owned(),
      DestMatcher::Domain {
         host,
         subdomains: false,
      } => format!("only {host}"),
      DestMatcher::Domain {
         host,
         subdomains: true,
      } => format!("*.{host}"),
      DestMatcher::Ip(net) => net.to_string(),
      DestMatcher::Port(port) => format!("port {port}"),
   }
}

/// The verdict as it is spoken in the policy model; the table upper-cases it.
pub fn action_label(action: Action) -> &'static str {
   match action {
      Action::Allow => "allow",
      Action::Deny => "deny",
   }
}

/// How long the decision lasts, in the words the prompt uses.
pub fn duration_label(duration: Duration) -> &'static str {
   match duration {
      Duration::Once => "once",
      Duration::Session => "until restart",
      Duration::Forever => "forever",
   }
}

/// The last time a rule matched, as `HH:MM:SS` in UTC, or an em dash when it never did.
pub fn matched_label(at: Option<u64>) -> String {
   match at {
      Some(at) => clock(at),
      None => "—".to_owned(),
   }
}

/// Formats unix seconds as `HH:MM:SS` in UTC.
fn clock(at: u64) -> String {
   let secs = at % SECS_PER_DAY;
   format!(
      "{:02}:{:02}:{:02}",
      secs / 3600,
      (secs / 60) % 60,
      secs % 60
   )
}

/// Which delete is awaiting its second click. At most one at a time.
#[derive(Default)]
pub struct Confirm {
   pending: Option<RuleId>,
}

impl Confirm {
   /// First call arms `id`; a second call for the same id returns true (and disarms);
   /// a call for a different id re-arms to that id and returns false.
   pub fn click(&mut self, id: &RuleId) -> bool {
      if self.pending.as_ref() == Some(id) {
         self.pending = None;
         true
      } else {
         self.pending = Some(id.clone());
         false
      }
   }

   /// Whether this rule's Delete button currently reads `Confirm?`.
   pub fn is_armed(&self, id: &RuleId) -> bool {
      self.pending.as_ref() == Some(id)
   }

   /// Drops any pending confirmation, so a click elsewhere cannot delete later.
   pub fn cancel(&mut self) {
      self.pending = None;
   }
}

/// What the table wants the caller to send; the caller owns the socket.
#[derive(Default)]
pub struct Actions {
   pub toggles: Vec<(RuleId, bool)>,
   pub deletes: Vec<RuleId>,
}

/// Draws the table; collects intents instead of sending them, so it stays testable and the
/// caller owns the socket.
pub fn show(ui: &mut Ui, rules: &[Rule], confirm: &mut Confirm) -> Actions {
   let mut actions = Actions::default();

   ui.horizontal(|ui| {
      ui.heading("Rules");
      ui.add_space(8.0);
      ui.label(RichText::new(format!("{} rules", rules.len())).weak());
   });
   ui.add_space(4.0);

   if rules.is_empty() {
      ui.label(
         RichText::new(
            "No rules yet. The first prompt creates one, and a default allow rule for the \
             local resolver is seeded on first start.",
         )
         .weak(),
      );
      return actions;
   }

   let mut delete_clicked = false;
   let table = egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
      let grid = egui::Grid::new("rules")
         .num_columns(HEADERS.len())
         .striped(true)
         .spacing([12.0, 6.0])
         .show(ui, |ui| {
            for header in HEADERS {
               ui.label(RichText::new(header).strong());
            }
            ui.end_row();

            for rule in rules {
               let enabled = rule.enabled;
               let base = if enabled {
                  ui.visuals().text_color()
               } else {
                  ui.visuals().weak_text_color()
               };

               let mut checked = enabled;
               if ui.add(egui::Checkbox::without_text(&mut checked)).changed() {
                  actions.toggles.push((rule.id.clone(), checked));
               }

               application_cell(ui, rule, &base);

               ui.label(RichText::new(dest_label(&rule.dest)).color(base));
               ui.label(
                  RichText::new(action_label(rule.action).to_uppercase())
                     .color(action_colour(rule.action, enabled))
                     .strong(),
               );
               ui.label(RichText::new(duration_label(rule.duration)).color(base));
               ui.label(RichText::new(rule.hits.to_string()).color(base));
               ui.label(RichText::new(matched_label(rule.last_matched)).monospace().color(base));

               let label = if confirm.is_armed(&rule.id) {
                  "Confirm?"
               } else {
                  "Delete"
               };
               if ui.button(label).clicked() {
                  delete_clicked = true;
                  if confirm.click(&rule.id) {
                     actions.deletes.push(rule.id.clone());
                  }
               }
               ui.end_row();
            }
         });
      grid.response.rect
   });

   // A click in the table that is not a Delete click disarms the pending confirmation,
   // so an armed row cannot be deleted later by a stray click on another cell.
   let clicked = ui.input(|input| input.pointer.primary_clicked());
   let position = ui.input(|input| input.pointer.interact_pos());
   if clicked && !delete_clicked && position.is_some_and(|pos| table.inner.contains(pos)) {
      confirm.cancel();
   }

   actions
}

/// The application cell; an `Exe` rule also shows the path so the exact binary is visible.
fn application_cell(ui: &mut Ui, rule: &Rule, base: &Color32) {
   match &rule.app {
      AppMatcher::Exe(path) => {
         ui.vertical(|ui| {
            ui.label(RichText::new(app_label(&rule.app)).color(*base));
            ui.label(
               RichText::new(path.display().to_string())
                  .small()
                  .monospace()
                  .color(ui.visuals().weak_text_color()),
            );
         });
      }
      _ => {
         ui.label(RichText::new(app_label(&rule.app)).color(*base));
      }
   }
}

/// The verdict colour, desaturated for a disabled rule so it cannot look active.
fn action_colour(action: Action, enabled: bool) -> Color32 {
   let colour = match action {
      Action::Allow => ALLOWED,
      Action::Deny => DENIED,
   };
   if enabled {
      colour
   } else {
      colour.gamma_multiply(0.55)
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::path::PathBuf;

   #[test]
   fn app_label_names_the_scope() {
      assert_eq!(app_label(&AppMatcher::Any), "any application");
      assert_eq!(
         app_label(&AppMatcher::Exe(PathBuf::from(
            "/usr/bin/firefox"
         ))),
         "firefox"
      );
      assert_eq!(app_label(&AppMatcher::Unknown), "unknown");
   }

   #[test]
   fn dest_label_names_the_scope() {
      assert_eq!(dest_label(&DestMatcher::Any), "anywhere");
      assert_eq!(
         dest_label(&DestMatcher::Domain {
            host: "api.github.com".to_owned(),
            subdomains: false,
         }),
         "only api.github.com"
      );
      assert_eq!(
         dest_label(&DestMatcher::Domain {
            host: "github.com".to_owned(),
            subdomains: true,
         }),
         "*.github.com"
      );
      assert_eq!(
         dest_label(&DestMatcher::Ip("140.82.0.0/16".parse().unwrap())),
         "140.82.0.0/16"
      );
      assert_eq!(dest_label(&DestMatcher::Port(443)), "port 443");
   }

   #[test]
   fn action_and_duration_labels() {
      assert_eq!(action_label(Action::Allow), "allow");
      assert_eq!(action_label(Action::Deny), "deny");
      assert_eq!(duration_label(Duration::Once), "once");
      assert_eq!(duration_label(Duration::Session), "until restart");
      assert_eq!(duration_label(Duration::Forever), "forever");
      assert_eq!(matched_label(None), "—");
      assert_eq!(matched_label(Some(3661)), "01:01:01");
   }

   #[test]
   fn confirm_needs_the_same_id_twice() {
      let first = RuleId::new_unique();
      let second = RuleId::new_unique();
      let mut confirm = Confirm::default();

      assert!(!confirm.click(&first));
      assert!(confirm.is_armed(&first));

      assert!(!confirm.click(&second));
      assert!(!confirm.is_armed(&first));
      assert!(confirm.is_armed(&second));

      assert!(confirm.click(&second));
      assert!(!confirm.is_armed(&second));

      assert!(!confirm.click(&first));
      confirm.cancel();
      assert!(!confirm.is_armed(&first));
   }
}
