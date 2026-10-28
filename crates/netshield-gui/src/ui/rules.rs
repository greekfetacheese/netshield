//! The Rules page: the policy table, the delete-confirmation state and the rule editor.

use std::cell::Cell;

use egui::{Color32, RichText, Ui};
use egui_elements::{Button, ComboBox, Label, Modal};
use elegance::Switch;
use netshield_core::ipnet::IpNet;
use netshield_core::rule::{
   Action, AppMatcher, DestMatcher, Duration, Rule, RuleId, normalize_host,
};

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
   /// Rules whose `Edit` button was pressed; the caller opens the editor on the first.
   pub edits: Vec<Rule>,
   /// Rules the editor saved; the caller upserts them.
   pub upserts: Vec<Rule>,
}

/// The rule editor: the rule being edited (by id) and its draft values.
///
/// The draft is dropped by every way out of the modal -- Cancel, Escape, the backdrop and
/// the header's close button -- because the modal's own flags all flip the same `open`
/// bool this state is checked against.
#[derive(Default)]
pub struct Editor {
   draft: Option<Draft>,
}

impl Editor {
   /// Opens the editor on `rule`, replacing any draft already held.
   pub fn open(&mut self, rule: &Rule) {
      self.draft = Some(Draft::from_rule(rule));
   }

   /// Draws the modal, if a draft is held, and returns the rule to save when the user
   /// presses Save.
   ///
   /// Every other close -- Cancel, Escape, the backdrop, the header's close button --
   /// leaves `None` and drops the draft, so a reopened editor never inherits stale values.
   pub fn show(&mut self, ctx: &egui::Context, now: u64) -> Option<Rule> {
      let draft = self.draft.as_mut()?;
      let valid = Cell::new(false);
      let saved = Cell::new(false);
      let cancelled = Cell::new(false);
      // A held draft is an open modal; the modal's own flags (Escape, backdrop, close)
      // clear it during `show`, and Cancel is applied just below.
      let mut open = true;

      Modal::new("rule-editor", &mut open)
         .heading("Edit rule")
         .max_width(520.0)
         .footer(|ui| {
            if ui.add_enabled(valid.get(), Button::new("Save")).clicked() {
               saved.set(true);
            }
            if ui.add(Button::new("Cancel")).clicked() {
               // The modal's `open` flag is still borrowed by the builder here, so Cancel
               // is recorded and acted on once `show` has returned.
               cancelled.set(true);
            }
         })
         .show(ctx, |ui| {
            egui::Grid::new("rule-editor-fields").num_columns(2).spacing([16.0, 10.0]).show(
               ui,
               |ui| {
                  ui.label("Application");
                  application_field(ui, draft);
                  ui.end_row();

                  ui.label("Action");
                  action_field(ui, draft);
                  ui.end_row();

                  ui.label("Duration");
                  duration_field(ui, draft);
                  ui.end_row();

                  ui.label("Enabled");
                  ui.add(Switch::new(&mut draft.enabled, "Rule is active"));
                  ui.end_row();

                  ui.label("Scope");
                  scope_field(ui, draft);
                  ui.end_row();

                  let verdict = validate(draft);
                  if let Err(message) = &verdict {
                     let colour = ui.visuals().error_fg_color;
                     ui.label("");
                     ui.label(RichText::new(message).color(colour));
                     ui.end_row();
                  }
                  valid.set(verdict.is_ok());
               },
            );
         });

      if saved.get() && valid.get() {
         // The draft is consumed, so a reopened editor starts from the daemon's rule, not
         // from what this one contained.
         return self.draft.take().and_then(|draft| draft.into_rule(now).ok());
      }
      if cancelled.get() {
         // The footer cannot clear `open` while the modal borrows it, so the close is
         // applied here: one more `show` lets the modal see it and restore the focus it
         // took when it opened.
         open = false;
         let _ = Modal::new("rule-editor", &mut open).show(ctx, |_| {});
      }
      if !open {
         self.draft = None;
      }
      None
   }
}

/// Every editable field of a rule except the destination, which the scope draft models.
struct Draft {
   id: RuleId,
   app: AppMatcher,
   /// Read-only in the UI; carried through so the upsert does not change the rule's identity.
   note: Option<String>,
   created_at: u64,
   action: Action,
   duration: Duration,
   enabled: bool,
   scope: ScopeDraft,
   /// The daemon owns these counters; the draft only carries them so an upsert preserves
   /// them instead of resetting the rule's history.
   hits: u64,
   last_matched: Option<u64>,
}

impl Draft {
   fn from_rule(rule: &Rule) -> Self {
      Self {
         id: rule.id.clone(),
         app: rule.app.clone(),
         note: rule.note.clone(),
         created_at: rule.created_at,
         action: rule.action,
         duration: rule.duration,
         enabled: rule.enabled,
         scope: ScopeDraft::from_dest(&rule.dest),
         hits: rule.hits,
         last_matched: rule.last_matched,
      }
   }

   /// Rebuilds the rule this draft edits: the identity, note, creation time and counters
   /// come from the original, `updated_at` is stamped by the caller's clock.
   fn into_rule(self, now: u64) -> Result<Rule, String> {
      let dest = validate(&self)?;
      Ok(Rule {
         id: self.id,
         enabled: self.enabled,
         app: self.app,
         dest,
         action: self.action,
         duration: self.duration,
         note: self.note,
         created_at: self.created_at,
         updated_at: now,
         last_matched: self.last_matched,
         hits: self.hits,
      })
   }
}

/// The destination scope as the editor's widgets edit it.
enum ScopeDraft {
   Any,
   Domain { host: String, subdomains: bool },
   Ip { text: String },
   Port { text: String },
}

impl ScopeDraft {
   fn from_dest(dest: &DestMatcher) -> Self {
      match dest {
         DestMatcher::Any => Self::Any,
         DestMatcher::Domain { host, subdomains } => Self::Domain {
            host: host.clone(),
            subdomains: *subdomains,
         },
         DestMatcher::Ip(net) => Self::Ip {
            text: net.to_string(),
         },
         DestMatcher::Port(port) => Self::Port {
            text: port.to_string(),
         },
      }
   }

   fn kind(&self) -> ScopeKind {
      match self {
         Self::Any => ScopeKind::Any,
         Self::Domain { .. } => ScopeKind::Domain,
         Self::Ip { .. } => ScopeKind::Ip,
         Self::Port { .. } => ScopeKind::Port,
      }
   }

   /// Switches the scope kind, keeping the draft only when the kind did not change.
   fn switch(&mut self, kind: ScopeKind) {
      if self.kind() == kind {
         return;
      }
      *self = match kind {
         ScopeKind::Any => Self::Any,
         ScopeKind::Domain => Self::Domain {
            host: String::new(),
            subdomains: false,
         },
         ScopeKind::Ip => Self::Ip {
            text: String::new(),
         },
         ScopeKind::Port => Self::Port {
            text: String::new(),
         },
      };
   }
}

/// The scope choices in the order the combo box lists them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
   Any,
   Domain,
   Ip,
   Port,
}

impl ScopeKind {
   const ALL: [Self; 4] = [Self::Any, Self::Domain, Self::Ip, Self::Port];

   fn label(self) -> &'static str {
      match self {
         Self::Any => "Anywhere",
         Self::Domain => "Domain",
         Self::Ip => "IP or CIDR",
         Self::Port => "Port",
      }
   }
}

/// The destination the draft's scope describes, or the message to show while it cannot.
fn validate(draft: &Draft) -> Result<DestMatcher, String> {
   match &draft.scope {
      ScopeDraft::Any => Ok(DestMatcher::Any),
      ScopeDraft::Domain { host, subdomains } => {
         let raw = host.trim();
         if raw.is_empty() {
            return Err("host is empty".to_owned());
         }
         let host = normalize_host(raw).map_err(|err| err.to_string())?;
         Ok(DestMatcher::Domain {
            host,
            subdomains: *subdomains,
         })
      }
      ScopeDraft::Ip { text } => text
         .trim()
         .parse::<IpNet>()
         .map(DestMatcher::Ip)
         .map_err(|_| "not a CIDR, e.g. 140.82.0.0/16".to_owned()),
      ScopeDraft::Port { text } => match text.trim().parse::<u16>() {
         Ok(port) if port > 0 => Ok(DestMatcher::Port(port)),
         _ => Err("port must be 1-65535".to_owned()),
      },
   }
}

/// The application row: read-only, because a rule's application is its identity here.
fn application_field(ui: &mut Ui, draft: &Draft) {
   ui.vertical(|ui| {
      ui.label(app_label(&draft.app));
      if let AppMatcher::Exe(path) = &draft.app {
         ui.label(RichText::new(path.display().to_string()).small().monospace().weak());
      }
   });
}

/// The verdict row: two buttons, one of which is always the selection.
fn action_field(ui: &mut Ui, draft: &mut Draft) {
   ui.horizontal(|ui| {
      for action in [Action::Allow, Action::Deny] {
         let label = action_label(action);
         let selected = draft.action == action;
         if ui.add(Button::selectable(selected, label)).clicked() {
            draft.action = action;
         }
      }
   });
}

/// The duration row: the three durations the model offers, in the table's own wording.
fn duration_field(ui: &mut Ui, draft: &mut Draft) {
   ui.horizontal(|ui| {
      for duration in [Duration::Once, Duration::Session, Duration::Forever] {
         let selected = draft.duration == duration;
         if ui
            .add(Button::selectable(
               selected,
               duration_label(duration),
            ))
            .clicked()
         {
            draft.duration = duration;
         }
      }
   });
}

/// The scope row: the kind selector above the inputs that kind uses.
fn scope_field(ui: &mut Ui, draft: &mut Draft) {
   ui.vertical(|ui| {
      ComboBox::new(
         "rule-editor-scope",
         Label::new(draft.scope.kind().label(), None),
      )
      .width(160.0)
      .show_ui(ui, |ui| {
         for kind in ScopeKind::ALL {
            let selected = draft.scope.kind() == kind;
            if ui.add(Button::selectable(selected, kind.label())).clicked() {
               draft.scope.switch(kind);
            }
         }
      });

      match &mut draft.scope {
         ScopeDraft::Any => {}
         ScopeDraft::Domain { host, subdomains } => {
            ui.add(egui::TextEdit::singleline(host).hint_text("api.github.com"));
            ui.checkbox(subdomains, "include subdomains");
         }
         ScopeDraft::Ip { text } => {
            ui.add(egui::TextEdit::singleline(text).hint_text("140.82.0.0/16"));
         }
         ScopeDraft::Port { text } => {
            ui.add(egui::TextEdit::singleline(text).hint_text("443"));
         }
      }
   });
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

               ui.horizontal(|ui| {
                  if ui.add(Button::new("Edit").small()).clicked() {
                     actions.edits.push(rule.clone());
                  }
                  let label = if confirm.is_armed(&rule.id) {
                     "Confirm?"
                  } else {
                     "Delete"
                  };
                  if ui.add(Button::new(label).small()).clicked() {
                     delete_clicked = true;
                     if confirm.click(&rule.id) {
                        actions.deletes.push(rule.id.clone());
                     }
                  }
               });
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

/// The application cell: only the process name, with the full path on hover for an `Exe`
/// rule so the exact binary stays inspectable without costing a second line.
fn application_cell(ui: &mut Ui, rule: &Rule, base: &Color32) {
   let label = ui.label(RichText::new(app_label(&rule.app)).color(*base));
   if let AppMatcher::Exe(path) = &rule.app {
      label.on_hover_text(path.display().to_string());
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

   fn rule(dest: DestMatcher) -> Rule {
      Rule {
         id: RuleId::new_unique(),
         enabled: true,
         app: AppMatcher::Any,
         dest,
         action: Action::Allow,
         duration: Duration::Forever,
         note: Some("a note the editor must carry".to_owned()),
         created_at: 1_000,
         updated_at: 1_000,
         last_matched: Some(2_000),
         hits: 7,
      }
   }

   fn draft(scope: ScopeDraft) -> Draft {
      Draft {
         id: RuleId::new_unique(),
         app: AppMatcher::Any,
         note: None,
         created_at: 0,
         action: Action::Allow,
         duration: Duration::Once,
         enabled: true,
         scope,
         hits: 0,
         last_matched: None,
      }
   }

   #[test]
   fn validate_accepts_each_good_scope() {
      assert_eq!(
         validate(&draft(ScopeDraft::Domain {
            host: "API.GitHub.com.".to_owned(),
            subdomains: true,
         })),
         Ok(DestMatcher::Domain {
            host: "api.github.com".to_owned(),
            subdomains: true,
         })
      );
      assert_eq!(
         validate(&draft(ScopeDraft::Ip {
            text: " 140.82.0.0/16 ".to_owned(),
         })),
         Ok(DestMatcher::Ip("140.82.0.0/16".parse().unwrap()))
      );
      assert_eq!(
         validate(&draft(ScopeDraft::Port {
            text: "443".to_owned(),
         })),
         Ok(DestMatcher::Port(443))
      );
   }

   #[test]
   fn validate_names_what_is_wrong_with_bad_scope() {
      assert_eq!(
         validate(&draft(ScopeDraft::Domain {
            host: "   ".to_owned(),
            subdomains: false,
         })),
         Err("host is empty".to_owned())
      );
      for bad in ["140.82.0.0/33", "not an ip", "140.82.0.0/"] {
         assert_eq!(
            validate(&draft(ScopeDraft::Ip {
               text: bad.to_owned(),
            })),
            Err("not a CIDR, e.g. 140.82.0.0/16".to_owned()),
            "CIDR {bad:?} must be rejected"
         );
      }
      for bad in ["0", "70000", ""] {
         assert_eq!(
            validate(&draft(ScopeDraft::Port {
               text: bad.to_owned(),
            })),
            Err("port must be 1-65535".to_owned()),
            "port {bad:?} must be rejected"
         );
      }
   }

   #[test]
   fn draft_round_trips_a_domain_and_an_any_rule() {
      let domain = rule(DestMatcher::Domain {
         host: "github.com".to_owned(),
         subdomains: true,
      });
      let any = rule(DestMatcher::Any);

      for original in [domain, any] {
         let rebuilt = Draft::from_rule(&original)
            .into_rule(9_999)
            .expect("a rule the draft came from must validate");
         assert_eq!(rebuilt.id, original.id);
         assert_eq!(rebuilt.app, original.app);
         assert_eq!(rebuilt.dest, original.dest);
         assert_eq!(rebuilt.note, original.note);
         assert_eq!(rebuilt.created_at, original.created_at);
         assert_eq!(rebuilt.hits, original.hits);
         assert_eq!(rebuilt.last_matched, original.last_matched);
         assert_eq!(
            rebuilt.updated_at, 9_999,
            "an edit stamps the time it was saved"
         );
      }
   }

   #[test]
   fn a_cancelled_editor_leaves_no_draft() {
      let mut editor = Editor::default();
      editor.open(&rule(DestMatcher::Any));
      assert!(
         editor.draft.is_some(),
         "open must hold the rule's draft"
      );

      let ctx = egui::Context::default();
      let input = |events: Vec<egui::Event>| egui::RawInput {
         screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(980.0, 640.0),
         )),
         events,
         ..Default::default()
      };

      // Frame one: the modal opens and takes focus into itself, which the draft must
      // survive -- a closed modal must not be what every frame looks like.
      let output = ctx.run_ui(input(Vec::new()), |ctx| {
         assert_eq!(
            editor.show(ctx, 9_999),
            None,
            "Save was not pressed"
         );
      });
      output.drop_without_applying_deltas();
      assert!(
         editor.draft.is_some(),
         "an open modal keeps its draft"
      );
      assert!(
         ctx.memory(|memory| memory.focused()).is_some(),
         "the modal must have drawn and taken focus"
      );

      // Escape is the modal's own dismissal path: it flips the builder's `open` flag, and
      // the editor must drop the draft rather than keep it for the next opening.
      let output = ctx.run_ui(
         input(vec![egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
         }]),
         |ctx| {
            assert_eq!(editor.show(ctx, 9_999), None);
         },
      );
      output.drop_without_applying_deltas();
      assert!(
         editor.draft.is_none(),
         "a modal closed by Escape must leave no draft"
      );
   }

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
