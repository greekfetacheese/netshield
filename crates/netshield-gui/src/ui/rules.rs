//! The Rules page: the policy table, the delete-confirmation state and the rule editor.

use std::cell::Cell;

use egui::{Color32, RichText, Ui};
use egui_elements::{Button, ComboBox, Label, Modal};
use elegance::Switch;
use netshield_core::destlist::{dest_lines, parse_dest_lines};
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
      DestMatcher::Set(entries) => {
         let mut label = entries.iter().take(2).map(entry_label).collect::<Vec<_>>().join(", ");
         if entries.len() > 2 {
            label.push_str(&format!(" +{}", entries.len() - 2));
         }
         label
      }
   }
}

/// One entry of a list, without the phrasing a single-destination rule uses.
///
/// The table's `Destination` column has to stay readable, so a list reads `api.github.com,
/// *.example.org +3` rather than repeating "only" for every entry.
fn entry_label(entry: &DestMatcher) -> String {
   match entry {
      DestMatcher::Domain {
         host,
         subdomains: false,
      } => host.clone(),
      DestMatcher::Domain {
         host,
         subdomains: true,
      } => format!("*.{host}"),
      DestMatcher::Ip(net) => net.to_string(),
      DestMatcher::Port(port) => format!("port {port}"),
      DestMatcher::Any => "anywhere".to_owned(),
      // `from_entries` never nests, so this is only reachable for a rule a client invented.
      DestMatcher::Set(_) => "a list".to_owned(),
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
///
/// A rule scoped to one address and a rule scoped to twenty are the same thing to a person typing
/// them, so `Ip`, `Domain` and `Set` all become the one text list: the parser collapses a
/// single-line list back to the plain matcher, which keeps a rule `from_dest` read identical to
/// what `into_rule` writes.
enum ScopeDraft {
   Any,
   Destinations { text: String },
   Port { text: String },
}

impl ScopeDraft {
   fn from_dest(dest: &DestMatcher) -> Self {
      match dest {
         DestMatcher::Any => Self::Any,
         DestMatcher::Port(port) => Self::Port {
            text: port.to_string(),
         },
         DestMatcher::Ip(_) | DestMatcher::Domain { .. } | DestMatcher::Set(_) => {
            Self::Destinations {
               text: dest_lines(dest),
            }
         }
      }
   }

   fn kind(&self) -> ScopeKind {
      match self {
         Self::Any => ScopeKind::Any,
         Self::Destinations { .. } => ScopeKind::Destinations,
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
         ScopeKind::Destinations => Self::Destinations {
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
   Destinations,
   Port,
}

impl ScopeKind {
   const ALL: [Self; 3] = [Self::Any, Self::Destinations, Self::Port];

   fn label(self) -> &'static str {
      match self {
         Self::Any => "Anywhere",
         Self::Destinations => "IPs & domains",
         Self::Port => "Port",
      }
   }
}

/// The destination the draft's scope describes, or the message to show while it cannot.
fn validate(draft: &Draft) -> Result<DestMatcher, String> {
   match &draft.scope {
      ScopeDraft::Any => Ok(DestMatcher::Any),
      // The parser's message already names the offending line, which is the only way the user can
      // find the typo in a list of thirty entries.
      ScopeDraft::Destinations { text } => {
         parse_dest_lines(text).map_err(|error| error.to_string())
      }
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
         ScopeDraft::Destinations { text } => {
            ui.add(
               egui::TextEdit::multiline(text)
                  .font(egui::TextStyle::Monospace)
                  .desired_rows(6)
                  .desired_width(360.0)
                  .hint_text("api.github.com\n*.example.org\n140.82.0.0/16"),
            );
            ui.label(
               RichText::new("one IP, CIDR or domain per line; *.domain includes subdomains")
                  .small()
                  .weak(),
            );
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
   fn validate_accepts_good_scopes_and_rejects_bad_ones() {
      assert_eq!(
         validate(&draft(ScopeDraft::Destinations {
            text: "API.GitHub.com.\n*.example.org\n140.82.0.0/16\n::1".to_owned(),
         })),
         Ok(DestMatcher::Set(vec![
            DestMatcher::Domain {
               host: "api.github.com".to_owned(),
               subdomains: false,
            },
            DestMatcher::Domain {
               host: "example.org".to_owned(),
               subdomains: true,
            },
            DestMatcher::Ip("140.82.0.0/16".parse().unwrap()),
            DestMatcher::Ip("::1/128".parse().unwrap()),
         ])),
         "a mixed list is one scope and hosts are normalised"
      );
      assert_eq!(
         validate(&draft(ScopeDraft::Destinations {
            text: "  api.github.com  \n".to_owned(),
         })),
         Ok(DestMatcher::Domain {
            host: "api.github.com".to_owned(),
            subdomains: false,
         }),
         "a one-line list saves as the plain matcher"
      );
      assert_eq!(
         validate(&draft(ScopeDraft::Port {
            text: "443".to_owned(),
         })),
         Ok(DestMatcher::Port(443))
      );
      assert!(
         validate(&draft(ScopeDraft::Destinations {
            text: "   ".to_owned(),
         }))
         .is_err(),
         "an empty list is not a scope"
      );
      for bad in ["0", "70000", ""] {
         assert!(
            validate(&draft(ScopeDraft::Port {
               text: bad.to_owned(),
            }))
            .is_err(),
            "port {bad:?} must be rejected"
         );
      }
   }

   #[test]
   fn draft_round_trips_a_list_a_domain_a_port_and_an_any_rule() {
      let originals = [
         rule(DestMatcher::Set(vec![
            DestMatcher::Domain {
               host: "api.github.com".to_owned(),
               subdomains: false,
            },
            DestMatcher::Ip("10.0.0.0/8".parse().unwrap()),
            DestMatcher::Domain {
               host: "example.org".to_owned(),
               subdomains: true,
            },
         ])),
         rule(DestMatcher::Domain {
            host: "github.com".to_owned(),
            subdomains: true,
         }),
         rule(DestMatcher::Port(53)),
         rule(DestMatcher::Any),
      ];

      for original in originals {
         let rebuilt = Draft::from_rule(&original)
            .into_rule(9_999)
            .expect("a rule the draft came from must validate");
         assert_eq!(rebuilt.id, original.id);
         assert_eq!(rebuilt.app, original.app);
         assert_eq!(
            rebuilt.dest, original.dest,
            "an untouched scope must not change"
         );
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
   fn a_multi_line_scope_saves_as_one_set_rule() {
      let mut draft = draft(ScopeDraft::Destinations {
         text: "api.github.com\n*.example.org\n140.82.0.0/16".to_owned(),
      });
      draft.action = Action::Deny;

      let rule = draft.into_rule(9_999).expect("a well-formed list saves");
      assert_eq!(
         rule.dest,
         DestMatcher::Set(vec![
            DestMatcher::Domain {
               host: "api.github.com".to_owned(),
               subdomains: false,
            },
            DestMatcher::Domain {
               host: "example.org".to_owned(),
               subdomains: true,
            },
            DestMatcher::Ip("140.82.0.0/16".parse().unwrap()),
         ]),
         "three entries are one scope, in the order they were typed"
      );
      assert_eq!(rule.action, Action::Deny);
   }

   #[test]
   fn a_bad_line_is_reported_with_its_number() {
      let draft = draft(ScopeDraft::Destinations {
         text: "example.com\n\nnot a host".to_owned(),
      });
      let error = validate(&draft).expect_err("a bad line must not save");
      assert!(
         error.contains("line 3"),
         "the message must name the line that failed, got {error:?}"
      );
   }

   #[test]
   fn the_editor_seeds_a_list_rule_as_text() {
      let original = rule(DestMatcher::Set(vec![
         DestMatcher::Domain {
            host: "api.github.com".to_owned(),
            subdomains: false,
         },
         DestMatcher::Ip("10.0.0.0/8".parse().unwrap()),
         DestMatcher::Domain {
            host: "example.org".to_owned(),
            subdomains: true,
         },
      ]));

      let opened = Draft::from_rule(&original);
      assert!(
         matches!(
            &opened.scope,
            ScopeDraft::Destinations { text }
               if text == "api.github.com\n10.0.0.0/8\n*.example.org"
         ),
         "the editor opens a list as one line per entry, subdomains spelled *.host"
      );
      assert_eq!(
         opened.into_rule(9_999).expect("the seeded list validates").dest,
         original.dest
      );
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
