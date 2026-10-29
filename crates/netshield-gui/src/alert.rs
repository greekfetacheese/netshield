//! The interactive alert: one prompt rendered by both hosting modes.
//!
//! The panel is deliberately stateless about I/O. It draws into whatever `Ui` the host
//! gives it -- the root window in `--alert` mode, or a transient viewport in normal mode --
//! and returns the user's decision. [`AlertState`] holds the only mutable selection state,
//! and its default is the broad, safe decision the user can narrow.

use std::net::SocketAddr;
use std::path::Path;

use egui::{Color32, RichText, Ui};
use netshield_core::connection::Family;
use netshield_core::ipc::{ConnectionView, DecideRequest, PromptRequest, ScopeChoice};
use netshield_core::rule::{Action, Duration};

/// The host window's width; the panel never outgrows it.
pub const WIDTH: f32 = 480.0;

/// The host window's height. [`layout_height_estimate`] must stay below it.
///
/// Grown from 404 when the rule preview line was added, and from 440 when a grouped prompt
/// got the scope picker back: a group now draws the list *and* one scope row, so its stack is
/// no longer the shorter shape. The measured stack (with a queued prompt) is 410pt, and a
/// fixed viewport silently clips rather than scrolls, so the window grows once here instead
/// of resizing per prompt.
pub const HEIGHT: f32 = 462.0;

/// Inner margin of the alert panel, in points, applied on all four sides.
const PANEL_MARGIN: i8 = 14;

/// Extra gap at the top of the content, inside the panel margin.
const PANEL_TOP_GAP: f32 = 4.0;

/// The central panel's own margin around the alert frame, top plus bottom.
const PANEL_CHROME: f32 = 16.0;

/// Vertical gap between two sections.
const SECTION_GAP: f32 = 6.0;

/// Height of the bold process-name row.
const APP_ROW: f32 = 22.0;

/// Height of a default body line.
const BODY_ROW: f32 = 17.0;
/// Height of a small or monospace line.
const SMALL_ROW: f32 = 12.0;
/// Height of the destination line.
const DESTINATION_ROW: f32 = 26.0;
/// Height of one radio row, including the hit target.
const RADIO_ROW: f32 = 22.0;
/// Height of the `N more waiting` line.
const PENDING_ROW: f32 = 12.0;
/// Longest destination line drawn in the alert before it is elided; the list is one line
/// per destination and must not wrap into the buttons.
const DEST_LINE_CHARS: usize = 60;
/// Height of the countdown bar.
const COUNTDOWN_HEIGHT: f32 = 18.0;
/// Height of the Deny/Allow buttons.
const BUTTON_HEIGHT: f32 = 32.0;

/// Longest process name drawn before it is elided; the row must stay one line.
const APP_NAME_CHARS: usize = 30;

/// Character budget of the rule preview line. The alert is only 480pt wide, so the line
/// is elided to stay one line instead of wrapping into the buttons.
const RULE_PREVIEW_CHARS: usize = 60;

/// How many destinations the group list shows before the `+N more` remainder.
///
/// Three, not four: the scope control is drawn for a group too and costs one row, so the
/// list gives that row back. The panel is a fixed size, and a longer list would push the
/// action buttons past [`HEIGHT`] on the tallest shape.
pub const DEST_LINES: usize = 3;

/// Longest app name kept in the rule preview before it is elided.
const PREVIEW_APP_CHARS: usize = 20;

/// Longest host kept in the rule preview before it is elided.
const PREVIEW_HOST_CHARS: usize = 26;

/// Red fill of the Deny button. White text keeps the contrast well above 4.5:1.
const DENY_FILL: Color32 = Color32::from_rgb(0xB3, 0x2D, 0x2D);

/// Green fill of the Allow button.
const ALLOW_FILL: Color32 = Color32::from_rgb(0x2E, 0x8B, 0x45);

/// Both action buttons use white text on a saturated fill.
const BUTTON_TEXT: Color32 = Color32::WHITE;

/// Which destination scope the alert offers for one prompt.
///
/// `Any` is a rule for the app, not for the flow: the daemon turns it into
/// `DestMatcher::Any`. It is only offered for an attributed app, because for an
/// unattributed one it would allow every unattributed flow. `Address` is the fallback
/// that always works: it names the exact remote address of the flow being answered.
/// `TheseDestinations` is only offered for a group, where the daemon writes one rule per
/// listed destination instead of a rule for the whole app.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Scope {
   /// Any destination for this app; the default for an identified app.
   #[default]
   Any,
   /// The hostname the daemon learned for this address.
   Domain,
   /// The exact remote address of this flow.
   Address,
   /// Every destination the prompt listed, each scoped to itself; groups only.
   TheseDestinations,
}

/// One row of the scope picker: what selecting it writes, and the word it uses.
///
/// The list is derived from the prompt, never from how many destinations there are alone:
/// a group swaps the single-destination scopes for [`Scope::TheseDestinations`], and an
/// unattributed flow drops [`Scope::Any`] because the rule it writes would allow every
/// unattributed flow rather than that app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeOption {
   pub scope: Scope,
   pub label: String,
}

/// The scope rows offered for `prompt`, in display order.
///
/// The first row is the default and is what an untouched alert answers. A single
/// destination keeps its three scopes; a group offers the app-wide scope and the explicit
/// "these destinations" one, which is the only pair a grouped answer can honour.
pub fn scope_options(prompt: &PromptRequest) -> Vec<ScopeOption> {
   let mut options = Vec::new();
   if broad_scope_available(prompt) {
      options.push(ScopeOption {
         scope: Scope::Any,
         label: format!(
            "Any connection by {}",
            elide(&app_name(&prompt.connection), PREVIEW_APP_CHARS)
         ),
      });
   }
   if is_group(prompt) {
      options.push(ScopeOption {
         scope: Scope::TheseDestinations,
         label: format!(
            "These {} destinations",
            destinations(prompt).len()
         ),
      });
      return options;
   }
   if let Some(host) = offered_domain(prompt) {
      options.push(ScopeOption {
         scope: Scope::Domain,
         label: format!("Only {}", elide(host, PREVIEW_HOST_CHARS)),
      });
   }
   options.push(ScopeOption {
      scope: Scope::Address,
      label: "Only this address".to_owned(),
   });
   options
}

/// One answer to a prompt, ready to be turned into a [`DecideRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
   pub action: Action,
   pub duration: Duration,
   pub scope: ScopeChoice,
}

/// Selection state for one alert.
///
/// `duration` starts at `Session` ("until restart"). `scope` starts at `Any`, which is the
/// broad, app-wide decision for an attributed app; [`AlertState::effective_scope`] resolves
/// it per prompt, so an unattributed flow defaults to the narrowest destination scope that
/// is available instead. `Forever` stays selectable but is never the default: an accidental
/// click must not outlive the daemon.
#[derive(Debug)]
pub struct AlertState {
   pub duration: Duration,
   /// The user's selection; [`AlertState::effective_scope`] says whether it is available.
   pub scope: Scope,
   pub subdomains: bool,
}

impl AlertState {
   /// The default selection: `Session`, scoped to any connection by this app.
   pub fn new() -> Self {
      Self {
         duration: Duration::Session,
         scope: Scope::Any,
         subdomains: false,
      }
   }

   /// The selection that is actually available for `prompt`.
   ///
   /// `Scope::Any` is not available when the app was not attributed, a domain scope is only
   /// expressible when the daemon learned a hostname and offered it, and `TheseDestinations`
   /// only exists for a group. Resolving here rather than in the constructor keeps the default
   /// correct even though the host constructs the state before it sees the prompt, and keeps a
   /// selection made on one shape from sending a scope the current prompt cannot honour when a
   /// group growth replaces the payload under it.
   fn effective_scope(&self, prompt: &PromptRequest) -> Scope {
      let group = is_group(prompt);
      let broad = broad_scope_available(prompt);
      // What a selection the prompt cannot honour resolves to: the default shape of this
      // prompt. A group's default is the app-wide rule when the app is identified, because
      // that is the single rule that ends the prompting for the app.
      let fallback = || {
         if broad {
            Scope::Any
         } else if group {
            Scope::TheseDestinations
         } else if offered_domain(prompt).is_some() {
            Scope::Domain
         } else {
            Scope::Address
         }
      };
      // A group cannot express a single host or address: both rows it offers cover every
      // destination, so a narrow pick that arrives with a group growth (the payload is
      // replaced under the selection) resolves to the group's default rather than sending a
      // scope the picker cannot show.
      match self.scope {
         Scope::Any if !broad => fallback(),
         Scope::Any => Scope::Any,
         Scope::Domain if group || offered_domain(prompt).is_none() => fallback(),
         Scope::Domain => Scope::Domain,
         Scope::Address if group => fallback(),
         Scope::Address => Scope::Address,
         Scope::TheseDestinations if !group => fallback(),
         Scope::TheseDestinations => Scope::TheseDestinations,
      }
   }

   /// Builds the request body for `action`.
   ///
   /// A domain scope is only expressible when the daemon learned a hostname *and* offered
   /// it; otherwise the answer falls back to the scope [`AlertState::effective_scope`]
   /// resolved, never to a scope the user could not select. The scope alone decides the rule:
   /// [`Scope::Any`] is one rule for the app even on a group, and
   /// [`Scope::TheseDestinations`] is the only scope that writes one rule per destination.
   pub fn decision(&self, prompt: &PromptRequest, action: Action) -> DecideRequest {
      let scope = match self.effective_scope(prompt) {
         Scope::Any => ScopeChoice::AnyConnection,
         Scope::Domain => match offered_domain(prompt) {
            Some(host) => ScopeChoice::Domain {
               host: host.to_owned(),
               subdomains: self.subdomains,
            },
            // Resolving never yields `Domain` without an offered host; choose the
            // always-available narrow scope rather than unwrap in the alert.
            None => ScopeChoice::Address,
         },
         Scope::Address => ScopeChoice::Address,
         Scope::TheseDestinations => ScopeChoice::TheseDestinations,
      };

      DecideRequest {
         prompt_id: prompt.id,
         action,
         duration: self.duration,
         scope,
      }
   }
}

impl Default for AlertState {
   fn default() -> Self {
      Self::new()
   }
}

/// The alert's whole state, with no egui windowing in it: the host owns a viewport, this owns
/// what that viewport shows and what the answer is.
///
/// No host constructs it yet -- the deferred-viewport wiring is a separate change -- so the
/// binary would otherwise warn on every field and method. Only the tests use it today.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct AlertModel {
   prompt: Option<PromptRequest>,
   state: AlertState,
   deadline: Option<std::time::Instant>,
   raised: std::collections::HashSet<u64>,
   outgoing: Vec<DecideRequest>,
}

#[allow(dead_code)]
impl AlertModel {
   /// An idle model: no prompt, no countdown and nothing to send.
   pub fn new() -> Self {
      Self::default()
   }

   /// Shows `prompt`, resets the selection to the defaults, and starts its countdown.
   ///
   /// The daemon only activates one prompt at a time and queues the rest, so a prompt
   /// presented while another is active replaces it rather than waiting its turn.
   pub fn present(
      &mut self,
      prompt: PromptRequest,
      timeout: std::time::Duration,
      now: std::time::Instant,
   ) {
      self.state = AlertState::new();
      self.deadline = Some(now + timeout);
      self.prompt = Some(prompt);
   }

   /// Replaces the active prompt's payload with a newer copy of the same id.
   ///
   /// The daemon re-broadcasts a prompt as destinations join its group, so only the
   /// destination list changed. The selection and the countdown belong to the answer the
   /// user is composing and must survive the update; a different id is ignored because
   /// presenting and closing are the paths for a new prompt.
   pub fn replace_prompt(&mut self, prompt: PromptRequest) {
      if self.prompt.as_ref().is_some_and(|open| open.id == prompt.id) {
         self.prompt = Some(prompt);
      }
   }

   /// The active prompt, if any.
   pub fn prompt(&self) -> Option<&PromptRequest> {
      self.prompt.as_ref()
   }

   /// The live selection, for `alert::ui`.
   pub fn state_mut(&mut self) -> &mut AlertState {
      &mut self.state
   }

   /// Seconds left, for `alert::ui`'s `remaining`; `None` when no prompt is active.
   ///
   /// Saturates at `0.0`, never negative, so the countdown text and bar see one shape.
   pub fn remaining_secs(&self, now: std::time::Instant) -> Option<f32> {
      self.prompt.as_ref()?;
      let deadline = self.deadline?;
      Some(deadline.saturating_duration_since(now).as_secs_f32())
   }

   /// Whether the countdown has reached its deadline.
   pub fn is_expired(&self, now: std::time::Instant) -> bool {
      self.prompt.is_some() && self.deadline.is_some_and(|deadline| now >= deadline)
   }

   /// Returns the prompt id the first time it is called for that prompt, then `None`.
   /// This is the once-per-prompt guard for raising the window: never focus on every frame.
   pub fn raise_once(&mut self) -> Option<u64> {
      let id = self.prompt.as_ref()?.id;
      self.raised.insert(id).then_some(id)
   }

   /// Builds the `DecideRequest` from the current selection and queues it in `outgoing`.
   ///
   /// The request comes from [`AlertState::decision`], so it is exactly the rule the
   /// preview line describes. After queueing, the prompt stops being active.
   pub fn submit(&mut self, decision: Decision) {
      let Some(prompt) = self.prompt.as_ref() else {
         return;
      };
      let request = self.state.decision(prompt, decision.action);
      self.outgoing.push(request);
      self.clear();
   }

   /// Hands the queued requests to the host, leaving the buffer empty.
   pub fn take_outgoing(&mut self) -> Vec<DecideRequest> {
      std::mem::take(&mut self.outgoing)
   }

   /// Drops the active prompt (after an answer or an expiry) and the countdown.
   pub fn clear(&mut self) {
      self.prompt = None;
      self.deadline = None;
   }
}

/// The rule the current selections would write, as one line:
/// `allow firefox → anywhere · until restart`.
///
/// It renders exactly what [`AlertState::decision`] will send, never what the radios look
/// like: a scope that is not available for this prompt reads as the scope the decision
/// actually produces. On a group the list above the picker still shows what prompted the
/// question, but the sentence names the grant: `anywhere` for the app-wide default, `these N
/// destinations` only when that is the scope the click sends. Pure, so the wording is
/// testable without a window.
pub fn rule_preview(prompt: &PromptRequest, state: &AlertState, action: Action) -> String {
   let verb = match action {
      Action::Allow => "allow",
      Action::Deny => "deny",
   };
   let app = elide(&app_name(&prompt.connection), PREVIEW_APP_CHARS);
   let scope = preview_scope(prompt, state);
   let duration = duration_label(state.duration);
   elide(
      &format!("{verb} {app} → {scope} · {duration}"),
      RULE_PREVIEW_CHARS,
   )
}

/// The duration phrase shared by the preview and the grant sentence.
fn duration_label(duration: Duration) -> &'static str {
   match duration {
      Duration::Once => "once",
      Duration::Session => "until restart",
      Duration::Forever => "forever",
   }
}

/// The scope phrase the decision will produce, mirroring [`AlertState::decision`].
///
/// The app-wide scope reads as `anywhere`, which is what its rule holds. The address scope
/// renders as the bare address, matching what `DestMatcher::Ip` holds: there is no name to
/// prefix and no subdomain question, so `only` would add nothing. The group scope names the
/// count, because the click writes one rule for each of them.
fn preview_scope(prompt: &PromptRequest, state: &AlertState) -> String {
   match state.effective_scope(prompt) {
      Scope::Any => "anywhere".to_owned(),
      Scope::Address => prompt.connection.remote_ip.to_string(),
      Scope::Domain => match offered_domain(prompt) {
         Some(host) => {
            let host = elide(host, PREVIEW_HOST_CHARS);
            if state.subdomains {
               format!("only *.{host}")
            } else {
               format!("only {host}")
            }
         }
         // `effective_scope` never returns `Domain` without an offered host; state the
         // address scope it resolves to rather than inventing a name.
         None => prompt.connection.remote_ip.to_string(),
      },
      Scope::TheseDestinations => format!(
         "these {} destinations",
         destinations(prompt).len()
      ),
   }
}

/// The hostname the prompt learned and the daemon offered as a domain scope.
fn offered_domain(prompt: &PromptRequest) -> Option<&str> {
   prompt
      .connection
      .domain
      .as_deref()
      .filter(|host| !host.is_empty())
      .filter(|_| prompt.domain_scope_available)
}

/// Whether the app-wide scope may be offered for this prompt.
///
/// It must not be: the rule it writes is `AppMatcher::Unknown` + `DestMatcher::Any`, which
/// allows every unattributed flow rather than "that app". An unattributed connection is
/// recognised by the absent owner ids; the daemon builds the view with both empty for
/// `Attribution::Unknown`, and an attributed process always has a pid.
fn broad_scope_available(prompt: &PromptRequest) -> bool {
   prompt.connection.pid.is_some()
}

/// Every destination the answer covers, or the first one for an older daemon.
///
/// A current daemon always sends at least one entry; `dests` is empty only in a frame from
/// a daemon that predates it, where `connection` is the whole prompt.
pub fn destinations(prompt: &PromptRequest) -> Vec<&ConnectionView> {
   if prompt.dests.is_empty() {
      return vec![&prompt.connection];
   }
   prompt.dests.iter().collect()
}

/// Whether the answer covers more than one destination.
///
/// A group offers the app-wide scope and the explicit "these destinations" one. It has no
/// single host or address the narrower scopes could name, because the answer covers every
/// destination shown, so those scopes would silently drop the rest of the list.
pub fn is_group(prompt: &PromptRequest) -> bool {
   destinations(prompt).len() > 1
}

/// What the Allow button says the click grants.
///
/// It follows the selected scope, not the number of destinations the prompt listed: the
/// app-wide default on a group is one rule for the app and keeps the plain `Allow`, while
/// only an explicit "these N destinations" makes the click write one rule per destination.
pub fn allow_label(prompt: &PromptRequest, state: &AlertState) -> String {
   match state.effective_scope(prompt) {
      Scope::TheseDestinations => format!(
         "Allow {} destinations",
         destinations(prompt).len()
      ),
      Scope::Any | Scope::Domain | Scope::Address => "Allow".to_owned(),
   }
}

/// The destinations a group lists, capped at [`DEST_LINES`], plus the `· +N more` remainder.
///
/// Each entry is exactly the line the panel draws, so the cap is testable without a window.
/// A single destination draws no list at all: the header below the destination already
/// names it.
pub fn destination_lines(prompt: &PromptRequest) -> Vec<String> {
   let dests = destinations(prompt);
   if dests.len() <= 1 {
      return Vec::new();
   }
   let mut lines: Vec<String> = dests
      .iter()
      .take(DEST_LINES)
      .map(|view| {
         format!(
            "· {}",
            elide(&destination_label(view), DEST_LINE_CHARS)
         )
      })
      .collect();
   let hidden = dests.len().saturating_sub(DEST_LINES);
   if hidden > 0 {
      lines.push(format!("· +{hidden} more"));
   }
   lines
}

/// How the destination is named: the learned hostname, or the endpoint otherwise.
fn destination_label(view: &ConnectionView) -> String {
   view
      .domain
      .as_deref()
      .filter(|domain| !domain.is_empty())
      .map_or_else(|| endpoint(view), str::to_owned)
}

/// Draws the whole alert into `ui`. Returns the chosen decision, if any button was pressed.
///
/// The fixed layout is sized for the 480x462 host: app name, destination, duration, scope,
/// countdown and the two action buttons all fit without scrolling. The app row is drawn
/// first so a future section cannot push it off the top again; [`layout_height_estimate`]
/// is the budget that guards that. The scope picker is always drawn, a group included: a
/// group's list is visibly capped, and its default row is the app-wide rule that ends the
/// prompting for the app instead of writing one rule per address. There are no keyboard
/// shortcuts; Escape deliberately does nothing, because a stray key must not decide a
/// firewall rule.
pub fn ui(
   ui: &mut Ui,
   prompt: &PromptRequest,
   state: &mut AlertState,
   remaining_secs: f32,
) -> Option<Decision> {
   let view = &prompt.connection;
   let mut decision = None;

   // The constants exist to catch a section that outgrows the fixed host window; the
   // matching test below states the spare margin the real layout must leave.
   debug_assert!(
      layout_height_estimate() <= HEIGHT,
      "the alert layout outgrew its {HEIGHT}pt host window",
   );

   egui::Frame::default().inner_margin(PANEL_MARGIN).show(ui, |ui| {
      ui.add_space(PANEL_TOP_GAP);
      ui.spacing_mut().item_spacing.y = SECTION_GAP;

      // The app row goes first: the user must always know which program is asking.
      app_row(ui, view);
      if prompt.pending > 0 {
         ui.label(RichText::new(format!("{} more waiting", prompt.pending)).small().weak());
      }

      ui.add_space(SECTION_GAP);
      ui.label(RichText::new("wants to connect to").weak());
      destination(ui, view);
      if is_group(prompt) {
         destination_list(ui, prompt);
      }
      ui.label(RichText::new(protocol_line(view)).weak());

      ui.add_space(SECTION_GAP);
      duration_section(ui, state);

      ui.add_space(SECTION_GAP);
      scope_section(ui, prompt, state);

      ui.add_space(SECTION_GAP);
      let width = ui.available_width();
      ui.add(
         egui::ProgressBar::new(progress_fraction(
            remaining_secs,
            prompt.timeout_secs,
         ))
         .desired_width(width)
         .desired_height(COUNTDOWN_HEIGHT)
         .text(countdown_text(remaining_secs)),
      );

      ui.add_space(SECTION_GAP);
      ui.columns(2, |columns| {
         let deny =
            egui::Button::new(RichText::new("Deny").color(BUTTON_TEXT).strong()).fill(DENY_FILL);
         let deny_width = columns[0].available_width();
         if columns[0].add_sized(egui::vec2(deny_width, BUTTON_HEIGHT), deny).clicked() {
            decision = Some(decision_for(state, prompt, Action::Deny));
         }

         let allow = egui::Button::new(
            RichText::new(allow_label(prompt, state)).color(BUTTON_TEXT).strong(),
         )
         .fill(ALLOW_FILL);
         let allow_width = columns[1].available_width();
         if columns[1].add_sized(egui::vec2(allow_width, BUTTON_HEIGHT), allow).clicked() {
            decision = Some(decision_for(state, prompt, Action::Allow));
         }
      });
   });

   decision
}

/// Conservative vertical budget of the tallest panel the alert can draw, in points.
///
/// It is deliberately generous: a real render must fit the configured window with room to
/// spare, and the test below keeps a future section from silently clipping the app row.
/// The `pending` line is always counted, even though it only appears when prompts queue.
///
/// Every shape draws the scope picker now, so the group is no longer the shorter one: it
/// adds the capped destination list to a scope block that is a row shorter than the single
/// destination's (no domain checkbox). The budget is the taller of the two stacks, so neither
/// shape can outgrow the window the other one was sized for.
pub fn layout_height_estimate() -> f32 {
   layout_height(false).max(layout_height(true))
}

/// The stack of every section one prompt shape can draw; `group` adds the destination list
/// and drops the domain checkbox row from the scope block.
fn layout_height(group: bool) -> f32 {
   let mut sections = PENDING_ROW
      + SECTION_GAP
      + APP_ROW
      + SECTION_GAP
      + BODY_ROW
      + DESTINATION_ROW
      + SMALL_ROW
      + SECTION_GAP
      + SMALL_ROW
      + RADIO_ROW;
   if group {
      // The capped destination list plus its remainder line, and the scope block below it:
      // two radio rows (app-wide and "these N destinations"), no domain checkbox.
      sections += DEST_LINES as f32 * SMALL_ROW + SMALL_ROW;
      sections += SECTION_GAP + SMALL_ROW + 2.0 * RADIO_ROW + SECTION_GAP + SMALL_ROW;
   } else {
      // The scope label, its three radio rows (with the domain checkbox and the address
      // row) and the rule preview.
      sections += SECTION_GAP + SMALL_ROW + 3.0 * RADIO_ROW + SECTION_GAP + SMALL_ROW;
   }
   sections
      + SECTION_GAP
      + COUNTDOWN_HEIGHT
      + SECTION_GAP
      + BUTTON_HEIGHT
      + 2.0 * f32::from(PANEL_MARGIN)
      + PANEL_CHROME
      + PANEL_TOP_GAP
}

/// The process name, with the right-aligned owner ids when the daemon attributed it.
///
/// The name is elided rather than wrapped, so a long program name can never spill into
/// the destination's line.
fn app_row(ui: &mut Ui, view: &ConnectionView) {
   ui.horizontal(|ui| {
      let name = elide(&app_name(view), APP_NAME_CHARS);
      ui.add(egui::Label::new(RichText::new(name).size(20.0).strong()).truncate());

      let mut ids = Vec::new();
      if let Some(pid) = view.pid {
         ids.push(format!("pid {pid}"));
      }
      if let Some(uid) = view.uid {
         ids.push(format!("uid {uid}"));
      }
      if !ids.is_empty() {
         ui.with_layout(
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
               ui.label(RichText::new(ids.join(" · ")).small().weak());
            },
         );
      }
   });
}

/// Shortens `text` to at most `max_chars` characters, ending in `…` when it was cut.
///
/// Character-based so a multi-byte program name is never split mid-codepoint. Pure, so
/// the layout can trim a heading before egui ever measures it.
pub fn elide(text: &str, max_chars: usize) -> String {
   if max_chars == 0 {
      return String::new();
   }
   if text.chars().count() <= max_chars {
      return text.to_owned();
   }
   let kept: String = text.chars().take(max_chars - 1).collect();
   format!("{kept}…")
}

/// The destination: the learned hostname when there is one, the address otherwise.
fn destination(ui: &mut Ui, view: &ConnectionView) {
   let endpoint = endpoint(view);
   match view.domain.as_deref().filter(|domain| !domain.is_empty()) {
      Some(domain) => {
         ui.label(RichText::new(domain).size(22.0).strong());
         ui.label(RichText::new(endpoint).small().monospace().weak());
      }
      None => {
         ui.label(RichText::new(endpoint).size(20.0).strong().monospace());
         ui.label(RichText::new("no hostname was learned for this address").small().weak());
      }
   }
}

/// Lists a group's destinations under the header, capped at [`DEST_LINES`] with a
/// `· +N more` remainder.
///
/// One line per destination, so an answer's reach is visible instead of implied. The cap
/// keeps a large group from pushing the fixed panel past [`HEIGHT`]; the remainder line
/// still states how many destinations are not named.
fn destination_list(ui: &mut Ui, prompt: &PromptRequest) {
   for line in destination_lines(prompt) {
      ui.label(RichText::new(line).small().weak());
   }
}

/// `tcp · port 443`, plus the family when the flow is IPv6.
fn protocol_line(view: &ConnectionView) -> String {
   let mut line = format!(
      "{} · port {}",
      view.proto.as_str(),
      view.remote_port
   );
   if view.family == Family::V6 {
      line.push_str(" · ipv6");
   }
   line
}

/// The duration radios, under a muted `Duration` label.
///
/// Radios rather than a pill row: they say the three choices are mutually exclusive, and
/// there is no orphan `For` label left over from the old layout.
fn duration_section(ui: &mut Ui, state: &mut AlertState) {
   ui.label(RichText::new("Duration").small().weak());
   ui.horizontal(|ui| {
      for (value, label) in [
         (Duration::Once, "Once"),
         (Duration::Session, "Until restart"),
         (Duration::Forever, "Forever"),
      ] {
         ui.radio_value(&mut state.duration, value, label);
      }
   });
}

/// The scope radios, the subdomain opt-in when the domain row is offered, and the rule
/// preview.
///
/// The rows come from [`scope_options`], so the control is the same for one destination and
/// for a group and its first row is always the default. The muted `Scope` label keeps
/// `Any connection by <app>` from reading as a fourth duration option. That first label is
/// deliberately app-wide: the daemon turns `ScopeChoice::AnyConnection` into
/// `DestMatcher::Any`, i.e. *any destination for this app*, so calling it "This connection"
/// would promise a narrower rule than it writes. An unattributed flow gets no such row at
/// all, because with `AppMatcher::Unknown` that rule would allow *every* unattributed flow,
/// not this app. On a group the narrow row names the count instead of a host, because the
/// click writes one rule per listed destination. The subdomain checkbox follows the domain
/// row, indented to the radio's *text* rather than its circle, and stays disabled until that
/// scope is selected.
fn scope_section(ui: &mut Ui, prompt: &PromptRequest, state: &mut AlertState) {
   ui.label(RichText::new("Scope").small().weak());
   let selected = state.effective_scope(prompt);

   for option in scope_options(prompt) {
      ui.horizontal(|ui| {
         let row = ui.add(egui::RadioButton::new(
            selected == option.scope,
            option.label,
         ));
         if row.clicked() {
            state.scope = option.scope;
         }
      });

      // Directly under its radio, so the opt-in reads as part of that choice.
      if option.scope == Scope::Domain {
         let indent = ui.spacing().icon_width + ui.spacing().icon_spacing;
         ui.horizontal(|ui| {
            ui.add_space(indent);
            ui.add_enabled(
               selected == Scope::Domain,
               egui::Checkbox::new(&mut state.subdomains, "include subdomains"),
            );
         });
      }
   }

   // The line below the radios states the rule the current selections would write, so the
   // app-wide scope above cannot be mistaken for a single flow, and a group's default says
   // `anywhere` even though its destination list above still explains what was asked.
   ui.label(
      RichText::new(rule_preview(prompt, state, Action::Allow))
         .small()
         .monospace()
         .weak(),
   );
}

/// `Auto-deny in <n>s`, or the denying state once the deadline has passed.
///
/// A whole second is shown only while it is fully available (`59.4` reads as `59`), and
/// the final sub-second still reads as `1` so the countdown never says `0s` while the
/// prompt is still open.
fn countdown_text(remaining_secs: f32) -> String {
   if remaining_secs <= 0.0 {
      return "Denying…".to_owned();
   }
   let seconds = remaining_secs.floor().max(1.0);
   format!("Auto-deny in {seconds:.0}s")
}

/// The countdown bar's fraction, clamped to `0.0..=1.0`.
fn progress_fraction(remaining_secs: f32, timeout_secs: u64) -> f32 {
   if timeout_secs == 0 {
      return 0.0;
   }
   (remaining_secs / timeout_secs as f32).clamp(0.0, 1.0)
}

/// Converts [`AlertState::decision`] into the panel's return type.
fn decision_for(state: &AlertState, prompt: &PromptRequest, action: Action) -> Decision {
   let request = state.decision(prompt, action);
   Decision {
      action: request.action,
      duration: request.duration,
      scope: request.scope,
   }
}

/// The most human process name available, never an empty heading.
fn app_name(view: &ConnectionView) -> String {
   if !view.app_name.is_empty() {
      return view.app_name.clone();
   }
   view.exe.as_deref().and_then(|exe| Path::new(exe).file_name()).map_or_else(
      || "unknown".to_owned(),
      |name| name.to_string_lossy().into_owned(),
   )
}

/// `<ip>:<port>`, with brackets for IPv6.
fn endpoint(view: &ConnectionView) -> String {
   SocketAddr::new(view.remote_ip, view.remote_port).to_string()
}

#[cfg(test)]
mod tests {
   use std::net::{IpAddr, Ipv4Addr};

   use netshield_core::connection::L4Proto;

   use super::*;

   fn prompt(domain: Option<&str>, available: bool) -> PromptRequest {
      PromptRequest {
         id: 7,
         connection: ConnectionView {
            app_name: "firefox".to_owned(),
            exe: None,
            pid: Some(4242),
            uid: Some(1000),
            family: Family::V4,
            proto: L4Proto::Tcp,
            remote_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 185, 78)),
            remote_port: 443,
            local_port: 51_000,
            domain: domain.map(str::to_owned),
            domain_candidates: Vec::new(),
         },
         timeout_secs: 30,
         dests: Vec::new(),
         domain_scope_available: available,
         pending: 0,
      }
   }

   /// A destination view for a group, named by `domain` and otherwise independent.
   fn dest_view(app: &str, domain: &str, last_octet: u8) -> ConnectionView {
      ConnectionView {
         app_name: app.to_owned(),
         exe: None,
         pid: Some(4242),
         uid: Some(1000),
         family: Family::V4,
         proto: L4Proto::Tcp,
         remote_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 184, last_octet)),
         remote_port: 443,
         local_port: 51_000,
         domain: (!domain.is_empty()).then(|| domain.to_owned()),
         domain_candidates: Vec::new(),
      }
   }

   /// The six-destination group the brief asks the panel to describe.
   fn group_of_six() -> PromptRequest {
      let mut request = prompt(Some("accounts.google.com"), true);
      request.connection = dest_view("brave", "accounts.google.com", 74);
      request.dests = vec![
         request.connection.clone(),
         dest_view("brave", "ssl.gstatic.com", 75),
         dest_view("brave", "", 76),
         dest_view("brave", "www.google.com", 77),
         dest_view("brave", "fonts.gstatic.com", 78),
         dest_view("brave", "play.google.com", 79),
      ];
      request
   }

   /// The same prompt, but with no owner: the daemon's `Attribution::Unknown` view.
   fn unknown_prompt(domain: Option<&str>, available: bool) -> PromptRequest {
      let mut request = prompt(domain, available);
      request.connection.app_name = "unknown".to_owned();
      request.connection.pid = None;
      request.connection.uid = None;
      request
   }

   #[test]
   fn default_decision_is_session_and_any_connection() {
      let state = AlertState::new();
      let decision = state.decision(
         &prompt(Some("www.google.com"), true),
         Action::Allow,
      );
      assert_eq!(decision.duration, Duration::Session);
      assert_eq!(decision.scope, ScopeChoice::AnyConnection);
   }

   #[test]
   fn known_app_keeps_the_broad_default_and_all_three_scopes() {
      let request = prompt(Some("www.google.com"), true);
      let mut state = AlertState::new();
      assert_eq!(state.effective_scope(&request), Scope::Any);

      // The broad scope is still selectable after narrowing.
      state.scope = Scope::Address;
      assert_eq!(
         state.decision(&request, Action::Allow).scope,
         ScopeChoice::Address
      );
      state.scope = Scope::Any;
      assert_eq!(
         state.decision(&request, Action::Allow).scope,
         ScopeChoice::AnyConnection
      );
      assert_eq!(
         rule_preview(&request, &state, Action::Allow),
         "allow firefox → anywhere · until restart"
      );
      assert_eq!(
         rule_preview(&request, &state, Action::Deny),
         "deny firefox → anywhere · until restart"
      );
   }

   #[test]
   fn unknown_app_disables_the_broad_scope_and_defaults_to_the_learned_domain() {
      let request = unknown_prompt(Some("www.google.com"), true);
      assert!(
         !broad_scope_available(&request),
         "the broad scope must be unavailable"
      );

      let state = AlertState::new();
      assert_eq!(
         state.effective_scope(&request),
         Scope::Domain,
         "an unknown app with a hostname defaults to the domain scope"
      );
      assert_eq!(
         state.decision(&request, Action::Allow).scope,
         ScopeChoice::Domain {
            host: "www.google.com".to_owned(),
            subdomains: false,
         }
      );
   }

   #[test]
   fn unknown_app_without_a_hostname_defaults_to_the_address() {
      let request = unknown_prompt(None, false);
      let state = AlertState::new();
      assert_eq!(
         state.effective_scope(&request),
         Scope::Address,
         "without a hostname the narrow default is the exact address"
      );
      assert_eq!(
         state.decision(&request, Action::Allow).scope,
         ScopeChoice::Address
      );
   }

   #[test]
   fn unknown_app_never_falls_back_to_the_broad_scope() {
      // Even if something selected `Any`, the resolved answer stays narrow, so an
      // unattributed flow can never produce `AppMatcher::Unknown` + `DestMatcher::Any`.
      for request in [
         unknown_prompt(Some("www.google.com"), true),
         unknown_prompt(None, false),
         unknown_prompt(Some("www.google.com"), false),
      ] {
         let state = AlertState::new();
         assert_ne!(
            state.decision(&request, Action::Allow).scope,
            ScopeChoice::AnyConnection
         );
         assert!(
            !rule_preview(&request, &state, Action::Allow).contains("anywhere"),
            "the preview must not claim the broad scope"
         );
      }
   }

   #[test]
   fn unknown_app_preview_names_the_address_and_elides_none_of_it() {
      let request = unknown_prompt(Some("www.google.com"), true);
      let state = AlertState::new();
      assert_eq!(
         rule_preview(&request, &state, Action::Allow),
         "allow unknown → only www.google.com · until restart"
      );

      let mut address = AlertState::new();
      address.scope = Scope::Address;
      assert_eq!(
         rule_preview(&request, &address, Action::Allow),
         "allow unknown → 142.250.185.78 · until restart"
      );

      let request = unknown_prompt(None, false);
      assert_eq!(
         rule_preview(&request, &AlertState::new(), Action::Allow),
         "allow unknown → 142.250.185.78 · until restart"
      );
   }

   /// The required example: an IPv6 address renders as the destination it scopes to.
   #[test]
   fn address_preview_renders_an_ipv6_destination() {
      let mut request = unknown_prompt(None, false);
      request.connection.remote_ip = "2001:4860:482c:400::".parse().expect("an IPv6 address");
      request.connection.family = Family::V6;
      assert_eq!(
         rule_preview(&request, &AlertState::new(), Action::Allow),
         "allow unknown → 2001:4860:482c:400:: · until restart"
      );
   }

   #[test]
   fn rule_preview_matches_the_decision_it_previews() {
      let any = rule_preview(
         &prompt(Some("www.google.com"), true),
         &AlertState::new(),
         Action::Allow,
      );
      assert_eq!(any, "allow firefox → anywhere · until restart");

      let mut once = AlertState::new();
      once.scope = Scope::Domain;
      once.duration = Duration::Once;
      assert_eq!(
         rule_preview(
            &prompt(Some("www.google.com"), true),
            &once,
            Action::Allow
         ),
         "allow firefox → only www.google.com · once"
      );

      let mut forever = AlertState::new();
      forever.scope = Scope::Domain;
      forever.duration = Duration::Forever;
      forever.subdomains = true;
      assert_eq!(
         rule_preview(
            &prompt(Some("github.com"), true),
            &forever,
            Action::Allow
         ),
         "allow firefox → only *.github.com · forever"
      );
   }

   #[test]
   fn rule_preview_never_claims_an_unavailable_domain_scope() {
      let mut state = AlertState::new();
      state.scope = Scope::Domain;
      assert_eq!(
         rule_preview(
            &prompt(Some("www.google.com"), false),
            &state,
            Action::Allow
         ),
         "allow firefox → anywhere · until restart"
      );
   }

   #[test]
   fn rule_preview_elides_a_long_app_and_domain() {
      let mut request = prompt(
         Some("a-very-long-subdomain.and-a-long-domain.example.com"),
         true,
      );
      request.connection.app_name = "an-extremely-long-process-name-that-cannot-fit".to_owned();
      let mut state = AlertState::new();
      state.scope = Scope::Domain;
      let line = rule_preview(&request, &state, Action::Allow);
      assert!(
         line.chars().count() <= RULE_PREVIEW_CHARS,
         "preview over budget: {line}"
      );
      assert!(
         line.contains('…'),
         "expected an ellipsis in: {line}"
      );
   }

   #[test]
   fn domain_scope_uses_the_learned_host() {
      let mut state = AlertState::new();
      state.scope = Scope::Domain;
      let decision = state.decision(
         &prompt(Some("www.google.com"), true),
         Action::Allow,
      );
      assert_eq!(
         decision.scope,
         ScopeChoice::Domain {
            host: "www.google.com".to_owned(),
            subdomains: false,
         }
      );
   }

   #[test]
   fn domain_scope_never_invents_a_scope() {
      let mut state = AlertState::new();
      state.scope = Scope::Domain;

      let unavailable = state.decision(
         &prompt(Some("www.google.com"), false),
         Action::Deny,
      );
      assert_eq!(unavailable.scope, ScopeChoice::AnyConnection);

      let no_host = state.decision(&prompt(None, true), Action::Deny);
      assert_eq!(no_host.scope, ScopeChoice::AnyConnection);
   }

   #[test]
   fn subdomains_round_trip() {
      let mut state = AlertState::new();
      state.scope = Scope::Domain;
      state.subdomains = true;
      assert_eq!(
         state
            .decision(
               &prompt(Some("www.google.com"), true),
               Action::Allow
            )
            .scope,
         ScopeChoice::Domain {
            host: "www.google.com".to_owned(),
            subdomains: true,
         }
      );

      state.subdomains = false;
      assert_eq!(
         state
            .decision(
               &prompt(Some("www.google.com"), true),
               Action::Allow
            )
            .scope,
         ScopeChoice::Domain {
            host: "www.google.com".to_owned(),
            subdomains: false,
         }
      );
   }

   /// A group offers the choice that ends the prompting for the app, and the default is
   /// that choice: one rule for the app, never one rule per address.
   #[test]
   fn a_group_offers_any_connection_and_only_these_destinations() {
      let request = group_of_six();
      let state = AlertState::new();

      let options = scope_options(&request);
      assert_eq!(
         options.len(),
         2,
         "a group offers exactly two scopes"
      );
      assert_eq!(
         options.iter().map(|option| option.scope).collect::<Vec<_>>(),
         vec![Scope::Any, Scope::TheseDestinations],
         "the app-wide grant is first and the list scope second"
      );
      assert_eq!(options[0].label, "Any connection by brave");
      assert_eq!(options[1].label, "These 6 destinations");
      assert_eq!(
         state.effective_scope(&request),
         Scope::Any,
         "the app-wide grant is selected by default"
      );

      let decision = state.decision(&request, Action::Allow);
      assert_eq!(decision.scope, ScopeChoice::AnyConnection);
      assert_eq!(
         serde_json::to_value(&decision.scope).expect("serialisable scope"),
         serde_json::json!({ "kind": "any_connection" })
      );
   }

   /// The default on a group states the grant the click makes: the whole app, not the list.
   #[test]
   fn the_default_on_a_group_grants_the_whole_app() {
      let request = group_of_six();
      let state = AlertState::new();

      assert_eq!(allow_label(&request, &state), "Allow");
      assert_eq!(
         rule_preview(&request, &state, Action::Allow),
         "allow brave → anywhere · until restart"
      );
      assert!(
         !destination_lines(&request).is_empty(),
         "the list stays visible: it is what prompted the question"
      );
   }

   /// Switching to the list scope names the count in the button and the sentence, and sends
   /// the one scope that writes a rule per destination.
   #[test]
   fn choosing_these_destinations_states_the_list() {
      let request = group_of_six();
      let mut state = AlertState::new();
      state.scope = Scope::TheseDestinations;

      assert_eq!(
         allow_label(&request, &state),
         "Allow 6 destinations"
      );
      assert_eq!(
         rule_preview(&request, &state, Action::Allow),
         "allow brave → these 6 destinations · until restart"
      );
      let decision = state.decision(&request, Action::Allow);
      assert_eq!(decision.scope, ScopeChoice::TheseDestinations);
      assert_eq!(
         serde_json::to_value(&decision.scope).expect("serialisable scope"),
         serde_json::json!({ "kind": "these_destinations" })
      );
   }

   /// One destination with a learned name keeps all three scopes, unchanged.
   #[test]
   fn a_single_destination_keeps_its_three_scopes() {
      let request = prompt(Some("www.google.com"), true);
      let mut state = AlertState::new();

      let options = scope_options(&request);
      assert_eq!(options.len(), 3);
      assert_eq!(
         options.iter().map(|option| option.scope).collect::<Vec<_>>(),
         vec![Scope::Any, Scope::Domain, Scope::Address]
      );
      assert_eq!(options[0].label, "Any connection by firefox");
      assert_eq!(options[1].label, "Only www.google.com");
      assert_eq!(options[2].label, "Only this address");
      assert_eq!(allow_label(&request, &state), "Allow");
      assert!(
         destination_lines(&request).is_empty(),
         "one destination needs no list under the header"
      );

      state.scope = Scope::Domain;
      assert_eq!(
         state.decision(&request, Action::Allow).scope,
         ScopeChoice::Domain {
            host: "www.google.com".to_owned(),
            subdomains: false,
         }
      );
      state.scope = Scope::Address;
      assert_eq!(
         state.decision(&request, Action::Allow).scope,
         ScopeChoice::Address
      );
   }

   /// Without a learned name there is no domain row to offer, so the picker has two.
   #[test]
   fn a_single_destination_without_a_name_offers_two() {
      let request = prompt(None, false);
      let options = scope_options(&request);

      assert_eq!(options.len(), 2);
      assert_eq!(
         options.iter().map(|option| option.scope).collect::<Vec<_>>(),
         vec![Scope::Any, Scope::Address],
         "no domain row without a name"
      );
      assert_eq!(options[0].label, "Any connection by firefox");
      assert_eq!(options[1].label, "Only this address");
   }

   /// The required example: three named lines and a remainder, never more.
   #[test]
   fn the_list_is_capped_with_a_remainder() {
      let lines = destination_lines(&group_of_six());
      assert_eq!(
         lines,
         vec![
            "· accounts.google.com",
            "· ssl.gstatic.com",
            "· 142.250.184.76:443",
            "· +3 more",
         ]
      );
   }

   /// The required example: an older daemon's payload is a single destination.
   #[test]
   fn an_empty_dests_field_falls_back_to_the_first_destination() {
      let mut request = prompt(Some("accounts.google.com"), true);
      request.connection = dest_view("brave", "accounts.google.com", 74);
      assert!(request.dests.is_empty());

      assert_eq!(destinations(&request).len(), 1);
      assert_eq!(allow_label(&request, &AlertState::new()), "Allow");
      assert!(destination_lines(&request).is_empty());
      assert_eq!(
         rule_preview(&request, &AlertState::new(), Action::Allow),
         "allow brave → anywhere · until restart"
      );
   }

   #[test]
   fn tmp_measure_sections() {
      let ctx = egui::Context::default();
      crate::theme::install(&ctx);
      let input = egui::RawInput {
         screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(WIDTH, HEIGHT),
         )),
         ..Default::default()
      };
      let mut out: Vec<(&str, f32, f32)> = Vec::new();
      for pending in [0usize, 2] {
         let mut p = prompt(Some("www.google.com"), true);
         p.pending = pending;
         for _ in 0..3 {
            out.clear();
            let mut state = AlertState::new();
            let mut output = ctx.run_ui(input.clone(), |ctx| {
               egui::CentralPanel::default().show(ctx, |ui| {
                  let f = egui::Frame::default().inner_margin(PANEL_MARGIN).show(ui, |ui| {
                     ui.spacing_mut().item_spacing.y = SECTION_GAP;
                     let mut m = |ui: &mut Ui, name: &'static str, kind: u8| {
                        let a = ui.cursor().min.y;
                        match kind {
                           0 => app_row(ui, &p.connection),
                           1 => {
                              if p.pending > 0 {
                                 ui.label(
                                    RichText::new(format!("{} more waiting", p.pending))
                                       .small()
                                       .weak(),
                                 );
                              }
                           }
                           2 => {
                              ui.label(RichText::new("wants to connect to").weak());
                           }
                           3 => destination(ui, &p.connection),
                           4 => {
                              ui.label(RichText::new(protocol_line(&p.connection)).weak());
                           }
                           5 => duration_section(ui, &mut state),
                           6 => scope_section(ui, &p, &mut state),
                           7 => {
                              let width = ui.available_width();
                              ui.add(
                                 egui::ProgressBar::new(0.5)
                                    .desired_width(width)
                                    .desired_height(COUNTDOWN_HEIGHT)
                                    .text("Auto-deny in 18s"),
                              );
                           }
                           8 => {
                              ui.columns(2, |columns| {
                                 let w = columns[0].available_width();
                                 columns[0].add_sized(
                                    egui::vec2(w, BUTTON_HEIGHT),
                                    egui::Button::new(
                                       RichText::new("Deny").color(BUTTON_TEXT).strong(),
                                    )
                                    .fill(DENY_FILL),
                                 );
                                 let w = columns[1].available_width();
                                 columns[1].add_sized(
                                    egui::vec2(w, BUTTON_HEIGHT),
                                    egui::Button::new(
                                       RichText::new("Allow").color(BUTTON_TEXT).strong(),
                                    )
                                    .fill(ALLOW_FILL),
                                 );
                              });
                           }
                           9 => ui.add_space(SECTION_GAP),
                           _ => {}
                        }
                        out.push((name, a, ui.cursor().min.y - a));
                     };
                     m(ui, "app", 0);
                     m(ui, "pending", 1);
                     m(ui, "space", 9);
                     m(ui, "wants", 2);
                     m(ui, "dest", 3);
                     m(ui, "proto", 4);
                     m(ui, "space", 9);
                     m(ui, "duration", 5);
                     m(ui, "space", 9);
                     m(ui, "scope", 6);
                     m(ui, "space", 9);
                     m(ui, "countdown", 7);
                     m(ui, "space", 9);
                     m(ui, "buttons", 8);
                  });
                  let _ = f;
               });
            });
            output.textures_delta.clear();
         }
         println!("--- pending = {pending}");
         for (n, a, v) in &out {
            println!("{n:10} at {a:6.1} h={v:5.1}");
         }
      }
   }

   /// The panel's vertical budget must fit the host window with room to spare.
   ///
   /// [`layout_height_estimate`] counts every section but not this spare margin, so a
   /// section added without growing [`HEIGHT`] fails here instead of clipping the app row.
   /// A group is measured too: its capped destination list and its one-row-shorter scope
   /// block must stay inside the same fixed window as the full single-destination stack.
   #[test]
   fn layout_estimate_leaves_headroom_in_the_host_window() {
      const MARGIN: f32 = 24.0;
      let estimate = layout_height_estimate();
      assert!(
         HEIGHT > estimate + MARGIN,
         "layout estimate {estimate} + {MARGIN} margin must stay below HEIGHT {HEIGHT}"
      );
      let group = layout_height(true);
      assert!(
         group <= estimate,
         "the grouped stack {group} must fit the budget {estimate} it shares with the picker"
      );
      assert!(
         HEIGHT > group + MARGIN,
         "grouped stack {group} + {MARGIN} margin must stay below HEIGHT {HEIGHT}"
      );
      // The list cap is part of the budget: a fourth line would outgrow the fixed window.
      assert_eq!(
         destination_lines(&group_of_six()).len(),
         DEST_LINES + 1,
         "three lines plus the remainder is what the estimate counts"
      );
   }

   #[test]
   fn countdown_text_shows_whole_seconds_then_denies() {
      assert_eq!(countdown_text(59.4), "Auto-deny in 59s");
      assert_eq!(countdown_text(0.4), "Auto-deny in 1s");
      assert_eq!(countdown_text(0.0), "Denying…");
      assert_eq!(countdown_text(-1.0), "Denying…");
   }

   #[test]
   fn progress_fraction_is_clamped() {
      assert_eq!(progress_fraction(-5.0, 30), 0.0);
      assert_eq!(progress_fraction(0.0, 30), 0.0);
      assert_eq!(progress_fraction(15.0, 30), 0.5);
      assert_eq!(progress_fraction(60.0, 30), 1.0);
      assert_eq!(progress_fraction(1.0, 0), 0.0);
   }

   /// A fixed clock, so every model test is independent of wall time.
   fn clock() -> std::time::Instant {
      std::time::Instant::now()
   }

   #[test]
   fn present_starts_a_countdown_that_saturates_at_the_deadline() {
      let mut model = AlertModel::new();
      let start = clock();
      assert_eq!(
         model.remaining_secs(start),
         None,
         "an idle model has no countdown"
      );

      let timeout = std::time::Duration::from_secs(30);
      model.present(
         prompt(Some("www.google.com"), true),
         timeout,
         start,
      );

      assert_eq!(model.remaining_secs(start), Some(30.0));
      assert_eq!(
         model.remaining_secs(start + std::time::Duration::from_secs(10)),
         Some(20.0)
      );
      assert!(!model.is_expired(start + std::time::Duration::from_secs(29)));
      assert_eq!(
         model.remaining_secs(start + timeout),
         Some(0.0),
         "remaining must saturate at the deadline"
      );
      assert_eq!(
         model.remaining_secs(start + std::time::Duration::from_secs(90)),
         Some(0.0),
         "remaining must never go negative"
      );

      assert!(!model.is_expired(start + timeout - std::time::Duration::from_nanos(1)));
      assert!(model.is_expired(start + timeout));

      // A prompt presented while one is active replaces it and resets the selection.
      model.state_mut().duration = Duration::Forever;
      model.state_mut().scope = Scope::Domain;
      let mut next = prompt(Some("github.com"), true);
      next.id = 9;
      model.present(
         next.clone(),
         std::time::Duration::from_secs(10),
         start,
      );
      assert_eq!(model.prompt(), Some(&next));
      assert_eq!(model.state_mut().duration, Duration::Session);
      assert_eq!(model.state_mut().scope, Scope::Any);
      assert_eq!(model.remaining_secs(start), Some(10.0));
   }

   /// The daemon re-broadcasts a prompt as destinations join its group: the newer payload
   /// must reach the panel while the user's selection and countdown stay put.
   ///
   /// A growth also changes which scopes are offered, so a narrow pick made on the single
   /// destination must not survive as a scope the group's picker cannot show.
   #[test]
   fn replacing_a_prompt_keeps_the_selection_and_shows_the_grown_group() {
      let mut model = AlertModel::new();
      let now = clock();
      let single = prompt(Some("accounts.google.com"), true);
      assert_eq!(allow_label(&single, &AlertState::new()), "Allow");
      model.present(single, std::time::Duration::from_secs(30), now);
      model.state_mut().duration = Duration::Forever;

      model.replace_prompt(group_of_six());

      let presented = model.prompt().cloned().expect("the alert still has its prompt");
      assert_eq!(presented.dests.len(), 6);
      assert_eq!(
         model.state_mut().duration,
         Duration::Forever,
         "a growth must not reset what the user picked"
      );
      assert_eq!(
         model.remaining_secs(now),
         Some(30.0),
         "a growth must not restart the countdown"
      );
      assert_eq!(model.state_mut().scope, Scope::Any);
      assert_eq!(
         allow_label(&presented, model.state_mut()),
         "Allow",
         "the app-wide default on a group writes one rule for the app"
      );
      assert_eq!(
         rule_preview(&presented, model.state_mut(), Action::Allow),
         "allow brave → anywhere · forever"
      );
   }

   /// A payload for another id belongs to `present` and `clear`, never to a replacement.
   #[test]
   fn replacing_a_prompt_ignores_a_different_id() {
      let mut model = AlertModel::new();
      let now = clock();
      let single = prompt(Some("accounts.google.com"), true);
      model.present(
         single.clone(),
         std::time::Duration::from_secs(30),
         now,
      );

      let mut next = group_of_six();
      next.id = 8;
      model.replace_prompt(next);

      assert_eq!(model.prompt(), Some(&single));
   }

   #[test]
   fn raise_once_fires_once_per_prompt_and_again_for_a_new_id() {
      let mut model = AlertModel::new();
      let now = clock();
      assert_eq!(
         model.raise_once(),
         None,
         "nothing to raise while idle"
      );

      model.present(
         prompt(Some("www.google.com"), true),
         std::time::Duration::from_secs(30),
         now,
      );
      assert_eq!(model.raise_once(), Some(7));
      assert_eq!(model.raise_once(), None);

      let mut next = prompt(Some("github.com"), true);
      next.id = 9;
      model.present(next, std::time::Duration::from_secs(30), now);
      assert_eq!(model.raise_once(), Some(9));
      assert_eq!(model.raise_once(), None);
   }

   #[test]
   fn submit_queues_the_states_decision_and_clears_the_prompt() {
      let mut model = AlertModel::new();
      let now = clock();
      let request = prompt(Some("www.google.com"), true);
      model.present(
         request.clone(),
         std::time::Duration::from_secs(30),
         now,
      );
      model.state_mut().duration = Duration::Forever;
      model.state_mut().scope = Scope::Domain;

      let expected = model.state_mut().decision(&request, Action::Allow);
      model.submit(Decision {
         action: Action::Allow,
         duration: Duration::Forever,
         scope: ScopeChoice::AnyConnection,
      });

      assert_eq!(model.take_outgoing(), vec![expected.clone()]);
      assert_eq!(expected.prompt_id, 7);
      assert_eq!(expected.action, Action::Allow);
      assert_eq!(expected.duration, Duration::Forever);
      assert_eq!(
         expected.scope,
         ScopeChoice::Domain {
            host: "www.google.com".to_owned(),
            subdomains: false,
         }
      );
      assert!(model.prompt().is_none());
      assert_eq!(model.remaining_secs(now), None);
   }

   #[test]
   fn clear_without_submit_pushes_nothing() {
      let mut model = AlertModel::new();
      let now = clock();
      model.present(
         prompt(Some("www.google.com"), true),
         std::time::Duration::from_secs(30),
         now,
      );
      model.clear();

      assert!(model.prompt().is_none());
      assert!(!model.is_expired(now + std::time::Duration::from_secs(120)));
      assert!(model.take_outgoing().is_empty());
   }

   #[test]
   fn take_outgoing_empties_the_buffer() {
      let mut model = AlertModel::new();
      let now = clock();
      for id in [7u64, 9] {
         let mut request = prompt(Some("www.google.com"), true);
         request.id = id;
         model.present(request, std::time::Duration::from_secs(30), now);
         model.submit(Decision {
            action: Action::Deny,
            duration: Duration::Session,
            scope: ScopeChoice::AnyConnection,
         });
      }

      let drained = model.take_outgoing();
      assert_eq!(drained.len(), 2);
      assert_eq!(drained[0].prompt_id, 7);
      assert_eq!(drained[1].prompt_id, 9);
      assert!(
         model.take_outgoing().is_empty(),
         "the buffer must be empty after a take"
      );
   }
}
