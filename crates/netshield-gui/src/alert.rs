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
/// Grown from 404 when the rule preview line was added: the measured stack (with a queued
/// prompt) is 410pt, and a fixed viewport silently clips rather than scrolls.
pub const HEIGHT: f32 = 440.0;

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
/// Height of the countdown bar.
const COUNTDOWN_HEIGHT: f32 = 18.0;
/// Height of the Deny/Allow buttons.
const BUTTON_HEIGHT: f32 = 32.0;

/// Longest process name drawn before it is elided; the row must stay one line.
const APP_NAME_CHARS: usize = 30;

/// Character budget of the rule preview line. The alert is only 480pt wide, so the line
/// is elided to stay one line instead of wrapping into the buttons.
const RULE_PREVIEW_CHARS: usize = 60;

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

/// One answer to a prompt, ready to be turned into a [`DecideRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
   pub action: Action,
   pub duration: Duration,
   pub scope: ScopeChoice,
}

/// Selection state for one alert.
///
/// `duration` starts at `Session` ("until restart") and `scope_domain` starts `false`, so
/// the default is the broad decision: an app-wide rule that does not survive a restart,
/// which the user can narrow or make permanent. `Forever` stays selectable but is never
/// the default: an accidental click must not outlive the daemon.
pub struct AlertState {
   pub duration: Duration,
   pub scope_domain: bool,
   pub subdomains: bool,
}

impl AlertState {
   /// The default selection: `Session`, scoped to any connection by this app.
   pub fn new() -> Self {
      Self {
         duration: Duration::Session,
         scope_domain: false,
         subdomains: false,
      }
   }

   /// Builds the request body for `action`.
   ///
   /// A domain scope is only expressible when the daemon learned a hostname *and* offered
   /// it. Otherwise the answer is `AnyConnection`: a scope the user cannot express must
   /// never be silently invented.
   pub fn decision(&self, prompt: &PromptRequest, action: Action) -> DecideRequest {
      let host = prompt.connection.domain.as_deref().filter(|host| !host.is_empty());
      let scope = if self.scope_domain && prompt.domain_scope_available {
         host.map_or(ScopeChoice::AnyConnection, |host| {
            ScopeChoice::Domain {
               host: host.to_owned(),
               subdomains: self.subdomains,
            }
         })
      } else {
         ScopeChoice::AnyConnection
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

/// The rule the current selections would write, as one line:
/// `allow firefox → anywhere · until restart`.
///
/// It renders exactly what [`AlertState::decision`] will send, never what the radios look
/// like: a domain scope the daemon did not offer reads as `anywhere`, because that is the
/// scope the decision actually produces. Pure, so the wording is testable without a window.
pub fn rule_preview(prompt: &PromptRequest, state: &AlertState, action: Action) -> String {
   let verb = match action {
      Action::Allow => "allow",
      Action::Deny => "deny",
   };
   let app = elide(&app_name(&prompt.connection), PREVIEW_APP_CHARS);
   let scope = preview_scope(prompt, state);
   let duration = match state.duration {
      Duration::Once => "once",
      Duration::Session => "until restart",
      Duration::Forever => "forever",
   };
   elide(
      &format!("{verb} {app} → {scope} · {duration}"),
      RULE_PREVIEW_CHARS,
   )
}

/// The scope phrase the decision will produce, mirroring [`AlertState::decision`].
fn preview_scope(prompt: &PromptRequest, state: &AlertState) -> String {
   let host = prompt.connection.domain.as_deref().filter(|host| !host.is_empty());
   let Some(host) = host.filter(|_| state.scope_domain && prompt.domain_scope_available) else {
      return "anywhere".to_owned();
   };
   let host = elide(host, PREVIEW_HOST_CHARS);
   if state.subdomains {
      format!("only *.{host}")
   } else {
      format!("only {host}")
   }
}

/// Draws the whole alert into `ui`. Returns the chosen decision, if any button was pressed.
///
/// The fixed layout is sized for the 480x404 host: app name, destination, duration, scope,
/// countdown and the two action buttons all fit without scrolling. The app row is drawn
/// first so a future section cannot push it off the top again; [`layout_height_estimate`]
/// is the budget that guards that. There are no keyboard shortcuts; Escape deliberately
/// does nothing, because a stray key must not decide a firewall rule.
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

         let allow =
            egui::Button::new(RichText::new("Allow").color(BUTTON_TEXT).strong()).fill(ALLOW_FILL);
         let allow_width = columns[1].available_width();
         if columns[1].add_sized(egui::vec2(allow_width, BUTTON_HEIGHT), allow).clicked() {
            decision = Some(decision_for(state, prompt, Action::Allow));
         }
      });
   });

   decision
}

/// Conservative vertical budget of every section the panel can draw, in points.
///
/// It is deliberately generous: a real render must fit the configured window with room to
/// spare, and the test below keeps a future section from silently clipping the app row.
/// The `pending` line is always counted, even though it only appears when prompts queue.
pub fn layout_height_estimate() -> f32 {
   let sections = PENDING_ROW
      + SECTION_GAP
      + APP_ROW
      + SECTION_GAP
      + BODY_ROW
      + DESTINATION_ROW
      + SMALL_ROW
      + SECTION_GAP
      + SMALL_ROW
      + RADIO_ROW
      + SECTION_GAP
      + SMALL_ROW
      + RADIO_ROW
      + RADIO_ROW
      + SECTION_GAP
      + SMALL_ROW
      + SECTION_GAP
      + COUNTDOWN_HEIGHT
      + SECTION_GAP
      + BUTTON_HEIGHT;
   sections + 2.0 * f32::from(PANEL_MARGIN) + PANEL_CHROME + PANEL_TOP_GAP
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

/// The scope radios, the domain `Only <host>` applies to, the subdomain opt-in and the
/// rule preview.
///
/// The muted `Scope` label keeps `Any connection by this app` from reading as a fourth
/// duration option. That first label is deliberately app-wide: the daemon turns
/// `ScopeChoice::AnyConnection` into `DestMatcher::Any`, i.e. *any destination for this
/// app*, so calling it "This connection" would promise a narrower rule than it writes.
/// The domain label shares the radio's line so the choice reads as one sentence. The
/// subdomain checkbox is indented to the radio's *text*, not its circle, and stays
/// disabled until the domain scope is both offered and selected.
fn scope_section(ui: &mut Ui, prompt: &PromptRequest, state: &mut AlertState) {
   ui.label(RichText::new("Scope").small().weak());
   ui.radio_value(
      &mut state.scope_domain,
      false,
      "Any connection by this app",
   );

   let host = prompt.connection.domain.as_deref().filter(|host| !host.is_empty());
   ui.horizontal(|ui| {
      let enabled = prompt.domain_scope_available && host.is_some();
      let domain = ui.add_enabled(
         enabled,
         egui::RadioButton::new(
            state.scope_domain,
            host.map_or_else(
               || "Only this domain".to_owned(),
               |host| format!("Only {}", elide(host, PREVIEW_HOST_CHARS)),
            ),
         ),
      );
      if domain.clicked() {
         state.scope_domain = true;
      }
   });

   let indent = ui.spacing().icon_width + ui.spacing().icon_spacing;
   ui.horizontal(|ui| {
      ui.add_space(indent);
      ui.add_enabled(
         state.scope_domain && prompt.domain_scope_available,
         egui::Checkbox::new(&mut state.subdomains, "include subdomains"),
      );
   });

   // The line below the radios states the rule the current selections would write, so the
   // app-wide scope above cannot be mistaken for a single flow.
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
         domain_scope_available: available,
         pending: 0,
      }
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
   fn rule_preview_matches_the_decision_it_previews() {
      let any = rule_preview(
         &prompt(Some("www.google.com"), true),
         &AlertState::new(),
         Action::Allow,
      );
      assert_eq!(any, "allow firefox → anywhere · until restart");

      let mut once = AlertState::new();
      once.scope_domain = true;
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
      forever.scope_domain = true;
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
      state.scope_domain = true;
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
      state.scope_domain = true;
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
      state.scope_domain = true;
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
      state.scope_domain = true;

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
      state.scope_domain = true;
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
   #[test]
   fn layout_estimate_leaves_headroom_in_the_host_window() {
      const MARGIN: f32 = 24.0;
      let estimate = layout_height_estimate();
      assert!(
         HEIGHT > estimate + MARGIN,
         "layout estimate {estimate} + {MARGIN} margin must stay below HEIGHT {HEIGHT}"
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
}
