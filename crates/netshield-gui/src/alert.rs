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
const WIDTH: f32 = 460.0;

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
/// `duration` starts at `Forever` and `scope_domain` starts `false`, so the default is
/// the broad decision: an allow writes a lasting rule, and a deny covers just this
/// connection unless the user explicitly narrows it.
pub struct AlertState {
   pub duration: Duration,
   pub scope_domain: bool,
   pub subdomains: bool,
}

impl AlertState {
   /// The default selection: `Forever`, scoped to this connection only.
   pub fn new() -> Self {
      Self {
         duration: Duration::Forever,
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

/// Draws the whole alert into `ui`. Returns the chosen decision, if any button was pressed.
///
/// The fixed layout is sized for the 460x260 host: destination, duration, scope, countdown
/// and the two action buttons all fit without scrolling. There are no keyboard shortcuts;
/// Escape deliberately does nothing, because a stray key must not decide a firewall rule.
pub fn ui(
   ui: &mut Ui,
   prompt: &PromptRequest,
   state: &mut AlertState,
   remaining_secs: f32,
) -> Option<Decision> {
   ui.set_max_width(WIDTH);
   ui.spacing_mut().item_spacing.y = 2.0;

   let view = &prompt.connection;
   let mut decision = None;

   if prompt.pending > 0 {
      ui.label(RichText::new(format!("{} more waiting", prompt.pending)).small().weak());
   }

   app_row(ui, view);
   ui.label(RichText::new("wants to connect to").weak());
   destination(ui, view);
   ui.label(RichText::new(protocol_line(view)).weak());

   duration_row(ui, state);
   scope_row(ui, prompt, state);

   ui.add(
      egui::ProgressBar::new(progress_fraction(
         remaining_secs,
         prompt.timeout_secs,
      ))
      .desired_height(12.0)
      .text(countdown_text(remaining_secs)),
   );

   ui.add_space(2.0);
   ui.with_layout(
      egui::Layout::right_to_left(egui::Align::Center),
      |ui| {
         let allow = egui::Button::new(RichText::new("Allow").color(BUTTON_TEXT).strong())
            .fill(ALLOW_FILL)
            .min_size(egui::vec2(130.0, 30.0));
         if ui.add(allow).clicked() {
            decision = Some(decision_for(state, prompt, Action::Allow));
         }

         let deny = egui::Button::new(RichText::new("Deny").color(BUTTON_TEXT).strong())
            .fill(DENY_FILL)
            .min_size(egui::vec2(130.0, 30.0));
         if ui.add(deny).clicked() {
            decision = Some(decision_for(state, prompt, Action::Deny));
         }
      },
   );

   decision
}

/// The process name, with the right-aligned owner ids when the daemon attributed it.
fn app_row(ui: &mut Ui, view: &ConnectionView) {
   ui.horizontal(|ui| {
      ui.heading(app_name(view));

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

/// `For` plus exactly one selected duration.
fn duration_row(ui: &mut Ui, state: &mut AlertState) {
   ui.horizontal(|ui| {
      ui.label("For");
      for (value, label) in [
         (Duration::Once, "Once"),
         (Duration::Session, "Until restart"),
         (Duration::Forever, "Forever"),
      ] {
         if ui.selectable_label(state.duration == value, label).clicked() {
            state.duration = value;
         }
      }
   });
}

/// The scope radios, the domain they will apply to, and the subdomain opt-in.
fn scope_row(ui: &mut Ui, prompt: &PromptRequest, state: &mut AlertState) {
   ui.horizontal(|ui| {
      ui.radio_value(&mut state.scope_domain, false, "This connection");
      let domain = ui.add_enabled(
         prompt.domain_scope_available,
         egui::RadioButton::new(state.scope_domain, "Only this domain"),
      );
      if domain.clicked() {
         state.scope_domain = true;
      }
   });

   if state.scope_domain
      && let Some(host) = prompt.connection.domain.as_deref().filter(|host| !host.is_empty())
   {
      ui.label(RichText::new(format!("Applies to {host}")).small().weak());
   }

   ui.add_enabled(
      state.scope_domain,
      egui::Checkbox::new(&mut state.subdomains, "include subdomains"),
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
   fn default_decision_is_forever_and_any_connection() {
      let state = AlertState::new();
      let decision = state.decision(
         &prompt(Some("www.google.com"), true),
         Action::Allow,
      );
      assert_eq!(decision.duration, Duration::Forever);
      assert_eq!(decision.scope, ScopeChoice::AnyConnection);
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
