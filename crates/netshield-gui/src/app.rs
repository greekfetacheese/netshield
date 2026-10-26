//! The application shell: navigation, the daemon poll and the current page.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use netshield_core::ipc::{DecideRequest, Mode, PromptRequest, Request, Response, StatusInfo};
use netshield_core::rule::Rule;

use crate::alert::{self, AlertState, Decision};
use crate::mock::{Mock, MockEvent};
use crate::ui;
use crate::{
   Cli,
   connlog::ConnectionLog,
   ipc::{self, IpcClient},
};

/// How many connection rows the history keeps before dropping the oldest.
const LOG_CAPACITY: usize = 500;

/// How often the GUI asks the daemon for a status snapshot.
const REFRESH_EVERY: Duration = Duration::from_secs(5);

/// How often the UI wakes so the socket queue is drained even when nothing is clicked.
const POLL_EVERY: Duration = Duration::from_millis(200);

/// Red used by the offline banner; loud on purpose.
const BANNER_RED: egui::Color32 = egui::Color32::from_rgb(0xA8, 0x1F, 0x1F);

/// Top-level application state.
pub struct App {
   page: Page,
   /// `None` in `--mock`, where no daemon is contacted.
   ipc: Option<IpcClient>,
   socket: PathBuf,
   connected: bool,
   log: ConnectionLog,
   mock: bool,
   /// `--alert`: the root window is the alert instead of the main navigation shell.
   alert: bool,
   /// Unanswered prompts in arrival order; only the first one has a window.
   pending: Vec<PromptRequest>,
   /// Selection state per prompt id; dropped together with the prompt.
   alerts: HashMap<u64, AlertState>,
   /// Wall-clock deadline per prompt id, derived from `timeout_secs` on arrival. The
   /// daemon enforces the timeout; this clock only drives the countdown.
   prompt_deadlines: HashMap<u64, Instant>,
   /// Last prompt the `--alert` root window was shown for, so the show/focus commands
   /// are sent once per prompt rather than every frame.
   last_alert_id: Option<u64>,
   /// Whether the `--alert` root window has been asked to hide already.
   alert_hidden: bool,
   /// Synthetic prompt and connection stream; always present in `--mock`.
   mock_stream: Mock,
   mode: Mode,
   /// Latest snapshot; `None` until the daemon answers the first `Status` request.
   status: Option<StatusInfo>,
   next_refresh: Instant,
   rules: Vec<Rule>,
   confirm: ui::rules::Confirm,
   /// Set when a mutation went out; the next update rewrites the rule list instead of
   /// waiting up to `REFRESH_EVERY` for the periodic tick.
   refresh_rules: bool,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Page {
   #[default]
   Connections,
   Rules,
   Settings,
   Status,
}

impl Page {
   const ALL: [Self; 4] = [Self::Connections, Self::Rules, Self::Settings, Self::Status];

   /// Label shown both in the navigation and as the page heading.
   fn name(self) -> &'static str {
      match self {
         Self::Connections => "Connections",
         Self::Rules => "Rules",
         Self::Settings => "Settings",
         Self::Status => "Status",
      }
   }
}

impl App {
   /// Builds the app and, outside mock mode, starts talking to the daemon.
   pub fn new(cli: Cli) -> Self {
      let ipc = if cli.mock {
         None
      } else {
         let client = IpcClient::spawn(cli.socket.clone());
         client.send(&Request::Subscribe);
         client.send(&Request::Status);
         client.send(&Request::ListRules);
         Some(client)
      };

      Self {
         page: Page::Connections,
         ipc,
         socket: cli.socket,
         connected: false,
         log: ConnectionLog::new(LOG_CAPACITY),
         mock: cli.mock,
         alert: cli.alert,
         pending: Vec::new(),
         alerts: HashMap::new(),
         prompt_deadlines: HashMap::new(),
         last_alert_id: None,
         alert_hidden: false,
         mock_stream: Mock::new(),
         mode: Mode::Alert,
         status: None,
         next_refresh: Instant::now() + REFRESH_EVERY,
         rules: Vec::new(),
         confirm: ui::rules::Confirm::default(),
         refresh_rules: false,
      }
   }

   /// Drains the socket queue (or the mock stream) and schedules the next periodic refresh.
   fn update(&mut self) {
      // Prompts are buffered rather than queued inside the drain: queueing needs `&mut
      // self`, and the drain holds an immutable borrow of the client.
      let mut arrived = Vec::new();
      let mut closed = Vec::new();
      if let Some(client) = &self.ipc {
         while let Some(event) = client.poll() {
            match event {
               ipc::IpcEvent::Connected(state) => self.connected = state,
               ipc::IpcEvent::Message(response) => match *response {
                  Response::Connection(event) => self.log.push(&event),
                  Response::Status(status) => {
                     self.mode = status.mode;
                     self.status = Some(status);
                  }
                  Response::Prompt(prompt) => arrived.push(prompt),
                  Response::PromptClosed { id, .. } => closed.push(id),
                  Response::Rules { rules } => self.rules = rules,
                  _ => {}
               },
            }
         }
      } else if self.mock {
         let now = Instant::now();
         for event in self.mock_stream.poll(now) {
            match event {
               MockEvent::Prompt(prompt) => self.enqueue_prompt(prompt),
               MockEvent::Closed(id) => self.remove_prompt(id),
            }
         }
         for event in self.mock_stream.connections(now) {
            self.log.push(&event);
         }
      }

      // A mutation invalidates the table; rewrite it now rather than on the slow tick.
      if self.refresh_rules {
         self.refresh_rules = false;
         if let Some(client) = &self.ipc {
            client.send(&Request::ListRules);
         }
      }

      for prompt in arrived {
         self.enqueue_prompt(prompt);
      }
      for id in closed {
         self.remove_prompt(id);
      }

      let now = Instant::now();
      if now < self.next_refresh {
         return;
      }
      if let Some(client) = &self.ipc {
         client.send(&Request::Status);
         client.send(&Request::ListRules);
      }
      self.next_refresh = now + REFRESH_EVERY;
   }

   /// Queues one prompt, ignoring an id that is already queued.
   fn enqueue_prompt(&mut self, prompt: PromptRequest) {
      if self.pending.iter().any(|queued| queued.id == prompt.id) {
         return;
      }
      let deadline = Instant::now() + Duration::from_secs(prompt.timeout_secs);
      self.prompt_deadlines.insert(prompt.id, deadline);
      self.alerts.insert(prompt.id, AlertState::new());
      self.pending.push(prompt);
   }

   /// Drops one prompt and its selection state; an unknown id is a no-op.
   fn remove_prompt(&mut self, id: u64) {
      self.pending.retain(|queued| queued.id != id);
      self.alerts.remove(&id);
      self.prompt_deadlines.remove(&id);
   }

   /// Sends one decision (or, in `--mock`, only logs it) and closes the prompt locally.
   fn answer(&mut self, ctx: &egui::Context, prompt_id: u64, decision: Decision) {
      let request = DecideRequest {
         prompt_id,
         action: decision.action,
         duration: decision.duration,
         scope: decision.scope,
      };
      if self.mock {
         log::info!(
            "mock: decided prompt {prompt_id} as {:?}",
            request.action
         );
      } else if let Some(client) = &self.ipc {
         client.send(&Request::Decide(request));
      }
      self.remove_prompt(prompt_id);
      ctx.request_repaint();
   }

   /// Seconds left on this prompt's deadline, as the panel shows it.
   fn remaining_secs(&self, id: u64) -> f32 {
      self.prompt_deadlines.get(&id).map_or(0.0, |deadline| {
         deadline.saturating_duration_since(Instant::now()).as_secs_f32()
      })
   }

   /// Shows the root window for a new prompt, or hides it once the queue is empty.
   ///
   /// This runs in `App::logic` because a hidden eframe window still ticks logic but runs
   /// no `ui` pass; the show command must therefore be sent from the logic side or a new
   /// prompt would keep the window hidden forever. Commands are sent once per prompt id,
   /// not every frame.
   fn alert_viewport(&mut self, ctx: &egui::Context) {
      let Some(first) = self.pending.first() else {
         if !self.alert_hidden {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.alert_hidden = true;
            self.last_alert_id = None;
         }
         return;
      };

      if self.last_alert_id != Some(first.id) {
         ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            alert::WIDTH,
            alert::HEIGHT,
         )));
         ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
         ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
            egui::WindowLevel::AlwaysOnTop,
         ));
         ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
         self.last_alert_id = Some(first.id);
         self.alert_hidden = false;
      }
   }

   /// Draws the oldest prompt into the root window.
   fn root_alert(&mut self, ui: &mut egui::Ui) {
      let Some(prompt) = self.pending.first().cloned() else {
         return;
      };
      let remaining = self.remaining_secs(prompt.id);
      let mut state = self.alerts.remove(&prompt.id).unwrap_or_default();
      let mut decision = None;
      egui::CentralPanel::default().show(ui, |ui| {
         decision = alert::ui(ui, &prompt, &mut state, remaining);
      });
      self.alerts.insert(prompt.id, state);

      if let Some(decision) = decision {
         self.answer(ui.ctx(), prompt.id, decision);
      }
   }

   /// The normal-mode host: the oldest prompt in its own always-on-top window.
   fn floating_alert(&mut self, ctx: &egui::Context) {
      let Some(prompt) = self.pending.first().cloned() else {
         return;
      };
      let remaining = self.remaining_secs(prompt.id);
      let mut state = self.alerts.remove(&prompt.id).unwrap_or_default();
      let builder = egui::ViewportBuilder::default()
         .with_title("NetShield")
         .with_inner_size([alert::WIDTH, alert::HEIGHT])
         .with_resizable(false)
         .with_always_on_top()
         .with_visible(true);

      let decision = ctx.show_viewport_immediate(
         egui::ViewportId::from_hash_of(("alert", prompt.id)),
         builder,
         |ctx, _| {
            let mut decision = None;
            egui::CentralPanel::default().show(ctx, |ui| {
               decision = alert::ui(ui, &prompt, &mut state, remaining);
            });
            decision
         },
      );

      self.alerts.insert(prompt.id, state);
      if let Some(decision) = decision {
         self.answer(ctx, prompt.id, decision);
      }
   }

   /// The loud offline banner, shown above the page content.
   fn banner(&self, ui: &mut egui::Ui) {
      if self.connected || self.mock {
         return;
      }
      egui::Panel::top("offline-banner")
         .resizable(false)
         .frame(egui::Frame::NONE.fill(BANNER_RED).inner_margin(egui::Margin::symmetric(12, 8)))
         .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
               egui::RichText::new(format!(
                  "Daemon not reachable at {} — retrying. Connections are NOT being filtered.",
                  self.socket.display()
               ))
               .color(egui::Color32::WHITE)
               .strong(),
            );
         });
   }

   /// Sidebar footer: connection state, policy mode and queued prompts.
   fn status_line(&self, ui: &mut egui::Ui) {
      let (dot, state) = if self.connected {
         ("●", "connected")
      } else if self.mock {
         ("○", "mock")
      } else {
         ("●", "offline")
      };
      let mut text = format!("{dot} {state}");
      if !self.mock {
         text.push_str(match self.mode {
            Mode::Alert => " · alert",
            Mode::Silent => " · silent",
         });
      }
      if !self.pending.is_empty() {
         text.push_str(&format!(" · {} waiting", self.pending.len()));
      }
      ui.label(egui::RichText::new(text).weak().small());
   }

   /// Sends the intents the Rules page collected, then re-lists so the table reflects
   /// the daemon's answer without waiting for the five-second tick.
   fn apply_actions(&mut self, actions: ui::rules::Actions) {
      if actions.toggles.is_empty() && actions.deletes.is_empty() {
         return;
      }
      let mut listed = false;
      if let Some(client) = &self.ipc {
         for (id, enabled) in actions.toggles {
            client.send(&Request::SetRuleEnabled { id, enabled });
         }
         for id in actions.deletes {
            client.send(&Request::DeleteRule { id });
         }
         // The daemon answers in order, so listing now reflects the mutations above
         // instead of leaving the table stale for up to a refresh interval.
         listed = client.send(&Request::ListRules);
      }
      // The queue is gone; retry the list on the next update.
      self.refresh_rules = !listed;
   }

   /// The selected page, or a placeholder for the slices that follow.
   fn page_content(&mut self, ui: &mut egui::Ui) {
      match self.page {
         Page::Connections => ui::connections::show(ui, &self.log),
         Page::Rules => {
            let actions = ui::rules::show(ui, &self.rules, &mut self.confirm);
            self.apply_actions(actions);
         }
         Page::Settings => {
            if let Some(mode) = ui::settings::show(ui, self.mode) {
               if let Some(client) = &self.ipc {
                  client.send(&Request::SetMode { mode });
               }
               // Move the radio at once instead of waiting a round trip for the daemon.
               self.mode = mode;
            }
         }
         Page::Status => ui::status::show(ui, self.status.as_ref(), unix_now()),
      }
   }
}

impl eframe::App for App {
   /// Polls the daemon and, in `--alert` mode, drives the root window's visibility.
   ///
   /// eframe keeps calling this for a hidden window but skips [`Self::ui`], so the polling
   /// and the "a prompt arrived, show the window" command must live here.
   fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
      self.update();
      ctx.request_repaint_after(POLL_EVERY);
      if self.alert {
         self.alert_viewport(ctx);
      }
   }

   fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
      if self.alert {
         self.root_alert(ui);
         return;
      }

      self.floating_alert(ui.ctx());

      egui::Panel::left("nav").exact_size(180.0).show(ui, |ui| {
         ui.add_space(8.0);
         for page in Page::ALL {
            if ui.selectable_label(self.page == page, page.name()).clicked() {
               self.page = page;
            }
         }
         ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(8.0);
            self.status_line(ui);
         });
      });

      self.banner(ui);

      egui::CentralPanel::default().show(ui, |ui| {
         self.page_content(ui);
      });
   }
}

/// Seconds since the unix epoch; the UI clock, never used for enforcement.
fn unix_now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
   use std::net::{IpAddr, Ipv4Addr};

   use netshield_core::connection::{Family, L4Proto};
   use netshield_core::ipc::ConnectionView;

   use super::*;

   fn app() -> App {
      App::new(Cli {
         socket: PathBuf::from("/nonexistent/control.sock"),
         mock: true,
         alert: false,
      })
   }

   fn prompt(id: u64) -> PromptRequest {
      PromptRequest {
         id,
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
            domain: Some("www.google.com".to_owned()),
            domain_candidates: Vec::new(),
         },
         timeout_secs: 30,
         domain_scope_available: true,
         pending: 0,
      }
   }

   #[test]
   fn a_duplicate_prompt_id_is_ignored() {
      let mut app = app();
      app.enqueue_prompt(prompt(1));
      app.enqueue_prompt(prompt(1));
      assert_eq!(app.pending.len(), 1);
      assert_eq!(app.alerts.len(), 1);
      assert_eq!(app.prompt_deadlines.len(), 1);
   }

   #[test]
   fn prompt_closed_removes_the_prompt_and_its_state() {
      let mut app = app();
      app.enqueue_prompt(prompt(1));
      app.enqueue_prompt(prompt(2));

      app.remove_prompt(1);
      assert_eq!(app.pending.len(), 1);
      assert_eq!(app.pending[0].id, 2);
      assert!(!app.alerts.contains_key(&1));
      assert!(!app.prompt_deadlines.contains_key(&1));
      assert!(app.alerts.contains_key(&2));
   }

   #[test]
   fn an_unknown_close_is_a_no_op() {
      let mut app = app();
      app.enqueue_prompt(prompt(1));
      app.remove_prompt(99);
      assert_eq!(app.pending.len(), 1);
   }
}
