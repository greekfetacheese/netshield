//! The application shell: navigation, the daemon poll and the current page.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use netshield_core::ipc::{DecideRequest, Mode, PromptRequest, Request, Response, StatusInfo};
use netshield_core::rule::Rule;

use crate::alert::{self, AlertModel, AlertState, Decision};
use crate::mock::{Mock, MockEvent};
use crate::ui;
use crate::{
   Cli,
   connlog::ConnectionLog,
   ipc::{self, Decider, IpcClient},
};

/// How many connection rows the history keeps before dropping the oldest.
const LOG_CAPACITY: usize = 500;

/// How often the GUI asks the daemon for a status snapshot.
const REFRESH_EVERY: Duration = Duration::from_secs(5);

/// How often the mock demo ticks: its events are generated inside `update`, so it has no
/// socket thread to wake it and must keep its own clock.
const POLL_EVERY: Duration = Duration::from_millis(200);

/// How often the main window repaints while a prompt is active or queued.
///
/// Belt and braces beside the socket thread's wake: the alert viewport repaints itself, but
/// registering it happens on the main window's frame path, so a lost wake-up must not be
/// able to strand a prompt until the user restores the window.
const PROMPT_REPAINT_EVERY: Duration = Duration::from_millis(500);

/// Red used by the offline banner; loud on purpose.
const BANNER_RED: egui::Color32 = egui::Color32::from_rgb(0xA8, 0x1F, 0x1F);

/// The slot the socket thread reads to wake the UI.
///
/// Empty until the first pass, because `App::new` runs before eframe hands the app a
/// `Context`. A minimised window gets no input and schedules no frames, so this wake is
/// what drains the queue and registers the alert viewport while it is iconified.
type UiWaker = Arc<Mutex<Option<egui::Context>>>;

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
   /// Selection state per prompt id, for the `--alert` root window.
   alerts: HashMap<u64, AlertState>,
   /// Wall-clock deadline per prompt id, for the `--alert` root window's countdown. The
   /// daemon enforces the timeout; this clock only drives the countdown.
   prompt_deadlines: HashMap<u64, Instant>,
   /// The floating alert's whole state, shared with the deferred viewport's paint callback,
   /// which runs outside the main window's frames.
   alert_model: Arc<Mutex<AlertModel>>,
   /// Answers prompts from inside the alert viewport, where the main window's frames --
   /// and therefore its own `IpcClient` sends -- do not run while it is minimised.
   decider: Decider,
   /// Last prompt whose window was raised, in both display modes, so the raise commands
   /// are sent once per prompt rather than every frame.
   last_alert_id: Option<u64>,
   /// Whether the `--alert` root window has been asked to hide already.
   alert_hidden: bool,
   /// Shared with the socket thread, which wakes the UI after every event it queues.
   ui_waker: UiWaker,
   /// The alert viewport's own context, published from inside its paint callback so the
   /// socket thread can show and repaint the alert without the main window's frames.
   alert_ctx: UiWaker,
   /// Whether the alert viewport is currently shown, shared across registrations: each
   /// `show_viewport_deferred` call installs a fresh closure, so the transition has to live
   /// on the app. It starts `true` because the builder creates the window visible, which is
   /// what gets the callback a first frame and publishes its context; that first idle paint
   /// is what hides it.
   alert_shown: Arc<std::sync::atomic::AtomicBool>,
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
      let ui_waker: UiWaker = Arc::new(Mutex::new(None));
      let alert_model: Arc<Mutex<AlertModel>> = Arc::new(Mutex::new(AlertModel::new()));
      let alert_ctx: UiWaker = Arc::new(Mutex::new(None));
      let alert_shown = Arc::new(std::sync::atomic::AtomicBool::new(true));
      let model_slot = Arc::clone(&alert_model);
      let ctx_slot = Arc::clone(&alert_ctx);
      let on_prompt = Arc::new(move |prompt: &PromptRequest| {
         let timeout = Duration::from_secs(prompt.timeout_secs);
         if let Ok(mut model) = model_slot.lock()
            && model.prompt().map(|open| open.id) != Some(prompt.id)
         {
            model.present(prompt.clone(), timeout, Instant::now());
         }
         if let Some(ctx) = ctx_slot.lock().ok().and_then(|slot| slot.clone()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
               ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(
                  centred_position(monitor, egui::vec2(alert::WIDTH, alert::HEIGHT)).into(),
               ));
            }
            ctx.request_repaint();
         }
      });
      let ipc = if cli.mock {
         None
      } else {
         // The thread wakes the UI through this slot; it stays empty until the first pass
         // stores the context, and the queued handshake is drained by that same pass.
         let wake_slot = Arc::clone(&ui_waker);
         let waker = Arc::new(move || {
            if let Some(ctx) = wake_slot.lock().ok().and_then(|slot| slot.clone()) {
               ctx.request_repaint();
            }
         });
         let client = IpcClient::spawn(cli.socket.clone(), waker, on_prompt);
         client.send(&Request::Subscribe);
         client.send(&Request::Status);
         client.send(&Request::ListRules);
         Some(client)
      };
      // In `--mock` there is no socket thread to send to, so the handle goes nowhere; the
      // alert still answers locally and the model is the only state that matters.
      let decider = ipc.as_ref().map_or_else(Decider::silent, IpcClient::decider);

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
         alert_model,
         decider,
         last_alert_id: None,
         alert_hidden: false,
         ui_waker,
         alert_ctx,
         alert_shown,
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
   ///
   /// The first call publishes the context into the waker slot: it cannot be done in
   /// `App::new`, which runs before eframe hands the app its `Context`.
   fn update(&mut self, ctx: &egui::Context) {
      if let Ok(mut slot) = self.ui_waker.lock()
         && slot.is_none()
      {
         *slot = Some(ctx.clone());
      }
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
   ///
   /// The prompt is also presented to the alert model, which starts its countdown. The
   /// daemon only activates one prompt at a time, so a later one replaces the active alert.
   fn enqueue_prompt(&mut self, prompt: PromptRequest) {
      if self.pending.iter().any(|queued| queued.id == prompt.id) {
         return;
      }
      let timeout = Duration::from_secs(prompt.timeout_secs);
      self.prompt_deadlines.insert(prompt.id, Instant::now() + timeout);
      self.alerts.insert(prompt.id, AlertState::new());
      if self.model().prompt().map(|open| open.id) != Some(prompt.id) {
         self.model().present(prompt.clone(), timeout, Instant::now());
      }
      self.pending.push(prompt);
   }

   /// Drops one prompt and its selection state; an unknown id is a no-op.
   fn remove_prompt(&mut self, id: u64) {
      self.pending.retain(|queued| queued.id != id);
      self.alerts.remove(&id);
      self.prompt_deadlines.remove(&id);
      let mut model = self.model();
      if model.prompt().is_some_and(|prompt| prompt.id == id) {
         model.clear();
      }
   }

   /// Seconds left on this prompt's deadline, as the `--alert` root window shows it.
   fn remaining_secs(&self, id: u64) -> f32 {
      self.prompt_deadlines.get(&id).map_or(0.0, |deadline| {
         deadline.saturating_duration_since(Instant::now()).as_secs_f32()
      })
   }

   /// The alert model, with a poisoned lock recovered rather than propagated: a panic in
   /// the paint callback must not wedge the daemon-facing part of the window.
   fn model(&self) -> std::sync::MutexGuard<'_, AlertModel> {
      self.alert_model.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
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

   /// Raises the alert for a newly active prompt, or hides the `--alert` root when the
   /// queue drains.
   ///
   /// This runs in `App::logic` because a hidden eframe window still ticks logic but runs
   /// no `ui` pass; the show command must therefore be sent from the logic side or a new
   /// prompt would keep the window hidden forever. Everything is guarded by `last_alert_id`:
   /// sent once per prompt, never every frame, because a repeated `Focus` steals the
   /// keyboard continuously while a prompt is open.
   ///
   /// Follows Zeus' `GUI::bring_to_front` for the `--alert` root only: unhide and unminimise
   /// it, then ask the window manager for critical attention. A floating alert has its own
   /// viewport, which does not exist yet at this point in the frame; it is activated,
   /// levelled and centred from inside its own closure instead (see [`Self::alert_window`]),
   /// and the main window is left completely alone. Answering a prompt is unchanged; this
   /// only raises it.
   fn alert_viewport(&mut self, ctx: &egui::Context) {
      let Some(first) = self.pending.first() else {
         // In normal mode the floating alert simply stops being shown; hiding the root
         // there would hide the main window.
         if self.alert && !self.alert_hidden {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.alert_hidden = true;
            self.last_alert_id = None;
         }
         return;
      };

      if self.last_alert_id == Some(first.id) {
         return;
      }

      if self.alert {
         // The root window *is* the alert, so it also takes the alert's own size and level.
         ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            alert::WIDTH,
            alert::HEIGHT,
         )));
      }

      // Only the `--alert` root is commanded here, because there it *is* the alert. A
      // floating prompt never commands the root at all: the main window keeps whatever
      // size, place and minimised state the user left it in, and the alert raises itself
      // from inside its own viewport (see `alert_window`).
      let root = egui::ViewportId::ROOT;
      if self.alert {
         ctx.send_viewport_cmd_to(root, egui::ViewportCommand::Minimized(false));
         ctx.send_viewport_cmd_to(root, egui::ViewportCommand::Visible(true));
         ctx.send_viewport_cmd_to(root, egui::ViewportCommand::Focus);
         ctx.send_viewport_cmd_to(
            root,
            egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Critical),
         );
         ctx.send_viewport_cmd_to(
            root,
            egui::ViewportCommand::WindowLevel(egui::WindowLevel::AlwaysOnTop),
         );
      }

      self.last_alert_id = Some(first.id);
      self.alert_hidden = false;
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

   /// Registers the alert's deferred viewport on every pass, prompt or not.
   ///
   /// This runs from `App::logic`, which eframe still calls for a minimised root window. A
   /// deferred viewport owns its own paint loop, so this registration is what keeps the
   /// alert alive -- and answering -- while the main window is iconified; registering it
   /// only once a prompt exists is a no-op there, because a viewport that has never been
   /// created cannot be shown by the socket thread. It is repeated every pass because egui
   /// drops any child viewport it was not shown in that pass; the same id and builder make
   /// that a no-op for the window itself. The callback hides the window while the model has
   /// no prompt.
   ///
   /// `--alert` mode is untouched: there the root window is already the alert.
   fn alert_window(&mut self, ctx: &egui::Context) {
      if self.alert {
         return;
      }
      let model = Arc::clone(&self.alert_model);
      let decider = self.decider.clone();
      let ctx_slot = Arc::clone(&self.alert_ctx);
      let visible = Arc::clone(&self.alert_shown);
      let size = egui::vec2(alert::WIDTH, alert::HEIGHT);
      let mut builder = egui::ViewportBuilder::default()
         .with_title("NetShield")
         .with_inner_size([alert::WIDTH, alert::HEIGHT])
         .with_resizable(false)
         .with_always_on_top()
         .with_visible(true)
         .with_active(true);
      if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
         builder = builder.with_position(centred_position(monitor, size));
      }
      ctx.show_viewport_deferred(alert_viewport_id(), builder, move |ui, _class| {
         let first = {
            let mut slot = ctx_slot.lock().ok();
            match slot.as_deref_mut() {
               Some(open) if open.is_none() => {
                  *open = Some(ui.ctx().clone());
                  true
               }
               _ => false,
            }
         };
         let _ = first;
         let open = model.lock().map(|m| m.prompt().is_some()).unwrap_or(false);
         let was = visible.swap(open, std::sync::atomic::Ordering::Relaxed);
         if open != was {
            ui.ctx().send_viewport_cmd(if open {
               egui::ViewportCommand::Visible(true)
            } else {
               egui::ViewportCommand::Visible(false)
            });
         }
         if open {
            paint_alert(ui, &model, &decider);
         }
      });
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
   /// Drains the daemon queue and, in `--alert` mode, drives the root window's visibility.
   ///
   /// eframe keeps calling this for a hidden window but skips [`Self::ui`], so the polling
   /// and the "a prompt arrived, show the window" command must live here. The root window
   /// is refreshed only through the socket thread's wake; only a pending prompt earns a
   /// timed repaint, because a lost wake-up would otherwise strand it until the next input.
   fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
      self.update(ctx);
      // `--mock` has no socket thread to wake it, so it keeps its own demo clock. A real
      // daemon wakes the UI per event; only a pending prompt earns a timed repaint, so a
      // lost wake-up cannot strand the alert until the user restores the window.
      let interval = if self.mock {
         Some(POLL_EVERY)
      } else if !self.pending.is_empty() || self.model().prompt().is_some() {
         Some(PROMPT_REPAINT_EVERY)
      } else {
         None
      };
      if let Some(interval) = interval {
         ctx.request_repaint_after(interval);
      }
      self.alert_viewport(ctx);
      self.alert_window(ctx);
   }

   fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
      if self.alert {
         self.root_alert(ui);
         return;
      }

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

/// The name the one alert viewport's id is hashed from.
///
/// A single id for every prompt: the window is registered once and reused, so each new
/// prompt paints into the existing alert rather than opening a duplicate window.
const ALERT_VIEWPORT: &str = "netshield-alert";

/// The one viewport the floating alert is shown in.
fn alert_viewport_id() -> egui::ViewportId {
   egui::ViewportId::from_hash_of(ALERT_VIEWPORT)
}

/// Draws the alert into its own viewport and delivers the answer.
///
/// A free function, not a closure over `App`: the callback must be `Send + Sync + 'static`,
/// and only the model and the send handle cross into it. Everything here -- raising,
/// drawing, submitting, expiring and sending -- must happen in this callback, because the
/// main window's `ui` pass does not run while it is minimised, which is exactly when the
/// alert still has to work.
fn paint_alert(ui: &mut egui::Ui, model: &std::sync::Mutex<AlertModel>, decider: &Decider) {
   let ctx = ui.ctx().clone();
   let mut model = model.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

   if model.raise_once().is_some() {
      ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
      ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
         egui::WindowLevel::AlwaysOnTop,
      ));
      ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
         egui::UserAttentionType::Critical,
      ));
      if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
         let size = egui::vec2(alert::WIDTH, alert::HEIGHT);
         ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(
            centred_position(monitor, size).into(),
         ));
      }
   }

   let Some(prompt) = model.prompt().cloned() else {
      return;
   };
   let remaining = model.remaining_secs(std::time::Instant::now()).unwrap_or(0.0);
   if let Some(decision) = alert::ui(ui, &prompt, model.state_mut(), remaining) {
      model.submit(decision);
   }
   if model.is_expired(std::time::Instant::now()) {
      model.clear();
   }
   // Sending belongs here rather than in `App::update`: while the main window is
   // minimised its update still runs, but a drain tied to that path would stall the
   // answer the moment the parent stopped painting.
   for request in model.take_outgoing() {
      if !decider.send(&Request::Decide(request)) {
         log::warn!("the ipc thread is gone; dropping a prompt answer");
      }
   }

   // The countdown and the selection both have to keep moving while the main window is
   // minimised, so ask for the next frame every frame; 10 Hz on a 480x440 window is cheap.
   ctx.request_repaint_after(std::time::Duration::from_millis(100));
}

/// Top-left position that centres a `size` window on a `monitor`.
///
/// egui 0.37 has no `ViewportCommand::Center`, so the alert computes it from the monitor
/// size. Clamped at `0.0`: a monitor smaller than the alert pins it to the top-left corner
/// instead of putting its title bar off-screen at a negative position.
fn centred_position(monitor: egui::Vec2, size: egui::Vec2) -> [f32; 2] {
   [
      ((monitor.x - size.x) / 2.0).max(0.0),
      ((monitor.y - size.y) / 2.0).max(0.0),
   ]
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
   use netshield_core::rule::Action;

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

   #[test]
   fn an_alert_is_centred_on_the_monitor() {
      let position = centred_position(
         egui::vec2(1920.0, 1080.0),
         egui::vec2(420.0, 260.0),
      );
      assert_eq!(position, [750.0, 410.0]);
   }

   #[test]
   fn a_monitor_smaller_than_the_alert_clamps_to_the_corner() {
      let position = centred_position(egui::vec2(300.0, 200.0), egui::vec2(420.0, 260.0));
      assert_eq!(position, [0.0, 0.0]);
   }

   #[test]
   fn a_queued_prompt_is_presented_to_the_alert_model() {
      let mut app = app();
      assert!(
         app.model().prompt().is_none(),
         "an idle app has no alert"
      );

      app.enqueue_prompt(prompt(1));
      let mut model = app.model();
      assert_eq!(model.prompt().map(|prompt| prompt.id), Some(1));
      assert!(
         model.remaining_secs(Instant::now()).is_some_and(|left| left > 29.0),
         "the countdown must start from the prompt's own timeout"
      );
      assert_eq!(
         model.raise_once(),
         Some(1),
         "a new prompt raises itself once"
      );
      assert_eq!(model.raise_once(), None, "and never twice");
   }

   #[test]
   fn queueing_an_already_presented_prompt_keeps_the_users_selection() {
      let mut app = app();
      // The socket thread's hook presents the prompt before the UI drains the queue; the
      // drain must recognise it by id and not rebuild the selection state around it.
      let timeout = Duration::from_secs(30);
      app.model().present(prompt(1), timeout, Instant::now());
      app.model().state_mut().duration = netshield_core::rule::Duration::Forever;

      app.enqueue_prompt(prompt(1));

      assert_eq!(app.pending.len(), 1);
      assert_eq!(
         app.model().state_mut().duration,
         netshield_core::rule::Duration::Forever,
         "presenting the same id twice must not reset the selection"
      );
   }

   #[test]
   fn the_model_keeps_the_latest_active_prompt() {
      let mut app = app();
      app.enqueue_prompt(prompt(1));
      app.enqueue_prompt(prompt(2));

      // The daemon activates one prompt at a time; the newest one owns the alert window.
      assert_eq!(
         app.model().prompt().map(|prompt| prompt.id),
         Some(2)
      );

      // Closing the queued prompt leaves the model alone: it is not the active one.
      app.remove_prompt(1);
      assert_eq!(
         app.model().prompt().map(|prompt| prompt.id),
         Some(2)
      );

      app.remove_prompt(2);
      assert!(app.model().prompt().is_none());
   }

   #[test]
   fn answering_from_the_viewport_queues_one_decision_and_closes_the_alert() {
      let mut app = app();
      app.enqueue_prompt(prompt(1));

      let decision = app.model().state_mut().decision(&prompt(1), Action::Deny);
      app.model().submit(Decision {
         action: decision.action,
         duration: decision.duration,
         scope: decision.scope,
      });

      let outgoing = app.model().take_outgoing();
      assert_eq!(outgoing.len(), 1);
      assert_eq!(outgoing[0].prompt_id, 1);
      assert!(
         app.model().prompt().is_none(),
         "a submitted prompt stops painting"
      );
   }
}
