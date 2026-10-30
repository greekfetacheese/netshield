//! The application shell: navigation, the daemon poll and the current page.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use netshield_core::ipc::{
   DecideRequest, Mode, PromptRequest, Request, Response, ScopeChoice, StatusInfo,
};

use crate::alert::{self, AlertModel, AlertState, Decision};
use crate::mock::{Mock, MockEvent};
use crate::tray::{self, Action, Tray};
use crate::ui;
use crate::{
   Cli,
   connlog::ConnectionLog,
   ipc::{self, Decider, IpcClient},
   prefs::Prefs,
   ruleset::Ruleset,
   work,
};

/// How long a changed log cap waits before the preferences file is written, so one drag of a
/// slider is one write instead of one per frame.
const PREFS_SAVE_DELAY: Duration = Duration::from_millis(400);

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

/// The width of the navigation panel. Narrow on purpose: the Connections list is the page
/// that needs the pixels, and the four labels are short.
const NAV_WIDTH: f32 = 140.0;

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
   /// Whether the current connection state has been logged. The socket thread reports
   /// `Connected(false)` on every failed dial while it retries, and `connected` starts
   /// `false`, so comparing states alone would leave the first failure unrecorded -- the
   /// exact line that proves an autostarted GUI looked at the socket at all.
   connection_logged: bool,
   /// The Connections history; its caps come from `prefs` and change live from the
   /// Settings page.
   log: ConnectionLog,
   /// The GUI's own preferences: the log's caps, loaded from the user's config file at
   /// startup and written back when a slider moves.
   prefs: Prefs,
   /// When the caps changed last, if the file has not been written since. `None` means
   /// there is nothing to write.
   prefs_save_at: Option<Instant>,
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
   /// The inner height the alert viewport was last asked to take, if it has been asked yet.
   ///
   /// Shared with the deferred viewport's `'static` paint callback, which measures the panel
   /// and asks for the new height, and with the prompt hook that centres the window before
   /// it is painted. `None` means no measurement has happened, so the cap is the size.
   alert_height: Arc<Mutex<Option<f32>>>,
   /// Last prompt whose window was raised, in both display modes, so the raise commands
   /// are sent once per prompt rather than every frame.
   last_alert_id: Option<u64>,
   /// Whether the `--alert` root window has been asked to hide already.
   alert_hidden: bool,
   /// Shared with the socket thread, which wakes the UI after every event it queues. The
   /// prompt hook also shows the alert through it: viewport commands are addressed by id,
   /// so the socket thread needs no alert context of its own, and an unmapped window --
   /// whose paint callback never runs -- cannot strand a prompt.
   ui_waker: UiWaker,
   /// Whether the alert viewport is currently shown. It lives on the app because each
   /// `show_viewport_deferred` call installs a fresh closure, and it is driven from the
   /// main window's frames rather than the alert's own paint callback, which does not run
   /// while the window is unmapped.
   alert_shown: bool,
   /// Whether the deferred viewport's registration has been logged already. It is
   /// re-registered every pass by design, so logging each one would bury the transitions.
   alert_registered: bool,
   /// Synthetic prompt and connection stream; always present in `--mock`.
   mock_stream: Mock,
   mode: Mode,
   /// Latest snapshot; `None` until the daemon answers the first `Status` request.
   status: Option<StatusInfo>,
   next_refresh: Instant,
   /// The rule list as received, with the revision that moves whenever it is replaced; the
   /// Connections derivation keys on the pair.
   rules: Ruleset,
   confirm: ui::rules::Confirm,
   /// Which applications are expanded on the Connections page.
   connections_expanded: ui::connections::Expanded,
   /// Which applications are showing all their connections past the child cap.
   connections_showing_all: ui::connections::ShowingAll,
   /// Derived Connections lines, reused across frames until the log or rules change.
   connections_cache: ui::connections::LinesCache,
   /// The row whose details the Connections page shows in its right-hand pane.
   connections_selection: ui::connections::Selection,
   /// The rule editor and its draft, if one is open.
   editor: ui::rules::Editor,
   /// Set when a mutation went out; the next update rewrites the rule list instead of
   /// waiting up to `REFRESH_EVERY` for the periodic tick.
   refresh_rules: bool,
   /// The system tray, owned for the app's lifetime. `None` in `--alert` mode, which is a
   /// bare prompt window, and when the desktop has no StatusNotifier host.
   tray: Option<Tray>,
   /// Whether building the tray has been attempted. `App::new` runs before eframe hands
   /// the app a `Context`, so the tray is built on the first `logic` pass; this flag keeps
   /// a host-less machine from retrying every frame.
   tray_tried: bool,
   /// Whether this app hid the window to the tray. `ViewportCommand::Visible` is not
   /// echoed back into `ViewportInfo`, so this flag is the single source of truth.
   hidden_to_tray: bool,
   /// Whether the root window is somewhere the user can see it: not minimized and not
   /// hidden to the tray. Set on every pass from the same value the socket thread is told,
   /// and read by `ui` to skip drawing an unseen window -- a drawn frame re-arms the
   /// Connections page's one-second repaint timer, which is what kept a minimized window
   /// running a pass (and a paint) every second.
   attended: bool,
   /// Set when the tray asked to quit, so the close path below lets the close through
   /// instead of turning it into another hide.
   allow_close: bool,
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
      let prefs = Prefs::load();
      let ui_waker: UiWaker = Arc::new(Mutex::new(None));
      let alert_model: Arc<Mutex<AlertModel>> = Arc::new(Mutex::new(AlertModel::new()));
      let alert_height: Arc<Mutex<Option<f32>>> = Arc::new(Mutex::new(None));
      // Starts `true` to match the builder's `with_visible(true)`: the first frame then
      // hides an idle alert, and a prompt that arrived before that frame only re-shows it.
      let alert_shown = true;
      let model_slot = Arc::clone(&alert_model);
      let height_slot = Arc::clone(&alert_height);
      let ctx_slot = Arc::clone(&ui_waker);
      let on_prompt = Arc::new(move |prompt: &PromptRequest| {
         let timeout = Duration::from_secs(prompt.timeout_secs);
         // Only a prompt the model has not seen is presented here, so the window is raised
         // before the UI drains the queue. A re-broadcast of an open id is left to the
         // drain's in-place growth, which is the path that keeps its position and never
         // shrinks the list on a stale repeat.
         if let Ok(mut model) = model_slot.lock()
            && model.get(prompt.id).is_none()
         {
            model.present(
               with_destinations(prompt.clone()),
               timeout,
               Instant::now(),
            );
         }
         if let Some(ctx) = ctx_slot.lock().ok().and_then(|slot| slot.clone()) {
            let id = alert_viewport_id();
            ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Visible(true));
            if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
               let height = height_slot
                  .lock()
                  .unwrap_or_else(std::sync::PoisonError::into_inner)
                  .unwrap_or(alert::MAX_HEIGHT);
               ctx.send_viewport_cmd_to(
                  id,
                  egui::ViewportCommand::OuterPosition(
                     centred_position(monitor, egui::vec2(alert::WIDTH, height)).into(),
                  ),
               );
            }
            ctx.request_repaint();
         }
      });
      // The derivation thread wakes the UI exactly as the socket thread does: a finished rebuild
      // has to reach a frame even when no input does.
      let work_waker: ipc::Waker = {
         let wake_slot = Arc::clone(&ui_waker);
         Arc::new(move || {
            if let Some(ctx) = wake_slot.lock().ok().and_then(|slot| slot.clone()) {
               ctx.request_repaint();
            }
         })
      };
      let work = work::Worker::spawn(work_waker);
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
         connection_logged: false,
         log: ConnectionLog::new(prefs.rows_per_app, prefs.max_apps),
         prefs,
         prefs_save_at: None,
         mock: cli.mock,
         alert: cli.alert,
         pending: Vec::new(),
         alerts: HashMap::new(),
         prompt_deadlines: HashMap::new(),
         alert_model,
         decider,
         alert_height,
         last_alert_id: None,
         alert_hidden: false,
         ui_waker,
         alert_shown,
         alert_registered: false,
         mock_stream: Mock::new(),
         mode: Mode::Alert,
         status: None,
         next_refresh: Instant::now() + REFRESH_EVERY,
         rules: Ruleset::default(),
         confirm: ui::rules::Confirm::default(),
         connections_expanded: ui::connections::Expanded::default(),
         connections_showing_all: ui::connections::ShowingAll::default(),
         connections_cache: ui::connections::LinesCache::new(work),
         connections_selection: ui::connections::Selection::default(),
         editor: ui::rules::Editor::default(),
         refresh_rules: false,
         tray: None,
         tray_tried: false,
         hidden_to_tray: false,
         attended: true,
         allow_close: false,
      }
   }

   /// Builds the tray once, on the first pass, and applies whatever it has queued.
   ///
   /// This has to run in `logic`, not `ui`: eframe runs no egui pass while the window is
   /// hidden and calls `logic` instead, which is exactly the state the tray leaves the
   /// window in. A desktop without a StatusNotifier host builds no tray and keeps the
   /// window's normal close-with-no-tray behaviour.
   ///
   /// `--alert` mode is a bare prompt window: no tray, and its close is not intercepted.
   fn handle_tray(&mut self, ctx: &egui::Context) {
      if self.alert {
         return;
      }
      if self.tray.is_none() && !self.tray_tried {
         self.tray_tried = true;
         self.tray = Tray::new(ctx);
      }

      let Some(tray) = self.tray.as_mut() else {
         return;
      };
      for action in tray.drain() {
         match action {
            Action::Show => {
               self.hidden_to_tray = false;
               tray::show_window(ctx);
            }
            Action::OpenRules => {
               self.page = Page::Rules;
               self.hidden_to_tray = false;
               tray::show_window(ctx);
            }
            Action::Quit => {
               // The same close the window's button would send; `allow_close` keeps the
               // close path below from hiding the window it is trying to exit.
               self.allow_close = true;
               log::info!("quit requested from the tray");
               ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
         }
      }

      // The close button hides to the tray only when there is one; without a tray the
      // close must go through, or the process would be left running with no way back.
      if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close {
         ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
         self.hidden_to_tray = true;
         tray::hide_window(ctx);
         log::info!("window closed to tray");
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
      // eframe 0.37 runs a full ui pass and paints on every repaint request even when the root
      // window is iconified or hidden to the tray -- it decides that from `ViewportInfo::visible`,
      // which it only sets at construction, so a daemon event otherwise costs a whole frame.
      // While nobody is looking the socket thread keeps the traffic instead; the first pass
      // after the window is back installs it.
      let attended =
         !self.hidden_to_tray && !ctx.input(|input| input.viewport().minimized.unwrap_or(false));
      self.attended = attended;
      let mut events = Vec::new();
      if let Some(client) = &self.ipc {
         client.attend(attended);
         if attended {
            let (buffered, dropped) = client.take_backlog();
            if !buffered.is_empty() || dropped > 0 {
               log::debug!(
                  "installed {} event(s) buffered while the window was not on screen ({dropped} older ones dropped)",
                  buffered.len()
               );
            }
            events.extend(buffered);
         }
         while let Some(event) = client.poll() {
            events.push(event);
         }
      }
      for event in events {
         self.install(event);
      }

      if self.mock {
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

      // The alert's own paint callback answers, steps and expires prompts outside this
      // window's frames, so the local list is refreshed from the model it mutates before
      // anything here reads it.
      self.sync_pending();

      // A dragged cap changes on every frame; the file is written once the value settles.
      if let Some(at) = self.prefs_save_at
         && Instant::now() >= at
      {
         self.prefs_save_at = None;
         self.prefs.save();
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

   /// Records a connection transition and logs the first state, whichever it is.
   ///
   /// The first `false` is a transition worth a line even though `connected` already
   /// starts `false`; the retry loop repeats it every second, and only a change after the
   /// first report is news.
   fn set_connected(&mut self, connected: bool) {
      if !self.connection_logged || connected != self.connected {
         log::info!("daemon connected: {connected}");
         self.connection_logged = true;
      }
      self.connected = connected;
   }

   /// Applies one socket event to the app's state.
   ///
   /// Split out of the drain so the events kept for an unseen window are installed by the
   /// same code: `poll` borrows the client, so the drain collects and this applies.
   fn install(&mut self, event: ipc::IpcEvent) {
      match event {
         ipc::IpcEvent::Connected(state) => self.set_connected(state),
         ipc::IpcEvent::Message(response) => match *response {
            Response::Connection(event) => self.log.push(&event),
            Response::Status(status) => {
               self.mode = status.mode;
               self.status = Some(status);
            }
            Response::Prompt(prompt) => self.enqueue_prompt(prompt),
            Response::PromptClosed { id, .. } => self.remove_prompt(id),
            Response::Rules { rules } => self.rules.install(rules),
            _ => {}
         },
      }
   }

   /// Queues one prompt, replacing an earlier copy of the same id.
   ///
   /// The prompt is also presented to the alert model, which owns the local order and each
   /// prompt's own countdown. A newer prompt is appended behind the one on screen; the
   /// daemon publishes every prompt at once, so nothing here replaces the shown one.
   /// [`with_destinations`] fills the destination list before the prompt is stored, so the
   /// whole group the answer covers survives in the queue as well as in the alert.
   ///
   /// The daemon re-broadcasts the same id as destinations join its group, and the newer
   /// copy is the truth: it replaces the pending entry in place, keeping its queue position
   /// and the user's selection, but only when it names strictly more destinations, because
   /// a reordered or duplicated broadcast must not shrink the list. The displayed prompt
   /// earns a repaint; it must not raise or focus the window again.
   fn enqueue_prompt(&mut self, prompt: PromptRequest) {
      let prompt = with_destinations(prompt);
      if let Some(index) = self.pending.iter().position(|queued| queued.id == prompt.id) {
         if prompt.dests.len() <= self.pending[index].dests.len() {
            return;
         }
         log::info!(
            "prompt {} grew to {} destinations",
            prompt.id,
            prompt.dests.len()
         );
         // Same id, so the entry keeps its place and its selection: the window is already
         // up, and only its contents changed. The repaint is what makes the new
         // destinations and labels visible before the next scheduled frame.
         self.model().replace_prompt(prompt.clone());
         if self.model().prompt().map(|open| open.id) == Some(prompt.id)
            && let Some(ctx) = self.ui_waker.lock().ok().and_then(|slot| slot.clone())
         {
            ctx.request_repaint();
         }
         self.pending[index] = prompt;
         return;
      }
      log::info!(
         "prompt {} presented for {}",
         prompt.id,
         prompt.connection.app_name
      );
      let timeout = Duration::from_secs(prompt.timeout_secs);
      self.prompt_deadlines.insert(prompt.id, Instant::now() + timeout);
      self.alerts.insert(prompt.id, AlertState::new());
      self.model().present(prompt.clone(), timeout, Instant::now());
      self.pending.push(prompt);
   }

   /// Drops one prompt and its selection state; an unknown id is a no-op.
   fn remove_prompt(&mut self, id: u64) {
      let had = self.pending.iter().any(|queued| queued.id == id);
      self.pending.retain(|queued| queued.id != id);
      self.alerts.remove(&id);
      self.prompt_deadlines.remove(&id);
      // Removing the shown prompt advances the alert to whatever is first afterwards.
      self.model().remove(id);
      if had {
         log::info!("prompt {id} closed");
      }
   }

   /// Seconds left on this prompt's deadline, as the `--alert` root window shows it.
   fn remaining_secs(&self, id: u64) -> f32 {
      self.prompt_deadlines.get(&id).map_or(0.0, |deadline| {
         deadline.saturating_duration_since(Instant::now()).as_secs_f32()
      })
   }

   /// Applies a step between prompts to the model and mirrors its order into `pending`.
   ///
   /// Nothing is answered: the prompt keeps running on its own deadline in the daemon.
   fn step(&mut self, action: alert::AlertAction) {
      {
         let mut model = self.model();
         match action {
            alert::AlertAction::Later => model.later(),
            alert::AlertAction::Previous => model.previous(),
            alert::AlertAction::Decide(_) => return,
         }
      }
      self.sync_pending();
   }

   /// Copies the alert model's local order into `pending`, the list the rest of the app reads.
   ///
   /// The model owns the order (the paint callback steps and answers it outside this
   /// window's frames), so this is the one place the two copies are reconciled.
   fn sync_pending(&mut self) {
      let prompts = self.model().prompts().to_vec();
      self.pending = prompts;
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
      } else if let Some(client) = &self.ipc
         && client.send(&Request::Decide(request.clone()))
      {
         log::info!(
            "decision sent for prompt {prompt_id}: {:?}, {:?}, {}",
            request.action,
            request.duration,
            scope_kind(&request.scope)
         );
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
            log::debug!("alert root window hidden");
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
            alert::MAX_HEIGHT,
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

      // A floating alert raises itself from its own paint callback (see `paint_alert`), so
      // only the `--alert` root is shown from here.
      if self.alert {
         log::debug!("alert root window shown for prompt {}", first.id);
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
      let waiting = self.pending.len().saturating_sub(1);
      let mut state = self.alerts.remove(&prompt.id).unwrap_or_default();
      let mut action = None;
      egui::CentralPanel::default().show(ui, |ui| {
         action = alert::ui(ui, &prompt, &mut state, remaining, waiting);
      });
      self.alerts.insert(prompt.id, state);

      match action {
         Some(alert::AlertAction::Decide(decision)) => {
            self.answer(ui.ctx(), prompt.id, decision);
         }
         Some(alert::AlertAction::Later) => {
            self.step(alert::AlertAction::Later);
            ui.ctx().request_repaint();
         }
         Some(alert::AlertAction::Previous) => {
            self.step(alert::AlertAction::Previous);
            ui.ctx().request_repaint();
         }
         None => {}
      }
   }

   /// Registers the alert's deferred viewport on every pass, prompt or not, and keeps its
   /// visibility in step with the model.
   ///
   /// This runs from `App::logic`, which eframe still calls for a minimised root window. A
   /// deferred viewport owns its own paint loop, so this registration is what keeps the
   /// alert alive -- and answering -- while the main window is iconified; registering it
   /// only once a prompt exists is a no-op there, because a viewport that has never been
   /// created cannot be shown by the socket thread. It is repeated every pass because egui
   /// drops any child viewport it was not shown in that pass; the same id and builder make
   /// that a no-op for the window itself.
   ///
   /// The show/hide commands are addressed by id from here rather than sent from the
   /// paint callback: an unmapped window never runs its callback, so a hide or show that
   /// depended on one would never fire. They are idempotent, so the prompt hook sending
   /// `Visible(true)` as well is harmless.
   ///
   /// `--alert` mode is untouched: there the root window is already the alert.
   fn alert_window(&mut self, ctx: &egui::Context) {
      if self.alert {
         return;
      }
      let model = Arc::clone(&self.alert_model);
      let decider = self.decider.clone();
      let alert_height = Arc::clone(&self.alert_height);
      let size = egui::vec2(alert::WIDTH, alert::MAX_HEIGHT);
      let mut builder = egui::ViewportBuilder::default()
         .with_title("NetShield")
         .with_inner_size([alert::WIDTH, alert::MAX_HEIGHT])
         .with_resizable(false)
         .with_always_on_top()
         .with_visible(true)
         .with_active(true);
      if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
         builder = builder.with_position(centred_position(monitor, size));
      }
      ctx.show_viewport_deferred(alert_viewport_id(), builder, move |ui, _class| {
         if model.lock().map(|m| m.prompt().is_some()).unwrap_or(false) {
            paint_alert(ui, &model, &decider, &alert_height);
         }
      });
      // The registration above is repeated every pass by design, so only the first one is
      // worth a record; a missing one here is exactly the "no alert while minimised" bug.
      if !self.alert_registered {
         log::debug!("alert viewport registered");
         self.alert_registered = true;
      }

      let open = self.model().prompt().is_some();
      if open && !self.alert_shown {
         ctx.send_viewport_cmd_to(
            alert_viewport_id(),
            egui::ViewportCommand::Visible(true),
         );
         self.alert_shown = true;
         log::debug!("alert viewport shown");
      } else if !open && self.alert_shown {
         ctx.send_viewport_cmd_to(
            alert_viewport_id(),
            egui::ViewportCommand::Visible(false),
         );
         self.alert_shown = false;
         log::debug!("alert viewport hidden");
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

   /// The top bar: the product name, the mode switch and the daemon state.
   ///
   /// The switch collects an intent into a local because the panel closure borrows `self`;
   /// the intent is applied after the closure, exactly as the Settings page used to.
   fn toolbar(&mut self, ui: &mut egui::Ui) {
      let mut requested: Option<Mode> = None;

      egui::Panel::top("toolbar").exact_size(42.0).show(ui, |ui| {
         ui.horizontal_centered(|ui| {
            ui.add_space(12.0);
            ui.add(egui_elements::Label::new(
               egui::RichText::new("NetShield").strong().size(15.0),
               None,
            ));
            ui.with_layout(
               egui::Layout::right_to_left(egui::Align::Center),
               |ui| {
                  ui.add_space(12.0);
                  let mut ask = self.mode == Mode::Alert;
                  let switch = elegance::Switch::new(&mut ask, "Ask before connecting");
                  if ui.add_enabled(!self.mock, switch).changed() {
                     requested = Some(if ask { Mode::Alert } else { Mode::Silent });
                  }
                  ui.add_space(14.0);
                  let (state, label) = if self.connected {
                     (elegance::IndicatorState::On, "connected")
                  } else if self.mock {
                     (elegance::IndicatorState::Connecting, "mock")
                  } else {
                     (elegance::IndicatorState::Off, "offline")
                  };
                  ui.add(elegance::Indicator::new(state).size(9.0));
                  ui.add(egui_elements::Label::new(
                     egui::RichText::new(label).weak().small(),
                     None,
                  ));
               },
            );
         });
      });

      if let Some(mode) = requested {
         if let Some(client) = &self.ipc {
            client.send(&Request::SetMode { mode });
         }
         // Move the switch at once instead of waiting a round trip for the daemon.
         self.mode = mode;
         log::info!("operation mode -> {mode:?}");
      }
   }

   /// Sidebar footer: connection state and queued prompts.
   ///
   /// The mode is not repeated here: the top bar's switch is the one place that says it,
   /// and two copies invite them to disagree.
   fn status_line(&self, ui: &mut egui::Ui) {
      let (state, label) = if self.connected {
         (elegance::IndicatorState::On, "connected")
      } else if self.mock {
         (elegance::IndicatorState::Connecting, "mock")
      } else {
         (elegance::IndicatorState::Off, "offline")
      };
      let mut text = label.to_owned();
      if !self.pending.is_empty() {
         text.push_str(&format!(" · {} waiting", self.pending.len()));
      }
      ui.horizontal(|ui| {
         ui.add(elegance::Indicator::new(state).size(9.0));
         ui.add(egui_elements::Label::new(
            egui::RichText::new(text).weak().small(),
            None,
         ));
      });
   }

   /// Sends the intents the Rules page collected, then re-lists so the table reflects
   /// the daemon's answer without waiting for the five-second tick.
   ///
   /// A queued edit only opens the editor; it is not a mutation, so it never triggers a
   /// re-list on its own.
   fn apply_actions(&mut self, actions: ui::rules::Actions) {
      if let Some(rule) = actions.edits.first() {
         self.editor.open(rule);
      }
      if actions.toggles.is_empty() && actions.deletes.is_empty() && actions.upserts.is_empty() {
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
         for rule in actions.upserts {
            client.send(&Request::UpsertRule { rule });
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
         Page::Connections => ui::connections::show(
            ui,
            &self.log,
            &self.rules,
            &mut self.connections_expanded,
            &mut self.connections_showing_all,
            &mut self.connections_cache,
            &mut self.connections_selection,
         ),
         Page::Rules => {
            let actions = ui::rules::show(ui, self.rules.as_slice(), &mut self.confirm);
            self.apply_actions(actions);
            // Drawn after the table so the modal sits over it.
            if let Some(rule) = self.editor.show(ui.ctx(), unix_now()) {
               self.apply_actions(ui::rules::Actions {
                  upserts: vec![rule],
                  ..Default::default()
               });
            }
         }
         Page::Settings => {
            if ui::settings::show(ui, self.mode, &mut self.prefs) {
               // Live: the log keeps what still fits instead of waiting for a restart.
               self.log.set_caps(self.prefs.rows_per_app, self.prefs.max_apps);
               self.prefs_save_at = Some(Instant::now() + PREFS_SAVE_DELAY);
               ui.ctx().request_repaint_after(PREFS_SAVE_DELAY);
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
      self.handle_tray(ctx);
   }

   fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
      // A window nobody can see needs no frame: eframe runs this pass anyway (it treats the
      // root viewport as visible for its whole life) and drawing it re-arms the Connections
      // page's one-second repaint timer, which kept a minimized window repainting every
      // second. Nothing here is lost: on restore the window gets one pass, `attended` is true
      // by then, and the backlog the socket thread kept is installed by `update`.
      if !self.attended {
         return;
      }

      if self.alert {
         self.root_alert(ui);
         return;
      }

      self.toolbar(ui);
      self.banner(ui);

      egui::Panel::left("nav").exact_size(NAV_WIDTH).show(ui, |ui| {
         ui.add_space(6.0);
         ui.spacing_mut().item_spacing.y = 2.0;
         ui.spacing_mut().button_padding = egui::vec2(8.0, 5.0);
         for page in Page::ALL {
            let selected = self.page == page;
            let button = egui_elements::Button::selectable(selected, page.name())
               .min_size(egui::vec2(ui.available_width(), 26.0));
            if ui.add(button).clicked() {
               self.page = page;
            }
         }
         ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(4.0);
            self.status_line(ui);
         });
      });

      egui::CentralPanel::default().show(ui, |ui| {
         self.page_content(ui);
      });
   }
}

/// Fills a prompt's destination list, so the panel always sees what the answer covers.
///
/// A current daemon sends every destination; an older one leaves `dests` empty and its
/// `connection` is the whole prompt, so the fallback keeps that prompt a single destination
/// rather than an empty list the panel would have to special-case.
fn with_destinations(mut prompt: PromptRequest) -> PromptRequest {
   if prompt.dests.is_empty() {
      prompt.dests = vec![prompt.connection.clone()];
   }
   prompt
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

/// Records a measured panel height and returns the inner height to ask the viewport for.
///
/// The measurement is rounded up to whole points and capped at [`alert::MAX_HEIGHT`]. A
/// difference of half a point or less is the same request: returning `None` there is what
/// keeps a steady panel from issuing a viewport command on every frame. The stored height is
/// updated only when a new request is returned, and it is also what a re-raise centres on.
fn request_alert_height(stored: &Mutex<Option<f32>>, measured: f32) -> Option<f32> {
   let height = measured.ceil().min(alert::MAX_HEIGHT);
   let mut stored = stored.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
   match *stored {
      Some(last) if (height - last).abs() <= 0.5 => None,
      _ => {
         *stored = Some(height);
         Some(height)
      }
   }
}

/// Draws the alert into its own viewport and delivers the answer.
///
/// A free function, not a closure over `App`: the callback must be `Send + Sync + 'static`,
/// and only the model and the send handle cross into it. Everything here -- raising,
/// drawing, submitting, expiring and sending -- must happen in this callback, because the
/// main window's `ui` pass does not run while it is minimised, which is exactly when the
/// alert still has to work.
fn paint_alert(
   ui: &mut egui::Ui,
   model: &std::sync::Mutex<AlertModel>,
   decider: &Decider,
   alert_height: &Mutex<Option<f32>>,
) {
   let ctx = ui.ctx().clone();
   let mut model = model.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

   if model.raise_once().is_some() {
      log::debug!(
         "alert viewport raised for prompt {}",
         model.prompt().map_or(0, |prompt| prompt.id)
      );
      ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
      ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
         egui::WindowLevel::AlwaysOnTop,
      ));
      ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
         egui::UserAttentionType::Critical,
      ));
      if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
         let height = alert_height
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unwrap_or(alert::MAX_HEIGHT);
         let size = egui::vec2(alert::WIDTH, height);
         ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(
            centred_position(monitor, size).into(),
         ));
      }
   }

   let Some(prompt) = model.prompt().cloned() else {
      return;
   };
   let remaining = model.remaining_secs(std::time::Instant::now()).unwrap_or(0.0);
   let waiting = model.waiting();
   match alert::ui(ui, &prompt, model.state_mut(), remaining, waiting) {
      Some(alert::AlertAction::Decide(decision)) => model.submit(decision),
      Some(alert::AlertAction::Later) => model.later(),
      Some(alert::AlertAction::Previous) => model.previous(),
      None => {}
   }

   // The panel now takes the height its content measured, capped at the old fixed size, so
   // a short prompt no longer sits above empty background. The command goes out only when
   // the rounded height actually changed; a steady panel measures the same every frame.
   let measured = ui.min_rect().height();
   if let Some(height) = request_alert_height(alert_height, measured) {
      ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
         alert::WIDTH,
         height,
      )));
      log::debug!("alert viewport height set to {height}");
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

/// Names a decision's scope in the log, so it can be read without decoding a frame.
fn scope_kind(scope: &ScopeChoice) -> &'static str {
   match scope {
      ScopeChoice::AnyConnection => "any connection",
      ScopeChoice::Domain { .. } => "domain",
      ScopeChoice::Address => "address",
      ScopeChoice::TheseDestinations => "these destinations",
   }
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
         dests: Vec::new(),
         domain_scope_available: true,
         pending: 0,
      }
   }

   /// The same connection, for the destinations of a group.
   fn destination(domain: &str) -> ConnectionView {
      ConnectionView {
         app_name: "firefox".to_owned(),
         exe: None,
         pid: Some(4242),
         uid: Some(1000),
         family: Family::V4,
         proto: L4Proto::Tcp,
         remote_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 185, 78)),
         remote_port: 443,
         local_port: 51_000,
         domain: Some(domain.to_owned()),
         domain_candidates: Vec::new(),
      }
   }

   /// A prompt with `count` destinations, all of the same connection.
   fn group(id: u64, count: usize) -> PromptRequest {
      let mut request = prompt(id);
      request.dests = vec![destination("accounts.google.com"); count];
      request
   }

   /// The ids the app and the model both hold, in local order.
   fn order(app: &App) -> Vec<u64> {
      let pending: Vec<u64> = app.pending.iter().map(|prompt| prompt.id).collect();
      let model: Vec<u64> = app.model().prompts().iter().map(|prompt| prompt.id).collect();
      assert_eq!(
         pending, model,
         "the app and the alert model must agree"
      );
      pending
   }

   #[test]
   fn the_prompt_queue_dedupes_by_id_and_keeps_order() {
      let mut app = app();
      app.enqueue_prompt(group(1, 1));
      app.enqueue_prompt(group(1, 1));
      assert_eq!(app.pending.len(), 1);
      assert_eq!(app.alerts.len(), 1);
      assert_eq!(app.prompt_deadlines.len(), 1);

      app.enqueue_prompt(group(2, 1));
      assert_eq!(app.pending.len(), 2);
      assert_eq!(app.pending[0].id, 1);
      assert_eq!(app.pending[1].id, 2);

      // A growth of the oldest prompt lands where that prompt already was: the queue the
      // user sees does not reorder, and the oldest stays the one on screen.
      app.enqueue_prompt(group(1, 6));
      assert_eq!(app.pending.len(), 2);
      assert_eq!(app.pending[0].id, 1);
      assert_eq!(app.pending[0].dests.len(), 6);
      assert_eq!(app.pending[1].id, 2);
      assert_eq!(app.model().prompt().map(|open| open.id), Some(1));
      assert_eq!(order(&app), vec![1, 2]);
   }

   /// The daemon re-broadcasts a prompt as destinations join its group; the newer copy is
   /// the truth and must replace the earlier one in place, including in the alert.
   #[test]
   fn a_growth_replaces_in_place_and_a_shrink_is_ignored() {
      let mut app = app();
      app.enqueue_prompt(group(7, 1));
      app.enqueue_prompt(group(7, 6));

      assert_eq!(
         app.pending.len(),
         1,
         "the growth is not a second prompt"
      );
      assert_eq!(
         app.pending[0].id, 7,
         "and it keeps its queue position"
      );
      assert_eq!(
         app.pending[0].dests.len(),
         6,
         "the queue shows every destination of the grown group"
      );
      assert_eq!(
         app.model().prompt().map(|open| open.dests.len()),
         Some(6),
         "the alert the window paints is the newer copy"
      );
      assert_eq!(
         app.prompt_deadlines.len(),
         1,
         "the deadline bookkeeping is not duplicated"
      );
      assert_eq!(app.alerts.len(), 1);

      // A group growth keeps the single-destination default: the app-wide rule, which is
      // the choice that stops the rule list from filling with one rule per address.
      let presented = app.model().prompt().cloned().expect("presented");
      assert_eq!(
         app.model().state_mut().decision(&presented, Action::Allow).scope,
         ScopeChoice::AnyConnection
      );

      app.enqueue_prompt(group(7, 1));
      assert_eq!(app.pending.len(), 1);
      assert_eq!(
         app.pending[0].dests.len(),
         6,
         "the six-destination list survives a shorter repeat"
      );
      assert_eq!(
         app.model().prompt().map(|open| open.dests.len()),
         Some(6)
      );
   }

   /// The same panel measures the same every frame, so only the first one asks for a size.
   /// A prompt that later grows asks for a taller window again.
   #[test]
   fn the_window_height_is_asked_once_and_again_on_growth() {
      let stored: Mutex<Option<f32>> = Mutex::new(None);
      let request = prompt(7);
      let measured = alert::measured_height(&request, 0);

      let first =
         request_alert_height(&stored, measured).expect("the first measurement asks for a height");
      assert_eq!(
         *stored.lock().expect("height lock"),
         Some(first),
         "the requested height is stored"
      );
      assert_eq!(
         request_alert_height(&stored, alert::measured_height(&request, 0)),
         None,
         "the same content issues no second request"
      );
      assert_eq!(
         *stored.lock().expect("height lock"),
         Some(first),
         "the stored height did not change"
      );

      let grown = request_alert_height(&stored, alert::measured_height(&group(7, 6), 0))
         .expect("the six destinations ask again");
      assert!(
         grown > first,
         "the grown prompt asks for {grown}, above the single destination's {first}"
      );
      assert_eq!(
         *stored.lock().expect("height lock"),
         Some(grown),
         "the taller request replaces the stored height"
      );
   }

   #[test]
   fn closing_a_prompt_removes_its_state() {
      let mut app = app();
      app.enqueue_prompt(prompt(1));
      app.enqueue_prompt(prompt(2));

      app.remove_prompt(1);
      assert_eq!(app.pending.len(), 1);
      assert_eq!(app.pending[0].id, 2);
      assert!(!app.alerts.contains_key(&1));
      assert!(!app.prompt_deadlines.contains_key(&1));
      assert!(app.alerts.contains_key(&2));

      app.remove_prompt(99);
      assert_eq!(app.pending.len(), 1);
   }

   #[test]
   fn the_first_offline_report_is_logged_once() {
      let mut app = app();
      assert!(!app.connection_logged);
      app.set_connected(false);
      assert!(
         app.connection_logged,
         "the first failed dial must be recorded even though the state did not change"
      );
      app.set_connected(true);
      assert!(app.connected);
      app.set_connected(false);
      assert!(!app.connected);
   }

   #[test]
   fn a_queued_prompt_reaches_the_alert_model() {
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
   fn an_already_presented_prompt_keeps_the_selection() {
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

   /// The oldest unanswered prompt owns the window, and `Later` rotates the local list
   /// without answering: the prompt stays open in the daemon until it answers or expires.
   #[test]
   fn the_oldest_prompt_is_shown_and_later_rotates_without_answering() {
      let mut app = app();
      app.enqueue_prompt(prompt(1));
      app.enqueue_prompt(prompt(2));

      // Every prompt is published at once, so the oldest unanswered one owns the window.
      assert_eq!(
         app.model().prompt().map(|prompt| prompt.id),
         Some(1)
      );
      assert_eq!(order(&app), vec![1, 2]);

      // Closing the shown prompt advances to the next one.
      app.remove_prompt(1);
      assert_eq!(
         app.model().prompt().map(|prompt| prompt.id),
         Some(2)
      );

      app.remove_prompt(2);
      assert!(app.model().prompt().is_none());

      for id in [1u64, 2, 3] {
         app.enqueue_prompt(prompt(id));
      }
      assert_eq!(order(&app), vec![1, 2, 3]);

      app.step(alert::AlertAction::Later);
      assert_eq!(order(&app), vec![2, 3, 1]);
      assert_eq!(app.model().prompt().map(|open| open.id), Some(2));

      app.step(alert::AlertAction::Later);
      assert_eq!(order(&app), vec![3, 1, 2]);
      assert_eq!(app.model().prompt().map(|open| open.id), Some(3));

      app.step(alert::AlertAction::Previous);
      assert_eq!(order(&app), vec![2, 3, 1]);
      assert_eq!(app.model().prompt().map(|open| open.id), Some(2));

      assert!(
         app.model().take_outgoing().is_empty(),
         "stepping must not answer any prompt"
      );
   }

   /// Answering the shown prompt sends exactly that decision, and the next becomes shown.
   #[test]
   fn answering_advances_to_the_next_prompt() {
      let mut app = app();
      for id in [1u64, 2] {
         app.enqueue_prompt(prompt(id));
      }

      let shown = app.model().prompt().cloned().expect("a prompt is shown");
      app.model().submit(Decision {
         action: Action::Deny,
         duration: netshield_core::rule::Duration::Session,
         scope: ScopeChoice::AnyConnection,
      });

      let outgoing = app.model().take_outgoing();
      assert_eq!(outgoing.len(), 1);
      assert_eq!(outgoing[0].prompt_id, shown.id);
      assert_eq!(
         app.model().prompt().map(|prompt| prompt.id),
         Some(2),
         "the second prompt is shown after the first is answered"
      );
   }

   #[test]
   fn a_prompt_keeps_its_whole_destination_list() {
      // An older daemon omits the field entirely: the fallback makes it one destination.
      let mut fallback = app();
      let request = prompt(1);
      assert!(
         request.dests.is_empty(),
         "an older daemon omits the field"
      );
      fallback.enqueue_prompt(request);

      let model = fallback.model();
      let presented = model.prompt().expect("the alert is presented");
      assert_eq!(
         presented.dests,
         vec![presented.connection.clone()],
         "the fallback makes the prompt a single destination"
      );

      let mut app = app();
      let mut request = prompt(1);
      request.dests = vec![
         destination("accounts.google.com"),
         destination("ssl.gstatic.com"),
      ];
      app.enqueue_prompt(request);

      let queued = &app.pending[0];
      assert_eq!(
         queued.dests.len(),
         2,
         "the queue keeps every destination"
      );
      let model = app.model();
      let presented = model.prompt().expect("the alert is presented");
      assert_eq!(
         presented.dests.len(),
         2,
         "the alert state gets the whole group, not just the first destination"
      );
   }
}
