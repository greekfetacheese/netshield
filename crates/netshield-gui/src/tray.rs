//! The system tray icon, its menu, and how it reaches the app.
//!
//! The tray is built once, on the GUI thread, and owned by [`crate::app::App`]:
//! `TrayIcon` is not `Send`, so it must never move into a global or a thread. The
//! callbacks it installs run on tray-icon's own thread, so they capture only `Send`
//! values -- the menu ids, the action queue and an `egui::Context` -- and wake the UI
//! with `request_repaint`.
//!
//! Actions are drained from `App::logic`, never `App::ui`: eframe runs no egui pass while
//! the window is hidden and calls `logic` instead, which is exactly the state the tray
//! leaves the window in.
//!
//! Linux/BSD use the `ksni` backend (pure-Rust D-Bus StatusNotifierItem) so the build
//! never needs GTK3 and the icon click produces an event. That backend renders the item
//! `title` as its hover text, not the `tooltip`, so exactly one of the two is set below.

use std::sync::{Arc, Mutex, PoisonError};

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::{ICON_RGBA, ICON_SIDE};

/// The hover text and item title the desktop shows for the icon.
const TITLE: &str = "NetShield";

/// What a tray interaction asks the app to do.
///
/// Callbacks cannot touch `&mut App`, so they queue one of these and the app applies it
/// on the next `logic` pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
   /// Show and focus the window: a left click, or `Show NetShield`.
   Show,
   /// Open the Rules page and show the window.
   OpenRules,
   /// Exit, exactly as the window's close button would if the tray were unavailable.
   Quit,
}

/// The tray icon and the actions its callbacks have queued since the last drain.
pub struct Tray {
   /// Dropping this removes the icon, so the app owns it for its whole lifetime.
   /// It is never read afterwards: owning it is the whole point.
   #[allow(dead_code)]
   icon: TrayIcon,
   /// Written by the callbacks' thread, read by `App::logic` on the GUI thread.
   actions: Arc<Mutex<Vec<Action>>>,
}

impl Tray {
   /// Creates the icon and its menu, or returns `None` when the platform has no
   /// StatusNotifier host.
   ///
   /// A missing host is a normal desktop configuration, not an error: the app runs without
   /// a tray and the window keeps its close button behaviour.
   pub fn new(ctx: &egui::Context) -> Option<Tray> {
      debug_assert_eq!(
         ICON_RGBA.len(),
         (ICON_SIDE * ICON_SIDE * 4) as usize,
         "the tray icon must be raw RGBA8, 64x64"
      );

      let icon = match Icon::from_rgba(ICON_RGBA.to_vec(), ICON_SIDE, ICON_SIDE) {
         Ok(icon) => icon,
         Err(err) => {
            log::warn!("cannot decode the tray icon, running without a tray: {err}");
            return None;
         }
      };

      let show = MenuItem::new("Show NetShield", true, None);
      let rules = MenuItem::new("Rules", true, None);
      let quit = MenuItem::new("Quit", true, None);
      let menu = Menu::new();
      if let Err(err) = menu.append_items(&[&show, &rules, &PredefinedMenuItem::separator(), &quit])
      {
         log::warn!("cannot build the tray menu, running without a tray: {err}");
         return None;
      }

      let builder = TrayIconBuilder::new()
         .with_menu(Box::new(menu))
         // Windows and macOS open the menu on a left click too, which would cover the
         // window it just restored. Linux ignores this: the StatusNotifier host owns the
         // right-click menu.
         .with_menu_on_left_click(false)
         .with_icon(icon);
      // Which attribute carries the hover text is backend-specific, and setting both
      // renders it twice: `ksni` maps it to `(title, tooltip)`. Windows/macOS read
      // `tooltip`, Linux/BSD read the item `title` and show nothing without it.
      #[cfg(any(target_os = "linux", target_os = "freebsd"))]
      let builder = builder.with_title(TITLE);
      #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
      let builder = builder.with_tooltip(TITLE);

      let icon = match builder.build() {
         Ok(icon) => icon,
         Err(err) => {
            log::warn!("no StatusNotifier host for the tray icon, running without one: {err}");
            return None;
         }
      };

      // The ids are `Send` clones; the `TrayIcon` itself is not and stays out of the
      // callbacks. `set_event_handler` writes a process-global cell, so the tray is built
      // once: a second one would never report.
      let show_id = show.id().clone();
      let rules_id = rules.id().clone();
      let quit_id = quit.id().clone();
      let actions: Arc<Mutex<Vec<Action>>> = Arc::new(Mutex::new(Vec::new()));

      {
         let queue = Arc::clone(&actions);
         let ctx = ctx.clone();
         TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            // Windows and macOS emit a click for both button edges, so only `Up` counts;
            // one press must not toggle the window twice. Linux `ksni` emits a single `Up`.
            if let TrayIconEvent::Click {
               button: MouseButton::Left,
               button_state: MouseButtonState::Up,
               ..
            } = event
            {
               push(&queue, Action::Show);
               ctx.request_repaint();
            }
         }));
      }

      {
         let queue = Arc::clone(&actions);
         let ctx = ctx.clone();
         MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let action = if *event.id() == show_id {
               Action::Show
            } else if *event.id() == rules_id {
               Action::OpenRules
            } else if *event.id() == quit_id {
               Action::Quit
            } else {
               return;
            };
            push(&queue, action);
            // Wakes the app even while the window is hidden, which is what makes
            // `App::logic` run and see the action.
            ctx.request_repaint();
         }));
      }

      log::info!("system tray icon registered");
      Some(Self { icon, actions })
   }

   /// Every action queued since the last call, without blocking.
   pub fn drain(&mut self) -> Vec<Action> {
      let mut queue = self.actions.lock().unwrap_or_else(PoisonError::into_inner);
      std::mem::take(&mut queue)
   }
}

/// Queues one action, recovering from a poisoned lock: the vector is still consistent.
fn push(actions: &Mutex<Vec<Action>>, action: Action) {
   actions.lock().unwrap_or_else(PoisonError::into_inner).push(action);
}

/// Hides the root window, leaving the tray icon as the only way back.
pub fn hide_window(ctx: &egui::Context) {
   ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
   // Clear the minimized state too: a window that is both hidden and minimized pops back
   // into the taskbar instead of reappearing in front of the user.
   ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
   ctx.request_repaint();
}

/// Brings the root window back, in front of whatever the user was doing.
pub fn show_window(ctx: &egui::Context) {
   ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
   ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
   ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
   ctx.request_repaint();
}
