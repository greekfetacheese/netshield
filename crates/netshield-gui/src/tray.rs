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

/// The desktop user whose session bus a root-started GUI should adopt.
///
/// `sudo` and `pkexec` reset the environment, so the tray cannot find the session bus of the
/// desktop in front of the user and falls back to root's runtime dir, which has no bus. The
/// invoker named by `SUDO_UID`/`PKEXEC_UID` is the owner of that session; root may connect to
/// its bus, and the icon then registers on the panel the user is looking at.
///
/// `None` means "leave the environment alone": not root, a bus already named by the caller, no
/// invoker to name, or an invoker whose bus socket is not there.
fn adopted_session(
   euid: u32,
   bus_is_set: bool,
   sudo_uid: Option<u32>,
   pkexec_uid: Option<u32>,
   bus_exists: impl Fn(u32) -> bool,
) -> Option<u32> {
   if euid != 0 || bus_is_set {
      return None;
   }
   let uid = sudo_uid.or(pkexec_uid)?;
   bus_exists(uid).then_some(uid)
}

/// Adopts the invoker's session bus when this process is a root-started GUI.
///
/// Must be called from the first lines of `main`, before any thread exists: `env::set_var` is
/// unsafe because a concurrent reader of the environment is undefined behaviour, and this is the
/// only place in the crate that needs it. The tray library resolves its bus from the environment
/// alone, so the environment is the only lever.
pub fn adopt_desktop_session() {
   let uid = adopted_session(
      effective_uid(),
      std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some(),
      std::env::var("SUDO_UID").ok().and_then(|value| value.parse().ok()),
      std::env::var("PKEXEC_UID").ok().and_then(|value| value.parse().ok()),
      |uid| std::path::Path::new(&format!("/run/user/{uid}/bus")).exists(),
   );
   let Some(uid) = uid else {
      return;
   };
   let bus = format!("unix:path=/run/user/{uid}/bus");
   let runtime = format!("/run/user/{uid}");
   // SAFETY: `main` calls this before eframe, the IPC thread, or the tray thread exists, so
   // nothing else can read the environment while it is replaced.
   unsafe {
      std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus);
      std::env::set_var("XDG_RUNTIME_DIR", &runtime);
   }
   log::info!("root start: using the desktop session bus at {bus} for the tray icon");
}

/// The effective uid, from the owner of `/proc/self/status`: procfs stamps that file with the
/// process's effective uid, so no libc call is needed. An unreadable file is treated as
/// "not root", which leaves the environment alone.
fn effective_uid() -> u32 {
   use std::os::unix::fs::MetadataExt;
   std::fs::metadata("/proc/self/status").map_or(u32::MAX, |meta| meta.uid())
}

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

#[cfg(test)]
mod tests {
   use super::adopted_session;

   /// A bus socket that always exists, for the cases that are not about its absence.
   fn bus_present(_uid: u32) -> bool {
      true
   }

   #[test]
   fn a_root_gui_adopts_the_invoking_users_bus() {
      assert_eq!(
         adopted_session(0, false, Some(1000), None, bus_present),
         Some(1000)
      );
   }

   #[test]
   fn a_root_gui_without_an_invoker_leaves_the_environment_alone() {
      assert_eq!(
         adopted_session(0, false, None, None, bus_present),
         None
      );
   }

   #[test]
   fn an_explicit_bus_address_is_respected() {
      // The caller's environment wins: sudoers can pass one through and must not be overridden.
      assert_eq!(
         adopted_session(0, true, Some(1000), None, bus_present),
         None
      );
   }

   #[test]
   fn an_unprivileged_gui_adopts_nothing() {
      assert_eq!(
         adopted_session(1000, false, Some(1000), None, bus_present),
         None
      );
   }

   #[test]
   fn pkexec_names_the_invoker_too() {
      assert_eq!(
         adopted_session(0, false, None, Some(1001), bus_present),
         Some(1001)
      );
   }

   #[test]
   fn a_missing_bus_socket_is_not_adopted() {
      assert_eq!(
         adopted_session(0, false, Some(1000), None, |_uid| false),
         None
      );
   }
}
