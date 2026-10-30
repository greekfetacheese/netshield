//! The Settings page: the read-only daemon settings and the GUI's own log caps.
//!
//! The operation mode lives in the top bar, always visible; this page reports the current daemon
//! state and edits the one thing the GUI owns itself -- how much connection history it keeps.
//! The timeout and socket are daemon-side settings, so the page shows them as text instead of
//! pretending the GUI can change them.

use egui::{Color32, RichText, Ui};
use elegance::Slider;
use netshield_core::config::Config;
use netshield_core::ipc::Mode;

use crate::prefs::{self, Prefs};

/// Warning text colour for the Silent-mode consequence.
const AMBER: Color32 = Color32::from_rgb(0xE0, 0xA8, 0x4A);

/// Background of the muted amber block; dark enough to stay below the warning text.
const AMBER_BG: Color32 = Color32::from_rgb(0x3A, 0x2E, 0x14);

/// Draws the page; returns whether either log cap was changed this frame.
///
/// The mode switch is in the top bar, so this reports the current mode and the Silent-mode
/// consequence instead of offering a control the shell already owns.
///
/// The page scrolls: it outgrew a short window, and the heading stays pinned above the
/// scroll area as it does on the Connections page.
pub fn show(ui: &mut Ui, current: Mode, prefs: &mut Prefs) -> bool {
   ui.heading("Settings");
   ui.add_space(4.0);

   egui::ScrollArea::vertical()
      .auto_shrink([false, false])
      .content_margin(10)
      .show(ui, |ui| {
         let mut changed = false;

         section(ui, "Operation mode");
         ui.label(RichText::new("\"Ask before connecting\" — toggled in the top bar.").weak());
         let state = match current {
            Mode::Alert => "currently: alert",
            Mode::Silent => "currently: silent",
         };
         ui.label(RichText::new(state).weak());

         if current == Mode::Silent {
            ui.add_space(6.0);
            egui::Frame::NONE
               .fill(AMBER_BG)
               .inner_margin(egui::Margin::symmetric(10, 8))
               .show(ui, |ui| {
                  ui.set_width(ui.available_width());
                  ui.label(
                     RichText::new(
                        "New connections are allowed without a decision. Rules still apply, \
                         so Silent is not \"monitoring only\".",
                     )
                     .color(AMBER),
                  );
               });
         }

         section(ui, "Connection log");
         ui.label(
            RichText::new(
               "How much history the Connections page keeps in memory. A change takes effect at \
                once: the oldest rows past a lower cap are dropped and counted as dropped.",
            )
            .weak(),
         );
         changed |= ui
            .add(
               Slider::new(&mut prefs.rows_per_app, prefs::ROWS_PER_APP)
                  .label("Tracked connections per application"),
            )
            .changed();
         changed |= ui
            .add(
               Slider::new(&mut prefs.max_apps, prefs::MAX_APPS)
                  .label("Applications tracked at once"),
            )
            .changed();

         section(ui, "Prompt timeout");
         let config = Config::default();
         ui.label(format!(
            "{} seconds (daemon default)",
            config.prompt_timeout_secs
         ));
         ui.label(
            RichText::new(
               "Configured in the daemon's config file as `prompt_timeout_secs`; a prompt left \
                unanswered is denied.",
            )
            .weak(),
         );

         section(ui, "Control socket");
         ui.label(RichText::new(config.socket_path.display().to_string()).monospace());
         ui.label(RichText::new("The GUI connects to this socket as an unprivileged user.").weak());

         changed
      })
      .inner
}

/// A separated section heading; every section after the first gets a rule above it.
fn section(ui: &mut Ui, title: &str) {
   ui.add_space(10.0);
   ui.separator();
   ui.add_space(6.0);
   ui.label(RichText::new(title).strong());
   ui.add_space(2.0);
}
