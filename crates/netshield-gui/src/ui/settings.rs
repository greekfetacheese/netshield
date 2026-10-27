//! The Settings page: the read-only daemon settings.
//!
//! The operation mode lives in the top bar, always visible; this page only reports the
//! current state. The timeout and socket are daemon-side settings too, so the page shows
//! them as text instead of pretending the GUI can change them.

use egui::{Color32, RichText, Ui};
use netshield_core::config::Config;
use netshield_core::ipc::Mode;

/// Warning text colour for the Silent-mode consequence.
const AMBER: Color32 = Color32::from_rgb(0xE0, 0xA8, 0x4A);

/// Background of the muted amber block; dark enough to stay below the warning text.
const AMBER_BG: Color32 = Color32::from_rgb(0x3A, 0x2E, 0x14);

/// Draws the page.
///
/// The mode switch is in the top bar, so this reports the current mode and the Silent-mode
/// consequence instead of offering a control the shell already owns.
pub fn show(ui: &mut Ui, current: Mode) {
   ui.heading("Settings");
   ui.add_space(4.0);

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
}

/// A separated section heading; every section after the first gets a rule above it.
fn section(ui: &mut Ui, title: &str) {
   ui.add_space(10.0);
   ui.separator();
   ui.add_space(6.0);
   ui.label(RichText::new(title).strong());
   ui.add_space(2.0);
}
