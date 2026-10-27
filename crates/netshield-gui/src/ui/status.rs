//! The Status page: the daemon's own view of its health.
//!
//! Everything here is reported by the daemon. `now` is passed in rather than read from
//! the clock so [`uptime`] stays pure and testable.

use egui::{Color32, RichText, Ui};
use netshield_core::ipc::{Mode, StatusInfo};

/// The disconnect banner's red, so an unverified table carries the same weight.
const ALERT_RED: Color32 = Color32::from_rgb(0xA8, 0x1F, 0x1F);

/// Warning colour for a non-zero dropped-packet count.
const AMBER: Color32 = Color32::from_rgb(0xE0, 0xA8, 0x4A);

const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_HOUR: u64 = 3_600;
const SECS_PER_DAY: u64 = 86_400;

/// Formats a duration in seconds as `0s`, `1m 30s`, `1h 1m` or `2d 3h`.
///
/// A `started_at` in the future cannot happen with a sane clock, but it is treated as
/// zero elapsed time instead of underflowing.
pub fn uptime(started_at: u64, now: u64) -> String {
   let secs = now.saturating_sub(started_at);
   if secs < SECS_PER_MINUTE {
      format!("{secs}s")
   } else if secs < SECS_PER_HOUR {
      format!(
         "{}m {}s",
         secs / SECS_PER_MINUTE,
         secs % SECS_PER_MINUTE
      )
   } else if secs < SECS_PER_DAY {
      format!(
         "{}h {}m",
         secs / SECS_PER_HOUR,
         (secs % SECS_PER_HOUR) / SECS_PER_MINUTE
      )
   } else {
      format!(
         "{}d {}h",
         secs / SECS_PER_DAY,
         (secs % SECS_PER_DAY) / SECS_PER_HOUR
      )
   }
}

/// Whether the page must shout that the firewall is not in force.
pub fn unfiltered_warning(status: &StatusInfo) -> bool {
   !status.table_verified
}

/// Draws the warning bar, the daemon details grid and the privilege note.
pub fn show(ui: &mut Ui, status: Option<&StatusInfo>, now: u64) {
   ui.heading("Status");
   ui.add_space(4.0);

   let Some(status) = status else {
      ui.label(RichText::new("Waiting for the daemon...").weak());
      return;
   };

   if unfiltered_warning(status) {
      egui::Frame::NONE
         .fill(ALERT_RED)
         .inner_margin(egui::Margin::symmetric(12, 8))
         .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
               RichText::new("Packets are not being filtered.").color(Color32::WHITE).strong(),
            );
         });
      ui.add_space(8.0);
   }

   egui::Grid::new("status").num_columns(2).spacing([24.0, 6.0]).show(ui, |ui| {
      field(
         ui,
         "Daemon PID",
         &status.daemon_pid.to_string(),
         None,
      );
      field(
         ui,
         "Uptime",
         &uptime(status.started_at, now),
         None,
      );
      field(ui, "Mode", mode_label(status.mode), None);
      field(ui, "Rules", &status.rule_count.to_string(), None);
      field(
         ui,
         "Pending prompts",
         &status.pending_prompts.to_string(),
         None,
      );
      field(
         ui,
         "Queue number",
         &status.queue_num.to_string(),
         None,
      );

      ui.label("Queue drops");
      if status.queue_drops > 0 {
         ui.label(RichText::new(status.queue_drops.to_string()).color(AMBER).strong());
      } else {
         ui.label(RichText::new("—").weak());
      }
      ui.end_row();
   });

   ui.add_space(10.0);
   ui.label(
      RichText::new("This process is the unprivileged GUI; the packet filters live in the daemon.")
         .weak(),
   );
}

/// One label/value row of the details grid, optionally tinted.
fn field(ui: &mut Ui, label: &str, value: &str, color: Option<Color32>) {
   ui.label(label);
   let text = RichText::new(value);
   ui.label(match color {
      Some(color) => text.color(color),
      None => text,
   });
   ui.end_row();
}

/// The mode as the daemon names it.
fn mode_label(mode: Mode) -> &'static str {
   match mode {
      Mode::Alert => "Alert",
      Mode::Silent => "Silent",
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn uptime_formats_each_unit_boundary() {
      assert_eq!(uptime(0, 0), "0s");
      assert_eq!(uptime(0, 59), "59s");
      assert_eq!(uptime(0, 60), "1m 0s");
      assert_eq!(uptime(0, 90), "1m 30s");
      assert_eq!(uptime(0, 3_600), "1h 0m");
      assert_eq!(uptime(0, 3_661), "1h 1m");
      assert_eq!(uptime(0, 86_400), "1d 0h");
      assert_eq!(uptime(0, 176_400), "2d 1h");
   }

   #[test]
   fn uptime_never_underflows_when_the_clock_is_behind() {
      assert_eq!(uptime(100, 0), "0s");
   }

   #[test]
   fn unfiltered_warning_tracks_the_verified_flag() {
      let status = StatusInfo {
         daemon_pid: 99,
         mode: Mode::Alert,
         rule_count: 4,
         pending_prompts: 1,
         queue_num: 0,
         queue_drops: 0,
         table_verified: false,
         started_at: 100,
      };
      assert!(unfiltered_warning(&status));
      assert!(!unfiltered_warning(&StatusInfo {
         table_verified: true,
         ..status
      }));
   }
}
