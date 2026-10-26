//! The Connections page: a newest-first table over the bounded connection log.

use egui::{Color32, RichText, Ui};

use crate::connlog::{ConnectionLog, Row};

/// Whole-row colour for a denied connection: muted red so a scan still reads as text.
const DENIED: Color32 = Color32::from_rgb(0xC0, 0x6A, 0x6A);

/// The verdict colour for an allowed connection.
const ALLOWED: Color32 = Color32::from_rgb(0x6C, 0xC0, 0x7A);

const HEADERS: [&str; 7] = [
   "Time (UTC)",
   "App",
   "Destination",
   "Address",
   "Proto",
   "Result",
   "Rule",
];

/// Draws the page heading, the row count and the scrollable table.
pub fn show(ui: &mut Ui, log: &ConnectionLog) {
   ui.horizontal(|ui| {
      ui.heading("Connections");
      ui.add_space(8.0);
      ui.label(RichText::new(format!("showing {} (oldest first)", log.len())).weak());
      if log.dropped() > 0 {
         ui.label(RichText::new(format!("· {} dropped", log.dropped())).weak());
      }
   });
   ui.add_space(4.0);

   if log.is_empty() {
      ui.label(
         RichText::new("No connections yet — the daemon reports them as they happen.").weak(),
      );
      return;
   }

   egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
      egui::Grid::new("connections")
         .num_columns(HEADERS.len())
         .striped(true)
         .spacing([12.0, 6.0])
         .show(ui, |ui| {
            for header in HEADERS {
               ui.label(RichText::new(header).strong());
            }
            ui.end_row();

            for row in log.rows().rev() {
               table_row(ui, row);
               ui.end_row();
            }
         });
   });
}

/// One row of the table. Denied connections paint every cell in the muted red.
fn table_row(ui: &mut Ui, row: &Row) {
   let base = if row.allowed {
      ui.visuals().text_color()
   } else {
      DENIED
   };

   ui.label(RichText::new(&row.time).monospace().color(base));
   ui.label(RichText::new(&row.app).color(base));
   match &row.candidate {
      Some(candidate) => {
         ui.label(RichText::new(candidate).italics().weak());
      }
      None => {
         ui.label(RichText::new(&row.dest).color(base));
      }
   }
   ui.label(RichText::new(&row.addr).monospace().color(base));
   ui.label(RichText::new(&row.proto).color(base));

   let verdict = if row.allowed { "ALLOWED" } else { "DENIED" };
   let verdict = if row.via_prompt {
      format!("{verdict} (prompt)")
   } else {
      verdict.to_owned()
   };
   let colour = if row.allowed { ALLOWED } else { DENIED };
   ui.label(RichText::new(verdict).color(colour).strong());

   ui.label(RichText::new(row.rule.as_deref().unwrap_or("—")).color(base));
}
