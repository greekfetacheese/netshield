//! One table cell's text, clipped to its column and centred vertically.
//!
//! Both tables draw their rows as painted text rather than as a widget per cell: a virtualised
//! list cannot afford a widget that re-measures its content on every row, and a label that grows
//! to fit its text pushes the row wider than the column it belongs to. A galley clipped at the
//! column's width keeps the pitch fixed; [`truncation_hint`] puts the rest in a tooltip.

use egui::text::{LayoutJob, TextFormat, TextWrapping};
use egui::{Color32, FontId, Rect, Response, pos2};

/// Paints one row's cells, clipped to their columns and centred vertically.
///
/// Column offsets are relative to the row's left edge, so the header and the rows share one
/// geometry.
pub struct Cells<'a> {
   pub painter: &'a egui::Painter,
   pub rect: Rect,
}

impl Cells<'_> {
   /// Draws `text` starting `x` into the row, truncated at `width`.
   ///
   /// Returns whether the text had to be cut, which is the condition for a tooltip: a value that
   /// fits must not nag the pointer.
   pub fn text(
      &self,
      x: f32,
      width: f32,
      text: &str,
      font: &FontId,
      color: Color32,
      italics: bool,
   ) -> bool {
      let needed = self.painter.layout_no_wrap(text.to_owned(), font.clone(), color).size().x;
      let format = TextFormat {
         italics,
         ..TextFormat::simple(font.clone(), color)
      };
      let mut job = LayoutJob::single_section(text.to_owned(), format);
      job.wrap = TextWrapping::truncate_at_width(width.max(0.0));
      let galley = self.painter.layout_job(job);
      let y = self.rect.center().y - galley.size().y / 2.0;
      self.painter.galley(pos2(self.rect.left() + x, y), galley, color);
      needed > width
   }
}

/// Shows `text` while `response` is hovered, but only when it did not fit in `width`.
pub fn truncation_hint(
   response: &Response,
   painter: &egui::Painter,
   width: f32,
   text: &str,
   font: &FontId,
) {
   if !response.hovered() {
      return;
   }
   let needed = painter.layout_no_wrap(text.to_owned(), font.clone(), Color32::WHITE).size().x;
   if needed > width {
      response.clone().on_hover_text(text.to_owned());
   }
}
