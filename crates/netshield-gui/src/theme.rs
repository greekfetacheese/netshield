//! Theme setup shared by every window in the GUI.

use egui_elements::{Theme, ThemeKind};

/// Install the dark theme the whole GUI draws with.
///
/// Called once at startup, before the first frame, so no widget ever paints with the
/// stock egui look. Default fonts are kept.
pub fn install(ctx: &egui::Context) {
   let mut theme = Theme::new(ThemeKind::TokyoNight);
   theme.install(ctx);

   // TODO(slice 6): lucide font. egui-lucide 0.2 ships SVG icons drawn through
   // egui_extras' image loader, not a font, and egui_extras is not a dependency of this
   // crate — so the nav uses plain text labels for now.
}
