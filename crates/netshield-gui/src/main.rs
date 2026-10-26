mod app;
mod ipc;
mod theme;

fn main() -> eframe::Result {
   let options = eframe::NativeOptions {
      viewport: egui::ViewportBuilder::default()
         .with_title("NetShield")
         .with_inner_size([980.0, 640.0])
         .with_min_inner_size([760.0, 480.0]),
      ..Default::default()
   };
   eframe::run_native(
      "NetShield",
      options,
      Box::new(|cc| {
         theme::install(&cc.egui_ctx);
         Ok(Box::new(app::App::default()))
      }),
   )
}
