//! The application shell: a left navigation panel and the current page.

/// Top-level application state.
#[derive(Default)]
pub struct App {
   page: Page,
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

impl eframe::App for App {
   fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
      egui::Panel::left("nav").exact_size(180.0).show(ui, |ui| {
         ui.add_space(8.0);
         for page in Page::ALL {
            if ui.selectable_label(self.page == page, page.name()).clicked() {
               self.page = page;
            }
         }
      });

      egui::CentralPanel::default().show(ui, |ui| {
         ui.heading(self.page.name());
         ui.add_space(4.0);
         ui.label(egui::RichText::new("Slice 1: this page is not implemented yet.").weak());
      });
   }
}
