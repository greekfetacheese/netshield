//! The application shell: navigation, the daemon poll and the current page.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use netshield_core::connection::{Family, L4Proto};
use netshield_core::ipc::{ConnectionEvent, ConnectionView, Mode, Request, Response};

use crate::Cli;
use crate::connlog::ConnectionLog;
use crate::ipc::{self, IpcClient};
use crate::ui;

/// How many connection rows the history keeps before dropping the oldest.
const LOG_CAPACITY: usize = 500;

/// How often the GUI asks the daemon for a status snapshot.
const REFRESH_EVERY: Duration = Duration::from_secs(5);

/// How often the UI wakes so the socket queue is drained even when nothing is clicked.
const POLL_EVERY: Duration = Duration::from_millis(200);

/// Red used by the offline banner; loud on purpose.
const BANNER_RED: egui::Color32 = egui::Color32::from_rgb(0xA8, 0x1F, 0x1F);

/// Top-level application state.
pub struct App {
   page: Page,
   /// `None` in `--mock`, where no daemon is contacted.
   ipc: Option<IpcClient>,
   socket: PathBuf,
   connected: bool,
   log: ConnectionLog,
   mock: bool,
   /// Accepted now; the alert slice gives it its own window mode.
   #[allow(dead_code)]
   alert: bool,
   pending_prompts: usize,
   mode: Mode,
   next_refresh: Instant,
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

impl App {
   /// Builds the app and, outside mock mode, starts talking to the daemon.
   pub fn new(cli: Cli) -> Self {
      let ipc = if cli.mock {
         None
      } else {
         let client = IpcClient::spawn(cli.socket.clone());
         client.send(&Request::Subscribe);
         client.send(&Request::Status);
         Some(client)
      };

      Self {
         page: Page::Connections,
         ipc,
         socket: cli.socket,
         connected: false,
         log: ConnectionLog::new(LOG_CAPACITY),
         mock: cli.mock,
         alert: cli.alert,
         pending_prompts: 0,
         mode: Mode::Alert,
         next_refresh: Instant::now() + REFRESH_EVERY,
      }
   }

   /// Drains the socket queue and schedules the next periodic refresh.
   fn update(&mut self) {
      if let Some(client) = &self.ipc {
         while let Some(event) = client.poll() {
            match event {
               ipc::IpcEvent::Connected(state) => self.connected = state,
               ipc::IpcEvent::Message(response) => match *response {
                  Response::Connection(event) => self.log.push(&event),
                  Response::Status(status) => {
                     self.mode = status.mode;
                     self.pending_prompts = status.pending_prompts;
                  }
                  Response::Prompt(_) => self.pending_prompts += 1,
                  Response::PromptClosed { .. } => {
                     self.pending_prompts = self.pending_prompts.saturating_sub(1);
                  }
                  _ => {}
               },
            }
         }
      }

      let now = Instant::now();
      if now < self.next_refresh {
         return;
      }
      if self.mock {
         self.log.push(&synthetic_event());
      } else if let Some(client) = &self.ipc {
         client.send(&Request::Status);
      }
      self.next_refresh = now + REFRESH_EVERY;
   }

   /// The loud offline banner, shown above the page content.
   fn banner(&self, ui: &mut egui::Ui) {
      if self.connected || self.mock {
         return;
      }
      egui::Panel::top("offline-banner")
         .resizable(false)
         .frame(egui::Frame::NONE.fill(BANNER_RED).inner_margin(egui::Margin::symmetric(12, 8)))
         .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
               egui::RichText::new(format!(
                  "Daemon not reachable at {} — retrying. Connections are NOT being filtered.",
                  self.socket.display()
               ))
               .color(egui::Color32::WHITE)
               .strong(),
            );
         });
   }

   /// Sidebar footer: connection state, policy mode and queued prompts.
   fn status_line(&self, ui: &mut egui::Ui) {
      let (dot, state) = if self.connected {
         ("●", "connected")
      } else if self.mock {
         ("○", "mock")
      } else {
         ("●", "offline")
      };
      let mut text = format!("{dot} {state}");
      if !self.mock {
         text.push_str(match self.mode {
            Mode::Alert => " · alert",
            Mode::Silent => " · silent",
         });
      }
      if self.pending_prompts > 0 {
         text.push_str(&format!(" · {} waiting", self.pending_prompts));
      }
      ui.label(egui::RichText::new(text).weak().small());
   }

   /// The selected page, or a placeholder for the slices that follow.
   fn page_content(&mut self, ui: &mut egui::Ui) {
      match self.page {
         Page::Connections => ui::connections::show(ui, &self.log),
         _ => {
            ui.heading(self.page.name());
            ui.add_space(4.0);
            ui.label(egui::RichText::new("This page is not implemented yet.").weak());
         }
      }
   }
}

impl eframe::App for App {
   fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
      self.update();
      ui.ctx().request_repaint_after(POLL_EVERY);

      egui::Panel::left("nav").exact_size(180.0).show(ui, |ui| {
         ui.add_space(8.0);
         for page in Page::ALL {
            if ui.selectable_label(self.page == page, page.name()).clicked() {
               self.page = page;
            }
         }
         ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(8.0);
            self.status_line(ui);
         });
      });

      self.banner(ui);

      egui::CentralPanel::default().show(ui, |ui| {
         self.page_content(ui);
      });
   }
}

/// One fake verdict so `--mock` exercises the log without a daemon.
fn synthetic_event() -> ConnectionEvent {
   struct Sample {
      app: &'static str,
      domain: Option<&'static str>,
      ip: [u8; 4],
      port: u16,
      proto: L4Proto,
      allowed: bool,
   }

   const SAMPLES: [Sample; 4] = [
      Sample {
         app: "firefox",
         domain: Some("example.com"),
         ip: [93, 184, 216, 34],
         port: 443,
         proto: L4Proto::Tcp,
         allowed: true,
      },
      Sample {
         app: "curl",
         domain: None,
         ip: [1, 1, 1, 1],
         port: 53,
         proto: L4Proto::Udp,
         allowed: true,
      },
      Sample {
         app: "unknown",
         domain: Some("telemetry.invalid"),
         ip: [203, 0, 113, 9],
         port: 443,
         proto: L4Proto::Tcp,
         allowed: false,
      },
      Sample {
         app: "steam",
         domain: None,
         ip: [23, 45, 67, 89],
         port: 27015,
         proto: L4Proto::Udp,
         allowed: false,
      },
   ];

   let at = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs());
   let sample = &SAMPLES[(at / 5) as usize % SAMPLES.len()];

   ConnectionEvent {
      at,
      connection: ConnectionView {
         app_name: sample.app.to_owned(),
         exe: None,
         pid: None,
         uid: None,
         family: Family::V4,
         proto: sample.proto,
         remote_ip: IpAddr::V4(Ipv4Addr::from(sample.ip)),
         remote_port: sample.port,
         local_port: 51_000,
         domain: sample.domain.map(str::to_owned),
         domain_candidates: Vec::new(),
      },
      allowed: sample.allowed,
      matched_rule: None,
      via_prompt: !sample.allowed,
   }
}
