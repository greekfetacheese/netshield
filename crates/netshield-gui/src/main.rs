//! NetShield desktop GUI entry point and its hand-rolled options parser.

mod alert;
mod app;
mod connlog;
mod ipc;
mod mock;
mod theme;
mod ui;

use std::path::PathBuf;

/// The default control socket the daemon listens on.
const DEFAULT_SOCKET: &str = "/run/netshield/control.sock";

/// Parsed command-line options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cli {
   pub socket: PathBuf,
   pub mock: bool,
   pub alert: bool,
}

impl Default for Cli {
   fn default() -> Self {
      Self {
         socket: PathBuf::from(DEFAULT_SOCKET),
         mock: false,
         alert: false,
      }
   }
}

/// What parsing produced: options to run with, or text the caller prints and exits on.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
   Run(Cli),
   /// Usage or version text, already formatted; the caller prints it to stdout.
   Info(String),
}

const USAGE: &str = "\
Usage: netshield-gui [OPTIONS]

Options:
  -h, --help           show this help and exit
  -V, --version        print the version and exit
      --socket PATH    control socket to connect to
                       [default: /run/netshield/control.sock]
      --mock           run with no daemon, showing synthetic connection events
      --alert          start minimised, showing only connection alerts (used by the daemon)
";

impl Cli {
   /// Parses arguments, excluding the program name.
   ///
   /// `--help` and `--version` are returned as [`Parsed::Info`] rather than printed here so
   /// the parser stays unit-testable. Unknown options and missing values yield `Err`,
   /// which the caller reports on stderr with exit code 2.
   pub fn parse<I: Iterator<Item = String>>(args: I) -> Result<Parsed, String> {
      let mut cli = Self::default();
      let mut args = args.peekable();
      while let Some(arg) = args.next() {
         match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Info(USAGE.to_owned())),
            "-V" | "--version" => {
               return Ok(Parsed::Info(format!(
                  "netshield-gui {}",
                  env!("CARGO_PKG_VERSION")
               )));
            }
            "--socket" => match args.next() {
               // A following option is a missing value, not a path: paths beginning with
               // a dash are not worth the ambiguity in a flag parser this small.
               Some(path) if !path.is_empty() && !path.starts_with('-') => {
                  cli.socket = PathBuf::from(path);
               }
               _ => return Err("--socket requires a path".to_owned()),
            },
            "--mock" => cli.mock = true,
            "--alert" => cli.alert = true,
            other if other.starts_with("--socket=") => {
               let path = &other["--socket=".len()..];
               if path.is_empty() {
                  return Err("--socket requires a path".to_owned());
               }
               cli.socket = PathBuf::from(path);
            }
            other => return Err(format!("unknown option: {other}")),
         }
      }
      Ok(Parsed::Run(cli))
   }
}

fn main() -> eframe::Result {
   let cli = match Cli::parse(std::env::args().skip(1)) {
      Ok(Parsed::Run(cli)) => cli,
      Ok(Parsed::Info(text)) => {
         println!("{text}");
         return Ok(());
      }
      Err(message) => {
         eprintln!("netshield-gui: {message}");
         eprintln!("Try 'netshield-gui --help' for usage.");
         std::process::exit(2);
      }
   };

   // In `--alert` mode the root window is the prompt itself, so it opens at the panel's
   // fixed size and cannot be resized out of the layout. Normal mode keeps the shell.
   let viewport = if cli.alert {
      egui::ViewportBuilder::default()
         .with_title("NetShield")
         .with_inner_size([460.0, 260.0])
         .with_min_inner_size([460.0, 260.0])
         .with_max_inner_size([460.0, 260.0])
         .with_resizable(false)
         .with_always_on_top()
         // Starts hidden; the app shows it from `App::logic` when the first prompt
         // arrives, which still runs for a hidden window.
         .with_visible(false)
   } else {
      egui::ViewportBuilder::default()
         .with_title("NetShield")
         .with_inner_size([980.0, 640.0])
         .with_min_inner_size([760.0, 480.0])
   };
   let options = eframe::NativeOptions {
      viewport,
      ..Default::default()
   };
   eframe::run_native(
      "NetShield",
      options,
      Box::new(move |cc| {
         theme::install(&cc.egui_ctx);
         Ok(Box::new(app::App::new(cli)))
      }),
   )
}

#[cfg(test)]
mod tests {
   use super::*;

   fn parse(args: &[&str]) -> Result<Parsed, String> {
      Cli::parse(args.iter().map(|arg| (*arg).to_owned()))
   }

   fn run(args: &[&str]) -> Cli {
      match parse(args) {
         Ok(Parsed::Run(cli)) => cli,
         other => panic!("expected Run, got {other:?}"),
      }
   }

   #[test]
   fn defaults_match_the_daemon_socket() {
      let cli = run(&[]);
      assert_eq!(
         cli.socket,
         PathBuf::from("/run/netshield/control.sock")
      );
      assert!(!cli.mock);
      assert!(!cli.alert);
   }

   #[test]
   fn socket_accepts_a_path() {
      assert_eq!(
         run(&["--socket", "/x"]).socket,
         PathBuf::from("/x")
      );
      assert_eq!(run(&["--socket=/x"]).socket, PathBuf::from("/x"));
   }

   #[test]
   fn flags_are_accepted() {
      assert!(run(&["--mock"]).mock);
      assert!(run(&["--alert"]).alert);
      assert!(!run(&["--mock"]).alert);
   }

   #[test]
   fn version_names_the_binary_and_crate_version() {
      let expected = format!("netshield-gui {}", env!("CARGO_PKG_VERSION"));
      assert_eq!(parse(&["--version"]), Ok(Parsed::Info(expected)));
      assert_eq!(parse(&["-V"]), parse(&["--version"]));
   }

   #[test]
   fn help_lists_every_flag() {
      let Ok(Parsed::Info(text)) = parse(&["--help"]) else {
         panic!("expected help text");
      };
      for flag in ["--socket", "--mock", "--alert", "--version", "--help"] {
         assert!(text.contains(flag), "help is missing {flag}");
      }
      assert!(text.contains("start minimised, showing only connection alerts"));
      assert_eq!(parse(&["-h"]), parse(&["--help"]));
   }

   #[test]
   fn unknown_options_are_errors() {
      assert!(parse(&["--nope"]).is_err());
      assert!(parse(&["extra"]).is_err());
   }

   #[test]
   fn socket_without_a_value_is_an_error() {
      assert!(parse(&["--socket"]).is_err());
      assert!(parse(&["--socket="]).is_err());
      assert!(parse(&["--socket", "--mock"]).is_err());
   }
}
