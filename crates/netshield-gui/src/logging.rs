//! The GUI's file logger and panic hook.
//!
//! Started by XDG autostart the GUI has no terminal, so every `log::` record was written
//! nowhere and the "alert while minimised" investigation had to inspect the process from
//! outside with `xwininfo`. This module keeps one append-only line per record in a state
//! file, still mirrors warn and error to stderr for a hand-started run, and records the
//! message and a backtrace of a panic before the default hook prints it. No dependency is
//! involved: the timestamp is civil-from-days and installation is a `OnceLock`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{Level, LevelFilter, Log, Metadata, Record};

/// Environment variable naming the level.
const LEVEL_ENV: &str = "NETSHIELD_LOG";

/// Environment variable that lifts the target filter for dependency debugging.
const TARGETS_ENV: &str = "NETSHIELD_LOG_TARGETS";

/// The [`TARGETS_ENV`] value that lets every crate's records through.
const ALL_TARGETS: &str = "all";

/// Environment variable naming the log file.
const LOG_FILE_ENV: &str = "NETSHIELD_LOG_FILE";

/// Directory under the state root that owns the log.
const STATE_DIR: &str = "netshield";

/// File name inside [`STATE_DIR`].
const LOG_NAME: &str = "gui.log";

/// The suffix a rotated log gets.
const ROTATED_SUFFIX: &str = ".1";

/// A log larger than this is rotated, at startup and whenever a write would cross it.
const MAX_LOG_BYTES: u64 = 1024 * 1024;

/// The installed logger; a second [`init`] reuses it instead of installing twice.
static LOGGER: OnceLock<FileLogger> = OnceLock::new();

/// The one open log file, behind the mutex every record takes.
struct FileLogger {
   /// The open file, its byte count since open and the path it was opened from; `None` is
   /// impossible today, but keeping the file optional makes the "already failed" state
   /// explicit instead of writing to a descriptor we know is broken.
   file: Mutex<Option<OpenLog>>,
   /// The settings `log` and `enabled` consult, parsed once at [`init`].
   settings: Settings,
   /// Whether the first failed write has already been reported to stderr.
   reported_write_error: AtomicBool,
}

/// The open log and the state a mid-run rotation needs.
struct OpenLog {
   /// The file records are appended to.
   file: File,
   /// Bytes written since the file was opened or last rotated.
   written: u64,
   /// Where the file lives, so it can be renamed and reopened in place.
   path: PathBuf,
}

/// The configured level and whether the target filter is lifted.
///
/// Kept as plain data so the emission predicate can be tested without touching the
/// environment or the global logger, which can only be installed once per process.
#[derive(Clone, Copy, Debug)]
struct Settings {
   /// The level `NETSHIELD_LOG` asked for.
   level: LevelFilter,
   /// Whether `NETSHIELD_LOG_TARGETS=all` lets every target through.
   all_targets: bool,
}

impl Settings {
   /// Reads the environment once, at [`init`].
   fn from_env() -> Self {
      Self {
         level: level_from(std::env::var(LEVEL_ENV).ok().as_deref()),
         all_targets: all_targets_from(std::env::var(TARGETS_ENV).ok().as_deref()),
      }
   }
}

/// Installs the file logger and the panic hook. Returns the log file path it opened.
///
/// The hook is installed even when the file cannot be opened, because the default hook
/// still names the panic on stderr; only the logger is skipped, so a GUI without a state
/// directory behaves exactly as it did before this module existed.
pub fn init() -> Option<PathBuf> {
   install_panic_hook();
   let settings = Settings::from_env();
   let path = resolve_path(
      std::env::var_os(LOG_FILE_ENV).map(PathBuf::from).as_deref(),
      std::env::var_os("XDG_STATE_HOME").map(PathBuf::from).as_deref(),
      std::env::var_os("HOME").map(PathBuf::from).as_deref(),
   );
   let Some(path) = path else {
      eprintln!("netshield-gui: cannot resolve a log file path; logging is disabled");
      return None;
   };
   let file = match open_log_file(&path) {
      Ok(file) => file,
      Err(err) => {
         eprintln!(
            "netshield-gui: cannot open the log file {}: {err}",
            path.display()
         );
         return None;
      }
   };
   let logger = LOGGER.get_or_init(|| FileLogger {
      file: Mutex::new(Some(OpenLog {
         file,
         written: 0,
         path: path.clone(),
      })),
      settings,
      reported_write_error: AtomicBool::new(false),
   });
   if log::set_logger(logger).is_ok() {
      log::set_max_level(settings.level);
   }
   Some(path)
}

/// Parses `NETSHIELD_LOG`; unset or unknown falls back to `info`.
fn level_from(value: Option<&str>) -> LevelFilter {
   let Some(raw) = value else {
      return LevelFilter::Info;
   };
   match raw.trim().to_ascii_lowercase().as_str() {
      "off" => LevelFilter::Off,
      "error" => LevelFilter::Error,
      "warn" => LevelFilter::Warn,
      "info" => LevelFilter::Info,
      "debug" => LevelFilter::Debug,
      "trace" => LevelFilter::Trace,
      _ => LevelFilter::Info,
   }
}

/// Parses `NETSHIELD_LOG_TARGETS`; only the exact word `all` lifts the target filter.
fn all_targets_from(value: Option<&str>) -> bool {
   value.is_some_and(|raw| raw.trim().eq_ignore_ascii_case(ALL_TARGETS))
}

/// Whether this target belongs to one of our crates rather than to a dependency.
fn is_own_target(target: &str) -> bool {
   target == "netshield" || target.starts_with("netshield_")
}

/// Whether a record is emitted, given the settings.
///
/// A dependency's `Debug`/`Trace`/`Info` records are the wgpu and naga noise that made
/// `NETSHIELD_LOG=debug` useless: 402 KB of adapter dumps buried the handful of
/// `netshield_gui` lines. Their warnings and errors are still worth keeping, because they
/// explain why a frame or a device failed. `NETSHIELD_LOG_TARGETS=all` lifts the filter
/// for the rare case of debugging a dependency.
fn emits(target: &str, level: Level, settings: &Settings) -> bool {
   let level = level.to_level_filter();
   if level > settings.level {
      return false;
   }
   settings.all_targets || is_own_target(target) || level <= LevelFilter::Warn
}

/// Resolves the log path from values, not the environment, so it is testable.
///
/// `NETSHIELD_LOG_FILE` wins, then `$XDG_STATE_HOME/netshield/gui.log`, then
/// `$HOME/.local/state/netshield/gui.log`. An empty variable counts as unset: a shell
/// that exports `NETSHIELD_LOG_FILE=` means "no override", not "the current directory".
fn resolve_path(
   file: Option<&Path>,
   xdg_state_home: Option<&Path>,
   home: Option<&Path>,
) -> Option<PathBuf> {
   if let Some(file) = file.filter(|path| !path.as_os_str().is_empty()) {
      return Some(file.to_owned());
   }
   let state_root = xdg_state_home
      .filter(|path| !path.as_os_str().is_empty())
      .map(Path::to_owned)
      .or_else(|| {
         home
            .filter(|path| !path.as_os_str().is_empty())
            .map(|home| home.join(".local").join("state"))
      })?;
   Some(state_root.join(STATE_DIR).join(LOG_NAME))
}

/// Whether a log of `len` bytes is large enough to rotate.
fn should_rotate(len: u64) -> bool {
   len > MAX_LOG_BYTES
}

/// The path a rotated log moves to: `<path>.1`.
fn rotated_path(path: &Path) -> PathBuf {
   let mut name = path.as_os_str().to_owned();
   name.push(ROTATED_SUFFIX);
   PathBuf::from(name)
}

/// Creates the parent directory, rotates an oversized log, then opens for append.
fn open_log_file(path: &Path) -> std::io::Result<File> {
   if let Some(parent) = path.parent()
      && !parent.as_os_str().is_empty()
   {
      std::fs::create_dir_all(parent)?;
   }
   match rotate_if_needed(path) {
      Ok(()) => {}
      // A failed rename must not cost the whole log: appending to the existing file is
      // still better than the no-observability state this module exists to end.
      Err(err) => eprintln!(
         "netshield-gui: cannot rotate the log file {}: {err}",
         path.display()
      ),
   }
   OpenOptions::new().create(true).append(true).open(path)
}

/// Renames an oversized log to `<path>.1`, replacing any previous rotation.
fn rotate_if_needed(path: &Path) -> std::io::Result<()> {
   let Ok(meta) = std::fs::metadata(path) else {
      // A missing file has nothing to rotate; the open below creates it.
      return Ok(());
   };
   if should_rotate(meta.len()) {
      std::fs::rename(path, rotated_path(path))?;
   }
   Ok(())
}

/// The civil date for a day count since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
   let shifted = days + 719_468;
   let era = shifted.div_euclid(146_097);
   let day_of_era = shifted - era * 146_097;
   let year_of_era =
      (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
   let year = year_of_era + era * 400;
   let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
   let month_index = (5 * day_of_year + 2) / 153;
   let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
   let month = if month_index < 10 {
      month_index + 3
   } else {
      month_index - 9
   } as u32;
   // January and February belong to the previous civil year, which the era folds away.
   let civil_year = if month <= 2 { year + 1 } else { year };
   (civil_year, month, day)
}

/// A UTC timestamp shaped `2026-10-27T15:31:02Z`, truncated to whole seconds.
///
/// A time before the epoch is clamped to it rather than panicking: a bad clock must not
/// take down the logger that is supposed to report a bad clock.
fn utc_timestamp(now: SystemTime) -> String {
   let secs = now.duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
   let days = (secs / 86_400) as i64;
   let of_day = secs % 86_400;
   let (year, month, day) = civil_from_days(days);
   let hour = of_day / 3_600;
   let minute = of_day % 3_600 / 60;
   let second = of_day % 60;
   format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// One formatted record: UTC timestamp, level padded to five, target, message, newline.
///
/// Kept free of the file handle so the documented shape is asserted without filesystem
/// side effects, and so the level column cannot drift between records.
fn format_record(level: Level, target: &str, message: &str, now: SystemTime) -> String {
   format!(
      "{} {level:<5} {target}: {message}\n",
      utc_timestamp(now)
   )
}

impl FileLogger {
   /// Appends one line and flushes it, so a crash right after a record still has it.
   fn write_line(&self, line: &str) {
      let mut guard = self.file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
      let Some(log) = guard.as_mut() else {
         return;
      };
      if let Err(err) = log.write(line, MAX_LOG_BYTES)
         && !self.reported_write_error.swap(true, Ordering::Relaxed)
      {
         // Reporting through a raw stderr handle, never through `log`, so a broken log
         // file cannot recurse back into this function.
         eprintln!("netshield-gui: cannot write to the log file: {err}");
      }
   }
}

impl OpenLog {
   /// Writes one line, rotating first when it would take the file past `limit`.
   fn write(&mut self, line: &str, limit: u64) -> std::io::Result<()> {
      let bytes = line.len() as u64;
      if self.written.saturating_add(bytes) > limit {
         self.rotate();
      }
      self.file.write_all(line.as_bytes())?;
      self.file.flush()?;
      self.written = self.written.saturating_add(bytes);
      Ok(())
   }

   /// Renames the open file to `<path>.1` and reopens `path` in append mode.
   ///
   /// A failed rotation is reported once and leaves the existing handle in place: writing
   /// on is still better than the no-observability state this module exists to end, and a
   /// logger must never take the GUI down.
   fn rotate(&mut self) {
      let rotated = rotated_path(&self.path);
      let reopened = std::fs::rename(&self.path, &rotated)
         .and_then(|()| OpenOptions::new().create(true).append(true).open(&self.path));
      match reopened {
         Ok(file) => {
            self.file = file;
            self.written = 0;
         }
         Err(err) => eprintln!(
            "netshield-gui: cannot rotate the log file {}: {err}",
            self.path.display()
         ),
      }
   }
}

impl Log for FileLogger {
   fn enabled(&self, metadata: &Metadata<'_>) -> bool {
      emits(
         metadata.target(),
         metadata.level(),
         &self.settings,
      )
   }

   fn log(&self, record: &Record<'_>) {
      // `log` can be reached without `enabled` through `log::logger().log(record)`, so the
      // same predicate decides here; a filtered record must not even be formatted.
      if !self.enabled(record.metadata()) {
         return;
      }
      let message = record.args().to_string();
      let line = format_record(
         record.level(),
         record.target(),
         &message,
         SystemTime::now(),
      );
      self.write_line(&line);
      // The file is the record of truth for an autostarted GUI, but a hand-started run
      // watches the terminal, and a warning that never reaches it is the reason this
      // module exists.
      if record.level() <= Level::Warn {
         let mut stderr = std::io::stderr().lock();
         let _ = stderr.write_all(line.as_bytes());
      }
   }

   fn flush(&self) {
      if let Ok(mut guard) = self.file.lock()
         && let Some(log) = guard.as_mut()
      {
         let _ = log.file.flush();
      }
   }
}

/// Writes a panic and its backtrace to the log, then lets the default hook print it.
///
/// Installed before the logger so a panic raised while the file is being opened is still
/// recorded; when no logger is installed this is a no-op and the default hook is all the
/// process has, which is what it had before.
fn install_panic_hook() {
   static INSTALLED: OnceLock<()> = OnceLock::new();
   if INSTALLED.set(()).is_err() {
      return;
   }
   let previous = std::panic::take_hook();
   std::panic::set_hook(Box::new(move |info| {
      let location = info.location().map_or_else(
         || "<unknown>".to_owned(),
         |location| format!("{}:{}", location.file(), location.line()),
      );
      let message = panic_message(info.payload());
      let mut line = format!("PANIC at {location}: {message}\n");
      let _ = std::fmt::Write::write_fmt(
         &mut line,
         format_args!("{}\n", std::backtrace::Backtrace::force_capture()),
      );
      if let Some(logger) = LOGGER.get() {
         logger.write_line(&line);
      }
      previous(info);
   }));
}

/// The text of a panic payload, which is usually a `&str` or a `String`.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
   if let Some(message) = payload.downcast_ref::<&str>() {
      message
   } else if let Some(message) = payload.downcast_ref::<String>() {
      message
   } else {
      "<non-string panic payload>"
   }
}

#[cfg(test)]
mod tests {
   use std::sync::atomic::AtomicUsize;
   use std::time::Duration;

   use super::*;

   fn at(secs: u64) -> SystemTime {
      UNIX_EPOCH + Duration::from_secs(secs)
   }

   #[test]
   fn every_known_level_name_parses() {
      assert_eq!(level_from(Some("off")), LevelFilter::Off);
      assert_eq!(level_from(Some("error")), LevelFilter::Error);
      assert_eq!(level_from(Some("warn")), LevelFilter::Warn);
      assert_eq!(level_from(Some("info")), LevelFilter::Info);
      assert_eq!(level_from(Some("debug")), LevelFilter::Debug);
      assert_eq!(level_from(Some("trace")), LevelFilter::Trace);
   }

   #[test]
   fn level_names_are_case_insensitive_and_trimmed() {
      assert_eq!(level_from(Some("DEBUG")), LevelFilter::Debug);
      assert_eq!(level_from(Some(" Warn \n")), LevelFilter::Warn);
   }

   #[test]
   fn an_unset_or_unknown_level_defaults_to_info() {
      assert_eq!(level_from(None), LevelFilter::Info);
      assert_eq!(level_from(Some("")), LevelFilter::Info);
      assert_eq!(level_from(Some("verbose")), LevelFilter::Info);
   }

   #[test]
   fn the_file_override_wins_over_the_state_directories() {
      assert_eq!(
         resolve_path(
            Some(Path::new("/tmp/custom.log")),
            Some(Path::new("/xdg")),
            Some(Path::new("/home/user")),
         ),
         Some(PathBuf::from("/tmp/custom.log"))
      );
   }

   #[test]
   fn an_empty_override_counts_as_unset() {
      assert_eq!(
         resolve_path(
            Some(Path::new("")),
            Some(Path::new("/xdg")),
            Some(Path::new("/home/user")),
         ),
         Some(PathBuf::from("/xdg/netshield/gui.log"))
      );
   }

   #[test]
   fn the_state_home_is_used_when_it_is_set() {
      assert_eq!(
         resolve_path(
            None,
            Some(Path::new("/xdg")),
            Some(Path::new("/home/user"))
         ),
         Some(PathBuf::from("/xdg/netshield/gui.log"))
      );
   }

   #[test]
   fn home_is_the_last_resort() {
      assert_eq!(
         resolve_path(None, None, Some(Path::new("/home/user"))),
         Some(PathBuf::from(
            "/home/user/.local/state/netshield/gui.log"
         ))
      );
   }

   #[test]
   fn no_state_directory_resolves_to_no_path() {
      assert_eq!(resolve_path(None, None, None), None);
      assert_eq!(
         resolve_path(None, Some(Path::new("")), Some(Path::new(""))),
         None
      );
   }

   #[test]
   fn rotation_only_happens_past_one_mebibyte() {
      assert!(!should_rotate(0));
      assert!(!should_rotate(MAX_LOG_BYTES));
      assert!(should_rotate(MAX_LOG_BYTES + 1));
   }

   #[test]
   fn a_rotated_log_sits_beside_the_original_with_a_dot_one() {
      assert_eq!(
         rotated_path(Path::new("/state/netshield/gui.log")),
         PathBuf::from("/state/netshield/gui.log.1")
      );
   }

   #[test]
   fn the_epoch_formats_as_utc() {
      assert_eq!(utc_timestamp(at(0)), "1970-01-01T00:00:00Z");
   }

   #[test]
   fn a_later_epoch_formats_as_utc() {
      // `1_000_000_000` is 2001-09-09T01:46:40Z, not the 2009 date it is easily mistaken
      // for; GNU `date -u -d @1000000000` agrees. The 2009 instant is `1_234_567_900`,
      // pinned beside it so both readings stay covered.
      assert_eq!(
         utc_timestamp(at(1_000_000_000)),
         "2001-09-09T01:46:40Z"
      );
      assert_eq!(
         utc_timestamp(at(1_234_567_900)),
         "2009-02-13T23:31:40Z"
      );
   }

   #[test]
   fn the_leap_day_formats_as_utc() {
      assert_eq!(
         utc_timestamp(at(951_782_400)),
         "2000-02-29T00:00:00Z"
      );
   }

   #[test]
   fn sub_second_time_is_truncated_not_rounded() {
      let now = at(1_234_567_900) + Duration::from_millis(999);
      assert_eq!(utc_timestamp(now), "2009-02-13T23:31:40Z");
   }

   #[test]
   fn a_formatted_line_has_the_documented_shape() {
      let line = format_record(
         Level::Info,
         "netshield_gui::app",
         "prompt 7 presented for curl -> example.com",
         at(1_793_115_062),
      );
      assert_eq!(
         line,
         "2026-10-27T15:31:02Z INFO  netshield_gui::app: \
          prompt 7 presented for curl -> example.com\n"
      );
   }

   #[test]
   fn the_level_column_is_left_padded_to_five_characters() {
      let line = format_record(Level::Warn, "netshield_gui::ipc", "short", at(0));
      assert!(line.starts_with("1970-01-01T00:00:00Z WARN  netshield_gui::ipc: "));
      let line = format_record(Level::Error, "netshield_gui::ipc", "short", at(0));
      assert!(line.starts_with("1970-01-01T00:00:00Z ERROR netshield_gui::ipc: "));
   }

   /// Debug settings with the dependency filter in its default state.
   fn debug_settings() -> Settings {
      Settings {
         level: LevelFilter::Debug,
         all_targets: false,
      }
   }

   #[test]
   fn our_own_debug_records_are_emitted() {
      assert!(emits(
         "netshield_gui::app",
         Level::Debug,
         &debug_settings()
      ));
   }

   #[test]
   fn a_dependencys_debug_records_are_dropped() {
      assert!(!emits(
         "wgpu_core::instance",
         Level::Debug,
         &debug_settings()
      ));
   }

   #[test]
   fn a_dependencys_warnings_are_still_emitted() {
      assert!(emits(
         "wgpu_core::instance",
         Level::Warn,
         &debug_settings()
      ));
      assert!(emits(
         "wgpu_core::instance",
         Level::Error,
         &debug_settings()
      ));
   }

   #[test]
   fn all_targets_lifts_the_dependency_filter() {
      let settings = Settings {
         level: LevelFilter::Debug,
         all_targets: all_targets_from(Some("all")),
      };
      assert!(emits(
         "wgpu_core::instance",
         Level::Debug,
         &settings
      ));
      assert!(!all_targets_from(None));
      assert!(!all_targets_from(Some("wgpu")));
   }

   /// A log path no parallel test can collide on; each test removes its files.
   fn temp_path(label: &str) -> PathBuf {
      static COUNTER: AtomicUsize = AtomicUsize::new(0);
      let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
      std::env::temp_dir().join(format!(
         "netshield-gui-logging-{}-{serial}-{label}.log",
         std::process::id()
      ))
   }

   #[test]
   fn a_write_past_the_threshold_rotates_the_open_file() {
      let path = temp_path("rotate-during-write");
      let mut log = OpenLog {
         file: open_log_file(&path).expect("the temp log opens"),
         written: 0,
         path: path.clone(),
      };
      // A tiny injected threshold, so the test never writes a real mebibyte.
      log.write("first\n", 16).expect("the first line is written");
      let len = std::fs::metadata(&path).expect("the log exists").len();
      assert_eq!(len, 6);
      log.write("second line\n", 16).expect("the second line is written");
      // 6 + 12 would cross 16: the old file became `.1` and a fresh one holds the line.
      assert_eq!(
         std::fs::read_to_string(rotated_path(&path)).expect("the rotated log is readable"),
         "first\n"
      );
      assert_eq!(
         std::fs::read_to_string(&path).expect("the reopened log is readable"),
         "second line\n"
      );
      assert_eq!(log.written, 12);
      let _ = std::fs::remove_file(&path);
      let _ = std::fs::remove_file(rotated_path(&path));
   }
}
