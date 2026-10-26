//! The daemon's stderr logger.
//!
//! systemd captures stderr into the journal, so there is no file, no rotation and no
//! dependency: one global logger that renders `LEVEL target: message` and nothing else.

use std::io::Write;

use log::{LevelFilter, Log, Metadata, Record};
use netshield_core::config::LogLevel;

/// Writes records to stderr, one line each.
struct StderrLogger;

static LOGGER: StderrLogger = StderrLogger;

impl Log for StderrLogger {
   fn enabled(&self, metadata: &Metadata<'_>) -> bool {
      metadata.level() <= log::max_level()
   }

   fn log(&self, record: &Record<'_>) {
      if !self.enabled(record.metadata()) {
         return;
      }
      let mut stderr = std::io::stderr().lock();
      // A failed write must not recurse into the logger; the record is lost with the
      // stream that was already broken.
      let _ = writeln!(
         stderr,
         "{} {}: {}",
         record.level(),
         record.target(),
         record.args()
      );
   }

   fn flush(&self) {
      let _ = std::io::stderr().flush();
   }
}

/// Installs the stderr logger at `level`; a second call is a no-op.
pub fn init(level: LevelFilter) {
   if log::set_logger(&LOGGER).is_ok() {
      log::set_max_level(level);
   }
}

/// Translates the configured verbosity into the filter the logger applies.
///
/// The two enums are deliberately separate: [`LogLevel`] is the persisted contract and
/// must not grow a variant just because `log` did, so the mapping is explicit here and
/// every arm is tested. Without this translation `Config::log_level` would be recorded
/// and then ignored, which is how a debug-level parse failure stayed invisible.
pub fn level_filter(level: LogLevel) -> LevelFilter {
   match level {
      LogLevel::Error => LevelFilter::Error,
      LogLevel::Warn => LevelFilter::Warn,
      LogLevel::Info => LevelFilter::Info,
      LogLevel::Debug => LevelFilter::Debug,
      LogLevel::Trace => LevelFilter::Trace,
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn every_configured_level_maps_to_its_filter() {
      assert_eq!(level_filter(LogLevel::Error), LevelFilter::Error);
      assert_eq!(level_filter(LogLevel::Warn), LevelFilter::Warn);
      assert_eq!(level_filter(LogLevel::Info), LevelFilter::Info);
      assert_eq!(level_filter(LogLevel::Debug), LevelFilter::Debug);
      assert_eq!(level_filter(LogLevel::Trace), LevelFilter::Trace);
   }
}
