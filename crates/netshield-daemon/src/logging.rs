//! The daemon's stderr logger.
//!
//! systemd captures stderr into the journal, so there is no file, no rotation and no
//! dependency: one global logger that renders `LEVEL target: message` and nothing else.

use std::io::Write;

use log::{LevelFilter, Log, Metadata, Record};

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
