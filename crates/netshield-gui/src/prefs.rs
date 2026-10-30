//! The GUI's own preferences, persisted as JSON in the user's config directory.
//!
//! These are the Connections log's caps: how much history one application keeps and how many
//! applications the log tracks at once. They are render limits of this process, so they live in
//! the user's config, never in the daemon's root-owned one.

use std::fs::{self, File};
use std::io::{self, Write};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Rows the Connections log keeps per application when nothing is saved yet.
pub const DEFAULT_ROWS_PER_APP: usize = 100;

/// Applications the log tracks at once when nothing is saved yet.
pub const DEFAULT_MAX_APPS: usize = 32;

/// What the "rows per application" slider offers; below this the log keeps no real history.
pub const ROWS_PER_APP: RangeInclusive<usize> = 10..=1000;

/// What the "applications" slider offers; the log must track at least one.
pub const MAX_APPS: RangeInclusive<usize> = 1..=128;

/// The directory and the file under the config root.
const DIR: &str = "netshield";
const FILE: &str = "gui.json";

/// The persisted preferences.
///
/// Every field falls back to its default, so a file from another build still loads: a missing
/// key must never cost the user the value they did set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
   pub rows_per_app: usize,
   pub max_apps: usize,
}

impl Default for Prefs {
   fn default() -> Self {
      Self {
         rows_per_app: DEFAULT_ROWS_PER_APP,
         max_apps: DEFAULT_MAX_APPS,
      }
   }
}

impl Prefs {
   /// Pulls both caps back into their slider ranges.
   ///
   /// A hand-edited file is the one writer this cannot trust: `0` would keep no history and a
   /// million would reserve for nothing.
   pub fn clamped(self) -> Self {
      Self {
         rows_per_app: self.rows_per_app.clamp(*ROWS_PER_APP.start(), *ROWS_PER_APP.end()),
         max_apps: self.max_apps.clamp(*MAX_APPS.start(), *MAX_APPS.end()),
      }
   }

   /// Reads the preferences from `path`, whole defaults on any problem.
   ///
   /// A missing file is the normal first run; one that will not parse is logged and ignored,
   /// because a preference is never worth a window that does not open.
   pub fn load_from(path: &Path) -> Self {
      let bytes = match fs::read(path) {
         Ok(bytes) => bytes,
         Err(error) if error.kind() == io::ErrorKind::NotFound => return Self::default(),
         Err(error) => {
            log::warn!(
               "cannot read the preferences at {}: {error}",
               path.display()
            );
            return Self::default();
         }
      };
      match serde_json::from_slice::<Self>(&bytes) {
         Ok(prefs) => prefs.clamped(),
         Err(error) => {
            log::warn!(
               "ignoring unreadable preferences at {}: {error}",
               path.display()
            );
            Self::default()
         }
      }
   }

   /// Reads the user's preferences, defaulting when no config directory can be resolved.
   pub fn load() -> Self {
      Self::user_path().map_or_else(Self::default, |path| Self::load_from(&path))
   }

   /// Writes the preferences atomically: temp file, fsync, rename.
   ///
   /// A partial write must never be observable as the live preferences, so the rename is the
   /// only step that replaces the file and the temp file is removed on failure.
   pub fn save_to(&self, path: &Path) -> io::Result<()> {
      if let Some(parent) = path.parent() {
         fs::create_dir_all(parent)?;
      }
      let mut tmp = path.as_os_str().to_owned();
      tmp.push(".tmp");
      let tmp = PathBuf::from(tmp);
      let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
      let write_result = write_synced(&tmp, &bytes).and_then(|()| fs::rename(&tmp, path));
      if write_result.is_err() {
         let _ = fs::remove_file(&tmp);
      }
      write_result
   }

   /// Writes the user's preferences, reporting a failure instead of failing the app.
   pub fn save(&self) {
      let Some(path) = Self::user_path() else {
         log::warn!("no config directory resolved; the log caps will not persist");
         return;
      };
      if let Err(error) = self.save_to(&path) {
         log::warn!(
            "cannot write the preferences to {}: {error}",
            path.display()
         );
      }
   }

   /// The user's own preferences file.
   fn user_path() -> Option<PathBuf> {
      path(
         std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).as_deref(),
         std::env::var_os("HOME").map(PathBuf::from).as_deref(),
      )
   }
}

/// `<XDG_CONFIG_HOME|$HOME/.config>/netshield/gui.json`.
///
/// Takes its inputs as values so it is testable; an empty variable counts as unset, the same
/// rule the log file's path uses.
pub fn path(xdg_config_home: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
   let root = xdg_config_home
      .filter(|path| !path.as_os_str().is_empty())
      .map(Path::to_owned)
      .or_else(|| {
         home
            .filter(|path| !path.as_os_str().is_empty())
            .map(|home| home.join(".config"))
      })?;
   Some(root.join(DIR).join(FILE))
}

/// Writes `bytes` to `path` and fsyncs it before returning.
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
   let mut file = File::create(path)?;
   file.write_all(bytes)?;
   file.sync_all()
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::time::{SystemTime, UNIX_EPOCH};

   /// A fresh directory per test; the caller removes it when it is done.
   fn temp_dir(name: &str) -> PathBuf {
      let nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      std::env::temp_dir().join(format!("netshield-prefs-{name}-{nanos}"))
   }

   #[test]
   fn a_missing_file_reads_as_the_defaults() {
      assert_eq!(
         Prefs::load_from(&temp_dir("missing").join(FILE)),
         Prefs::default()
      );
   }

   #[test]
   fn an_unreadable_file_reads_as_the_defaults() {
      let dir = temp_dir("corrupt");
      let path = dir.join(FILE);
      fs::create_dir_all(&dir).expect("create the fixture directory");
      fs::write(&path, b"{ not json").expect("write the fixture");

      assert_eq!(
         Prefs::load_from(&path),
         Prefs::default(),
         "a corrupt file must never stop the GUI"
      );

      let _ = fs::remove_dir_all(&dir);
   }

   #[test]
   fn a_saved_file_round_trips_and_leaves_no_temp_file() {
      let dir = temp_dir("round-trip");
      let path = dir.join(FILE);
      let prefs = Prefs {
         rows_per_app: 250,
         max_apps: 64,
      };

      prefs.save_to(&path).expect("save");

      assert_eq!(Prefs::load_from(&path), prefs);
      let files = fs::read_dir(&dir).expect("list the directory").count();
      assert_eq!(
         files, 1,
         "the temp file is renamed away, not left behind"
      );

      let _ = fs::remove_dir_all(&dir);
   }

   #[test]
   fn a_partial_file_keeps_the_other_default() {
      let dir = temp_dir("partial");
      let path = dir.join(FILE);
      fs::create_dir_all(&dir).expect("create the fixture directory");
      fs::write(&path, br#"{"rows_per_app": 250}"#).expect("write the fixture");

      assert_eq!(
         Prefs::load_from(&path),
         Prefs {
            rows_per_app: 250,
            max_apps: DEFAULT_MAX_APPS,
         }
      );

      let _ = fs::remove_dir_all(&dir);
   }

   #[test]
   fn values_outside_the_slider_ranges_are_clamped() {
      let dir = temp_dir("clamped");
      let path = dir.join(FILE);
      fs::create_dir_all(&dir).expect("create the fixture directory");
      fs::write(
         &path,
         br#"{"rows_per_app": 0, "max_apps": 100000}"#,
      )
      .expect("write the fixture");

      let prefs = Prefs::load_from(&path);

      assert_eq!(
         prefs.rows_per_app,
         *ROWS_PER_APP.start(),
         "a zero cap would keep no history at all"
      );
      assert_eq!(prefs.max_apps, *MAX_APPS.end());

      let _ = fs::remove_dir_all(&dir);
   }

   #[test]
   fn the_path_prefers_xdg_config_home_over_home() {
      assert_eq!(
         path(
            Some(Path::new("/cfg")),
            Some(Path::new("/home/u"))
         ),
         Some(PathBuf::from("/cfg/netshield/gui.json"))
      );
      assert_eq!(
         path(None, Some(Path::new("/home/u"))),
         Some(PathBuf::from(
            "/home/u/.config/netshield/gui.json"
         ))
      );
      assert_eq!(
         path(Some(Path::new("")), None),
         None,
         "empty counts as unset"
      );
   }
}
