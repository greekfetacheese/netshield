//! Reading the `rules.json` that a build of NetShield before the database wrote.
//!
//! The import runs once, on the first start that finds no database, and the file is renamed only
//! after its rules are safely in the database. A file this daemon cannot read is reported and left
//! where it is: refusing to start would leave the machine without a firewall, while starting
//! without the import only means the user is prompted again, which is the safe side of the two.
//!
//! A config from before the database can name `rules.json` itself as the rule store, so the old
//! file can sit exactly where the database belongs. That case is [`adopt`]: the file is renamed
//! before the database takes the freed path, because the database cannot be created over it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use log::{error, info};
use netshield_core::Rule;
use serde::Deserialize;

use super::StoreError;

/// The only JSON store format any NetShield build wrote.
const LEGACY_FORMAT_VERSION: u32 = 1;

/// The envelope the JSON store wrote.
#[derive(Deserialize)]
struct StoredRules {
   version: u32,
   rules: Vec<Rule>,
}

/// A legacy file that was read successfully, and the rules it held.
pub struct Legacy {
   pub rules: Vec<Rule>,
   path: PathBuf,
   /// `false` when the file was already renamed out of the way, so the caller must not rename it
   /// again: [`adopt`] has to move it before the database can take its place, while [`read`] moves
   /// it only after the rules are committed.
   pending_rename: bool,
}

/// Whether these bytes start like the JSON document a build before the database wrote.
///
/// A redb file starts with its own binary header, so the first non-blank byte decides without
/// reading a whole database off the disk on every boot.
fn looks_like_json(bytes: &[u8]) -> bool {
   bytes
      .iter()
      .find(|byte| !byte.is_ascii_whitespace())
      .is_some_and(|byte| *byte == b'{')
}

/// Reads the legacy store that sat next to `path`, if there is one.
pub fn read(path: &Path) -> Option<Legacy> {
   let legacy = path.with_extension("json");
   let bytes = match fs::read(&legacy) {
      Ok(bytes) => bytes,
      Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
      Err(error) => {
         error!(
            "the legacy rule store {} could not be read: {error}",
            legacy.display()
         );
         return None;
      }
   };

   let stored: StoredRules = match serde_json::from_slice(&bytes) {
      Ok(stored) => stored,
      Err(error) => {
         error!(
            "the legacy rule store {} is not readable, so no rule was imported from it: {error}",
            legacy.display()
         );
         return None;
      }
   };
   if stored.version != LEGACY_FORMAT_VERSION {
      error!(
         "the legacy rule store {} declares version {}, expected {LEGACY_FORMAT_VERSION}, so no \
          rule was imported from it",
         legacy.display(),
         stored.version
      );
      return None;
   }

   info!(
      "importing {} rule(s) from the legacy rule store {}",
      stored.rules.len(),
      legacy.display()
   );
   Some(Legacy {
      rules: stored.rules,
      path: legacy,
      pending_rename: true,
   })
}

/// Reads the legacy store that sits exactly at `path`, where the database belongs.
///
/// The config of a build before the database names `rules.json` as the rule store, so an upgraded
/// daemon finds the old file where its own file should be. Refusing to open it would stop the
/// firewall at boot, so the file is read, renamed to `<name>.json.migrated` and the caller creates
/// the database in the freed path. A file that looks like JSON but is not the store this build knows
/// is moved aside as `<name>.unreadable` and reported: the rules are lost from the running policy
/// either way, and the machine is safer being prompted than being unfirewalled.
pub fn adopt(path: &Path) -> Result<Option<Legacy>, StoreError> {
   let bytes = match fs::read(path) {
      Ok(bytes) => bytes,
      Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
      Err(error) => return Err(StoreError::Io(error)),
   };
   if !looks_like_json(&bytes) {
      return Ok(None);
   }

   let rules = match serde_json::from_slice::<StoredRules>(&bytes) {
      Ok(stored) if stored.version == LEGACY_FORMAT_VERSION => stored.rules,
      Ok(stored) => {
         error!(
            "the rule store {} declares JSON format version {}, expected {LEGACY_FORMAT_VERSION}",
            path.display(),
            stored.version
         );
         return unreadable(path);
      }
      Err(error) => {
         error!(
            "the rule store {} is not readable as the old JSON store: {error}",
            path.display()
         );
         return unreadable(path);
      }
   };

   let migrated = path.with_extension("json.migrated");
   fs::rename(path, &migrated)?;
   info!(
      "importing {} rule(s) from the rule store {} and moving it to {}",
      rules.len(),
      path.display(),
      migrated.display()
   );
   Ok(Some(Legacy {
      rules,
      path: migrated,
      pending_rename: false,
   }))
}

/// Moves a file that is not the store this build knows out of the database's way.
fn unreadable(path: &Path) -> Result<Option<Legacy>, StoreError> {
   let mut aside = path.as_os_str().to_owned();
   aside.push(".unreadable");
   let aside = PathBuf::from(aside);
   fs::rename(path, &aside)?;
   error!(
      "moved the unreadable rule store aside to {}: the daemon starts with no imported rule",
      aside.display()
   );
   Ok(None)
}

/// Renames an imported file out of the way, so the import cannot run twice.
pub fn mark_migrated(legacy: &Legacy) {
   if !legacy.pending_rename {
      return;
   }
   let migrated = legacy.path.with_extension("json.migrated");
   match fs::rename(&legacy.path, &migrated) {
      Ok(()) => info!(
         "renamed the imported legacy rule store to {}",
         migrated.display()
      ),
      Err(error) => error!(
         "could not rename the imported legacy rule store {}: {error}",
         legacy.path.display()
      ),
   }
}
