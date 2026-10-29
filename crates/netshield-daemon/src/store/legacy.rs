//! Reading the `rules.json` that a build of NetShield before the database wrote.
//!
//! The import runs once, on the first start that finds no database, and the file is renamed only
//! after its rules are safely in the database. A file this daemon cannot read is reported and left
//! where it is: refusing to start would leave the machine without a firewall, while starting
//! without the import only means the user is prompted again, which is the safe side of the two.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use log::{error, info};
use netshield_core::Rule;
use serde::Deserialize;

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
   })
}

/// Renames an imported file out of the way, so the import cannot run twice.
pub fn mark_migrated(legacy: &Legacy) {
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
