//! The persisted rule store, and the first-run rule that keeps DNS from prompting.
//!
//! `Forever` rules outlive the daemon, so they live in one JSON file whose schema is
//! versioned: a future format must be rejected rather than half-read, because silently
//! dropping a rule could turn a deny into a prompt. The store never merges a file with
//! in-memory rules — an existing file is authoritative — which makes a restart
//! deterministic and keeps the GUI's edits from being overwritten by a stale seed.
//!
//! The first-run seed exists because a user must never be asked about their own DNS
//! (ARCHITECTURE §6). It is keyed on the resolver binary path, not on the resolver's
//! UID: UIDs differ between machines, so a UID-keyed rule would be a per-machine guess.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use log::warn;
use netshield_core::{
   Action, AppMatcher, DestMatcher, Duration, Rule, RuleId, ScopeRequest, rule_from_scope,
};
use serde::{Deserialize, Serialize};

/// The only store format this daemon understands.
const FORMAT_VERSION: u32 = 1;

/// Where systemd's resolver binary is installed, most specific first.
///
/// The list is probed in order and the first path that exists becomes the seed's
/// application matcher. It is a path list rather than a name lookup so the seed cannot
/// accidentally match a different binary that happens to share the basename.
const RESOLVER_PATHS: [&str; 3] = [
   "/usr/lib/systemd/systemd-resolved",
   "/lib/systemd/systemd-resolved",
   "/usr/sbin/systemd-resolved",
];

/// Why loading, saving or mutating the rule store failed.
#[derive(Debug)]
pub enum StoreError {
   /// The file or its parent directory could not be read or written.
   Io(io::Error),
   /// The file is not the JSON document this daemon writes.
   Json(serde_json::Error),
   /// The file declares a format version this daemon must not misread.
   Version(u32),
}

impl fmt::Display for StoreError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Io(error) => write!(f, "rule store I/O error: {error}"),
         Self::Json(error) => write!(f, "rule store JSON error: {error}"),
         Self::Version(version) => write!(
            f,
            "rule store format version {version} is not supported (expected {FORMAT_VERSION})"
         ),
      }
   }
}

impl std::error::Error for StoreError {
   fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
      match self {
         Self::Io(error) => Some(error),
         Self::Json(error) => Some(error),
         Self::Version(_) => None,
      }
   }
}

impl From<io::Error> for StoreError {
   fn from(error: io::Error) -> Self {
      Self::Io(error)
   }
}

impl From<serde_json::Error> for StoreError {
   fn from(error: serde_json::Error) -> Self {
      Self::Json(error)
   }
}

/// The on-disk envelope: a version tag plus the rules themselves.
#[derive(Debug, Serialize, Deserialize)]
struct StoredRules {
   version: u32,
   rules: Vec<Rule>,
}

/// Reads only the version, so a future format is reported as [`StoreError::Version`]
/// even when its rule encoding no longer matches this daemon's.
#[derive(Debug, Deserialize)]
struct VersionProbe {
   version: u32,
}

/// The persistent rule store.
///
/// The path is held by value so every mutation persists without the caller passing the
/// location again; otherwise a caller could update memory and forget the file, and the
/// rule would vanish on the next restart.
#[derive(Debug)]
pub struct RuleStore {
   path: PathBuf,
   rules: Vec<Rule>,
}

impl RuleStore {
   /// Loads `path`, seeding the resolver rule on first run.
   ///
   /// A missing file is the first run: the seed is computed, persisted and reported as
   /// `true`. An existing file is authoritative, so it is never re-seeded or merged with
   /// anything — a store the user edited must survive a restart untouched. If no resolver
   /// binary exists the store is still created (empty) with a warning, so the machine
   /// prompts rather than silently allowing DNS.
   pub fn load_or_seed(path: &Path) -> Result<(Self, bool), StoreError> {
      let bytes = match fs::read(path) {
         Ok(bytes) => bytes,
         Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut rules = Vec::new();
            match resolver_seed(now_secs()) {
               Some(rule) => rules.push(rule),
               None => warn!(
                  "no systemd-resolved binary found; the resolver rule was not seeded, so \
                   DNS traffic will be prompted for"
               ),
            }
            let store = Self {
               path: path.to_path_buf(),
               rules,
            };
            store.save_atomic()?;
            return Ok((store, true));
         }
         Err(error) => return Err(StoreError::Io(error)),
      };

      let probe: VersionProbe = serde_json::from_slice(&bytes)?;
      if probe.version != FORMAT_VERSION {
         return Err(StoreError::Version(probe.version));
      }
      let stored: StoredRules = serde_json::from_slice(&bytes)?;
      Ok((
         Self {
            path: path.to_path_buf(),
            rules: stored.rules,
         },
         false,
      ))
   }

   /// The rules as the rule engine sees them.
   pub fn rules(&self) -> &[Rule] {
      &self.rules
   }

   /// Writes the store atomically: temp file, fsync, rename.
   ///
   /// A crash must never expose a half-written rule file, so the rename is the only step
   /// that replaces the live store. The parent directory is created first because the
   /// daemon may start before `/etc/netshield` exists on a fresh install.
   pub fn save_atomic(&self) -> Result<(), StoreError> {
      if let Some(parent) = self.path.parent()
         && !parent.as_os_str().is_empty()
      {
         fs::create_dir_all(parent)?;
      }

      let mut tmp = self.path.as_os_str().to_owned();
      tmp.push(".tmp");
      let tmp = PathBuf::from(tmp);

      let stored = StoredRules {
         version: FORMAT_VERSION,
         rules: self.rules.clone(),
      };
      let bytes = serde_json::to_vec_pretty(&stored)?;
      let written = write_synced(&tmp, &bytes).and_then(|()| fs::rename(&tmp, &self.path));
      if written.is_err() {
         let _ = fs::remove_file(&tmp);
      }
      written?;
      Ok(())
   }

   /// Inserts `rule`, replacing any rule with the same id, and persists.
   ///
   /// The replacement keeps the store a set keyed by id rather than a log: answering the
   /// same prompt twice must not leave two rules that can disagree. Replacing in place
   /// preserves insertion order, which is the rule engine's last tie-break.
   pub fn upsert(&mut self, rule: Rule) -> Result<(), StoreError> {
      if let Some(slot) = self.rules.iter_mut().find(|existing| existing.id == rule.id) {
         *slot = rule;
      } else {
         self.rules.push(rule);
      }
      self.save_atomic()
   }

   /// Removes the rule with `id`, returning whether it existed, and persists.
   pub fn remove(&mut self, id: &RuleId) -> Result<bool, StoreError> {
      let before = self.rules.len();
      self.rules.retain(|rule| rule.id != *id);
      let removed = self.rules.len() != before;
      if removed {
         self.save_atomic()?;
      }
      Ok(removed)
   }
}

/// The first-run resolver seed described in ARCHITECTURE §6, or `None` when no resolver
/// binary exists.
///
/// The rule allows the resolver binary to reach port 53 forever, so the user is never
/// prompted about their own DNS. Matching on the executable path rather than a UID is
/// deliberate: the resolver's UID is a per-machine deployment detail, and a UID rule
/// would either miss or over-grant on the next machine.
pub fn resolver_seed(now: u64) -> Option<Rule> {
   let exe = RESOLVER_PATHS.iter().map(PathBuf::from).find(|candidate| candidate.exists())?;
   let scope = ScopeRequest {
      action: Action::Allow,
      duration: Duration::Forever,
      dest: DestMatcher::Port(53),
   };
   let mut rule = rule_from_scope(
      RuleId::new_unique(),
      AppMatcher::Exe(exe),
      &scope,
      now,
   );
   rule.note = Some("seeded on first run: the system resolver's DNS must not prompt".to_owned());
   Some(rule)
}

/// Seconds since the Unix epoch, or 0 when the clock is before it.
fn now_secs() -> u64 {
   std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs())
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

   fn temp_path(name: &str) -> PathBuf {
      let nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      std::env::temp_dir().join(format!("netshield-store-{name}-{nanos}.json"))
   }

   fn sample_rule(note: &str) -> Rule {
      let scope = ScopeRequest {
         action: Action::Deny,
         duration: Duration::Forever,
         dest: DestMatcher::Port(443),
      };
      let mut rule = rule_from_scope(
         RuleId::new_unique(),
         AppMatcher::Any,
         &scope,
         1_700_000_000,
      );
      rule.note = Some(note.to_owned());
      rule
   }

   #[test]
   fn first_load_seeds_exactly_one_rule_and_saves_it() {
      let path = temp_path("seed");
      let (store, seeded) = RuleStore::load_or_seed(&path).expect("first run");
      assert!(seeded, "a missing file must report a first run");
      assert!(path.exists(), "the seed must be persisted");

      let expected = usize::from(resolver_seed(0).is_some());
      assert_eq!(store.rules().len(), expected);
      for rule in store.rules() {
         assert_eq!(rule.action, Action::Allow);
         assert_eq!(rule.duration, Duration::Forever);
         assert!(matches!(rule.app, AppMatcher::Exe(_)));
         assert_eq!(rule.dest, DestMatcher::Port(53));
      }
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn second_load_is_authoritative_and_never_reseeds() {
      let path = temp_path("authoritative");
      let rule = sample_rule("user edited");
      let mut store = RuleStore {
         path: path.clone(),
         rules: Vec::new(),
      };
      store.upsert(rule.clone()).expect("save");

      let (loaded, seeded) = RuleStore::load_or_seed(&path).expect("second run");
      assert!(!seeded, "an existing file is not a first run");
      assert_eq!(loaded.rules(), [rule]);
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn empty_existing_file_is_not_reseeded() {
      let path = temp_path("empty");
      let store = RuleStore {
         path: path.clone(),
         rules: Vec::new(),
      };
      store.save_atomic().expect("save empty store");

      let (loaded, seeded) = RuleStore::load_or_seed(&path).expect("load empty store");
      assert!(!seeded);
      assert!(loaded.rules().is_empty());
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn load_rejects_a_future_version() {
      let path = temp_path("version");
      fs::write(&path, br#"{"version":2,"rules":[]}"#).expect("write fixture");
      assert!(matches!(
         RuleStore::load_or_seed(&path),
         Err(StoreError::Version(2))
      ));
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn load_rejects_malformed_json() {
      let path = temp_path("malformed");
      fs::write(&path, b"{ not json").expect("write fixture");
      assert!(matches!(
         RuleStore::load_or_seed(&path),
         Err(StoreError::Json(_))
      ));
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn file_format_is_version_one_with_a_rules_array() {
      let path = temp_path("format");
      let mut store = RuleStore {
         path: path.clone(),
         rules: Vec::new(),
      };
      store.upsert(sample_rule("format")).expect("save");

      let value: serde_json::Value =
         serde_json::from_slice(&fs::read(&path).expect("read")).expect("json");
      assert_eq!(value["version"], 1);
      assert_eq!(value["rules"].as_array().map(Vec::len), Some(1));
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn upsert_replaces_by_id_and_persists() {
      let path = temp_path("upsert");
      let mut store = RuleStore {
         path: path.clone(),
         rules: Vec::new(),
      };
      let rule = sample_rule("first");
      store.upsert(rule.clone()).expect("insert");

      let mut changed = rule.clone();
      changed.enabled = false;
      store.upsert(changed.clone()).expect("replace");

      assert_eq!(store.rules(), [changed.clone()]);
      let (reloaded, _) = RuleStore::load_or_seed(&path).expect("reload");
      assert_eq!(reloaded.rules(), [changed]);
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn remove_persists_and_reports_whether_the_rule_existed() {
      let path = temp_path("remove");
      let mut store = RuleStore {
         path: path.clone(),
         rules: Vec::new(),
      };
      let rule = sample_rule("doomed");
      store.upsert(rule.clone()).expect("insert");
      assert!(store.remove(&rule.id).expect("remove"));
      assert!(store.rules().is_empty());

      let (reloaded, _) = RuleStore::load_or_seed(&path).expect("reload");
      assert!(reloaded.rules().is_empty());
      assert!(!store.remove(&rule.id).expect("remove again"));
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn save_atomic_creates_the_parent_directory_and_leaves_no_tmp() {
      let nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      let dir = std::env::temp_dir().join(format!("netshield-store-dir-{nanos}"));
      let path = dir.join("nested").join("rules.json");
      let store = RuleStore {
         path: path.clone(),
         rules: Vec::new(),
      };
      store.save_atomic().expect("save");

      let mut tmp = path.as_os_str().to_owned();
      tmp.push(".tmp");
      assert!(
         !Path::new(&tmp).exists(),
         "the temp file must be renamed away"
      );
      let _ = fs::remove_dir_all(&dir);
   }
}
