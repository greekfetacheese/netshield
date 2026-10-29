//! The persisted rule store: `Forever` rules in a redb database.
//!
//! The store used to rewrite one JSON file on every change, which costs the whole document in write
//! amplification for a one-field edit — a rule list that grows makes every toggle rewrite everything.
//! One record per rule, keyed by its identifier, means an edit writes only what changed, and redb
//! gives that with crash safety and almost no dependencies.
//!
//! Two things this store deliberately does NOT do. It never calls `compact()`: on this redb version
//! every compaction reallocates the arena and the resident set grows with each call, which is the
//! cost this change exists to avoid. And it never persists `hits`/`last_matched` updates — those
//! change per matched packet, and writing them would turn a read-mostly file into a write amplifier.
//!
//! The first run seeds the resolver rule (ARCHITECTURE §6). A file at the store's path that is not a
//! database is moved aside as `<name>.unreadable` rather than stopping the daemon, which would leave
//! the machine unfirewalled. A seed keyed on the resolver's executable path rather than its UID is
//! deliberate: that uid is a per-machine detail.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use log::{error, warn};
use netshield_core::{
   Action, AppMatcher, DestMatcher, Duration, Rule, RuleId, ScopeRequest, rule_from_scope,
};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use crate::store::codec::RecordError;

mod codec;

/// The schema of the database this daemon writes. A database that declares anything else is refused
/// rather than half-read: silently dropping a rule could turn a deny into a prompt.
const SCHEMA_VERSION: u32 = 1;

/// One record per rule, keyed by the identifier's eight raw bytes.
const RULES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rules");

/// The metadata table; today it holds only the schema version.
const META: TableDefinition<&str, u32> = TableDefinition::new("meta");
const SCHEMA_KEY: &str = "schema";

/// redb's default page cache is 1 GiB, which a rule table never needs. A hand-written rule list is
/// kilobytes, so a megabyte is generous and keeps the daemon's memory flat.
const PAGE_CACHE_BYTES: usize = 1024 * 1024;

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
   /// The directory or the database file could not be read or written.
   Io(io::Error),
   /// redb refused the operation.
   Redb(redb::Error),
   /// The database declares a schema this daemon must not misread.
   Schema(u32),
   /// One record cannot be read back as a rule of this version.
   Record { id: RuleId, reason: RecordError },
   /// A key in the rules table is not a rule identifier.
   Key,
}

impl fmt::Display for StoreError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Io(error) => write!(f, "rule store I/O error: {error}"),
         Self::Redb(error) => write!(f, "rule store error: {error}"),
         Self::Schema(version) => write!(
            f,
            "rule store schema version {version} is not supported (expected {SCHEMA_VERSION})"
         ),
         Self::Record { id, reason } => write!(f, "rule {id} cannot be read: {reason}"),
         Self::Key => f.write_str("the rule store holds a record key that is not a rule id"),
      }
   }
}

impl std::error::Error for StoreError {
   fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
      match self {
         Self::Io(error) => Some(error),
         Self::Redb(error) => Some(error),
         Self::Record { reason, .. } => Some(reason),
         Self::Schema(_) | Self::Key => None,
      }
   }
}

impl From<io::Error> for StoreError {
   fn from(error: io::Error) -> Self {
      Self::Io(error)
   }
}

macro_rules! redb_error {
   ($($kind:ty),+ $(,)?) => {
      $(
         impl From<$kind> for StoreError {
            fn from(error: $kind) -> Self {
               Self::Redb(error.into())
            }
         }
      )+
   };
}

redb_error!(
   redb::DatabaseError,
   redb::TransactionError,
   redb::TableError,
   redb::StorageError,
   redb::CommitError,
   redb::SetDurabilityError,
);

/// The persistent rule store.
///
/// The database handle is held by value so every mutation persists without the caller passing the
/// location again; otherwise a caller could update memory and forget the file, and the rule would
/// vanish on the next restart.
pub struct RuleStore {
   db: Database,
   rules: Vec<Rule>,
}

impl RuleStore {
   /// Opens `path`, creating it on first run, and seeds the resolver rule if this is that run.
   ///
   /// The returned flag says whether the resolver seed was written on this call, which is the only
   /// case where a rule appears without the user asking for one. An existing database is
   /// authoritative, so it is never re-seeded and never merged with anything.
   ///
   /// This runs before the firewall is installed, so failing here would leave the machine with no
   /// firewall at all. A file at `path` that is not a database redb can open is therefore moved to
   /// `<name>.unreadable` and reported rather than allowed to stop the daemon: the rules are
   /// unavailable either way and the file stays on disk for whoever wants it back. A database of an
   /// unknown *schema* is a different matter and still refuses (see `check_schema`), because that is
   /// a real store written by another version and discarding it would destroy the user's rules.
   pub fn load_or_seed(path: &Path) -> Result<(Self, bool), StoreError> {
      if let Some(parent) = path.parent()
         && !parent.as_os_str().is_empty()
      {
         fs::create_dir_all(parent)?;
      }

      let mut fresh = !path.exists();
      let db = match Database::builder().set_cache_size(PAGE_CACHE_BYTES).create(path) {
         Ok(db) => db,
         Err(error) if path.exists() => {
            let aside = unreadable_path(path);
            error!(
               "the rule store at {} cannot be opened ({error}); moving it to {} and starting with \
                the resolver seed",
               path.display(),
               aside.display()
            );
            fs::rename(path, &aside)?;
            fresh = true;
            Database::builder().set_cache_size(PAGE_CACHE_BYTES).create(path)?
         }
         Err(error) => return Err(error.into()),
      };

      let mut store = Self {
         db,
         rules: Vec::new(),
      };
      if fresh {
         let seeded = store.seed()?;
         return Ok((store, seeded));
      }

      store.check_schema()?;
      store.reload()?;
      Ok((store, false))
   }

   /// The rules as the rule engine sees them.
   pub fn rules(&self) -> &[Rule] {
      &self.rules
   }

   /// Inserts `rule`, replacing any rule with the same id, and persists that one record.
   ///
   /// Replacing by id keeps the store a set rather than a log: answering the same prompt twice must
   /// not leave two rules that can disagree.
   pub fn upsert(&mut self, rule: Rule) -> Result<(), StoreError> {
      self.upsert_many(std::slice::from_ref(&rule))
   }

   /// Inserts several rules in ONE transaction.
   ///
   /// One answer can create one rule per destination, and each commit is a durability barrier: a
   /// single transaction keeps that burst atomic and cheap instead of paying a commit per rule.
   pub fn upsert_many(&mut self, rules: &[Rule]) -> Result<(), StoreError> {
      let puts = encode_all(rules)?;
      self.apply(&puts, &[])?;

      for rule in rules {
         match self.rules.iter_mut().find(|existing| existing.id == rule.id) {
            Some(slot) => *slot = rule.clone(),
            None => self.rules.push(rule.clone()),
         }
      }
      Ok(())
   }

   /// Removes the rule with `id`, returning whether it existed, and persists the deletion.
   pub fn remove(&mut self, id: &RuleId) -> Result<bool, StoreError> {
      let key = codec::id_key(id).map_err(|reason| record_error(id, reason))?;
      let existed = self.rules.iter().any(|rule| rule.id == *id);
      if !existed {
         return Ok(false);
      }

      self.apply(&[], &[key.to_vec()])?;
      self.rules.retain(|rule| rule.id != *id);
      Ok(true)
   }

   /// Applies one batch of record writes and deletes in a single transaction.
   ///
   /// Every mutation goes through here: one place decides durability, and nothing is ever written
   /// wholesale — only the records that changed are touched.
   ///
   /// `Durability::Immediate` is redb's default and is set explicitly because a rule that survived
   /// the call must survive a crash. Rules are written by hand, never per packet, so the fsync costs
   /// nothing that matters. There is deliberately no `compact()` here: on this redb every compaction
   /// grows the resident set, which is the cost this store exists to avoid.
   fn apply(&self, puts: &[(Vec<u8>, Vec<u8>)], deletes: &[Vec<u8>]) -> Result<(), StoreError> {
      if puts.is_empty() && deletes.is_empty() {
         return Ok(());
      }

      let mut tx = self.db.begin_write()?;
      tx.set_durability(Durability::Immediate)?;
      {
         let mut table = tx.open_table(RULES)?;
         for (key, value) in puts {
            table.insert(key.as_slice(), value.as_slice())?;
         }
         for key in deletes {
            table.remove(key.as_slice())?;
         }
      }
      tx.commit()?;
      Ok(())
   }

   /// Writes the schema marker and seeds the resolver rule.
   fn seed(&mut self) -> Result<bool, StoreError> {
      self.write_schema()?;

      let Some(rule) = resolver_seed(now_secs()) else {
         warn!(
            "no systemd-resolved binary found; the resolver rule was not seeded, so DNS traffic \
             will be prompted for"
         );
         return Ok(false);
      };

      self.apply(&encode_all(std::slice::from_ref(&rule))?, &[])?;
      self.rules.push(rule);
      Ok(true)
   }

   fn write_schema(&self) -> Result<(), StoreError> {
      let tx = self.db.begin_write()?;
      {
         let mut meta = tx.open_table(META)?;
         meta.insert(SCHEMA_KEY, SCHEMA_VERSION)?;
      }
      tx.commit()?;
      Ok(())
   }

   /// Refuses a database whose schema this build does not know, including one that is not ours.
   fn check_schema(&self) -> Result<(), StoreError> {
      let tx = self.db.begin_read()?;
      let found = match tx.open_table(META) {
         Ok(meta) => meta.get(SCHEMA_KEY)?.map_or(0, |guard| guard.value()),
         // A database with no metadata table was not created by this store.
         Err(redb::TableError::TableDoesNotExist(_)) => 0,
         Err(error) => return Err(error.into()),
      };
      if found != SCHEMA_VERSION {
         return Err(StoreError::Schema(found));
      }
      Ok(())
   }

   /// Reads every record back into memory.
   fn reload(&mut self) -> Result<(), StoreError> {
      let tx = self.db.begin_read()?;
      let table = tx.open_table(RULES)?;
      let mut rules = Vec::new();
      for entry in table.iter()? {
         let (key, value) = entry?;
         let id = RuleId::from_bytes(key.value()).ok_or(StoreError::Key)?;
         let rule =
            codec::decode(id.clone(), value.value()).map_err(|reason| record_error(&id, reason))?;
         rules.push(rule);
      }

      // redb yields key order. The rule engine's final tie-break is insertion order, and
      // `created_at` is the part of it that survives a restart, so that is what orders the load.
      rules.sort_by(|left, right| (left.created_at, &left.id).cmp(&(right.created_at, &right.id)));
      self.rules = rules;
      Ok(())
   }
}

/// Builds the error that names the rule a record problem belongs to.
fn record_error(id: &RuleId, reason: RecordError) -> StoreError {
   StoreError::Record {
      id: id.clone(),
      reason,
   }
}

/// One record write: the identifier's stored key and the encoded rule.
type Put = (Vec<u8>, Vec<u8>);

/// Encodes rules as the `(key, value)` pairs one transaction writes.
fn encode_all(rules: &[Rule]) -> Result<Vec<Put>, StoreError> {
   let mut puts = Vec::with_capacity(rules.len());
   for rule in rules {
      let key = codec::id_key(&rule.id).map_err(|reason| record_error(&rule.id, reason))?;
      let value = codec::encode(rule).map_err(|reason| record_error(&rule.id, reason))?;
      puts.push((key.to_vec(), value));
   }
   Ok(puts)
}

/// The name a store that cannot be opened is kept under, so nothing is deleted on the way past.
fn unreadable_path(path: &Path) -> PathBuf {
   let mut aside = path.as_os_str().to_owned();
   aside.push(".unreadable");
   PathBuf::from(aside)
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

#[cfg(test)]
mod tests {
   use super::*;
   use std::path::PathBuf;
   use std::time::{SystemTime, UNIX_EPOCH};

   fn temp_path(name: &str) -> PathBuf {
      let nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      std::env::temp_dir().join(format!("netshield-store-{name}-{nanos}.db"))
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
   fn first_run_seeds_the_resolver_and_creates_the_database() {
      let path = temp_path("seed");
      let (store, seeded) = RuleStore::load_or_seed(&path).expect("first run");
      assert_eq!(seeded, resolver_seed(0).is_some());
      assert!(path.exists(), "the database file must be created");

      assert_eq!(
         store.rules().len(),
         usize::from(resolver_seed(0).is_some())
      );
      for rule in store.rules() {
         assert_eq!(rule.action, Action::Allow);
         assert_eq!(rule.duration, Duration::Forever);
         assert!(matches!(rule.app, AppMatcher::Exe(_)));
         assert_eq!(rule.dest, DestMatcher::Port(53));
      }
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn an_existing_database_is_authoritative_and_never_reseeded() {
      let path = temp_path("authoritative");
      let (mut store, _) = RuleStore::load_or_seed(&path).expect("first run");
      let seeded: Vec<RuleId> = store.rules().iter().map(|rule| rule.id.clone()).collect();
      for id in seeded {
         assert!(store.remove(&id).expect("clear the seed"));
      }
      let rule = sample_rule("user edited");
      store.upsert(rule.clone()).expect("save");
      drop(store);

      let (loaded, seeded) = RuleStore::load_or_seed(&path).expect("second run");
      assert!(!seeded, "an existing database is not re-seeded");
      assert_eq!(loaded.rules(), [rule]);
      drop(loaded);

      // All rules deleted is still not a first run: the seed must not come back.
      let (mut emptied, _) = RuleStore::load_or_seed(&path).expect("third run");
      let id = emptied.rules()[0].id.clone();
      assert!(emptied.remove(&id).expect("remove the only rule"));
      drop(emptied);
      let (empty, seeded) = RuleStore::load_or_seed(&path).expect("fourth run");
      assert!(!seeded);
      assert!(
         empty.rules().is_empty(),
         "an emptied database stays empty"
      );
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn a_missing_parent_directory_is_created() {
      let nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map_or(0, |elapsed| elapsed.as_nanos());
      let dir = std::env::temp_dir().join(format!("netshield-store-dir-{nanos}"));
      let path = dir.join("nested").join("rules.db");
      let (store, _) = RuleStore::load_or_seed(&path).expect("save");
      assert!(path.exists());
      assert_eq!(
         store.rules().len(),
         usize::from(resolver_seed(0).is_some())
      );
      let _ = fs::remove_dir_all(&dir);
   }

   #[test]
   fn upsert_replaces_by_id_and_reloads_every_matcher() {
      let path = temp_path("upsert");
      let (mut store, _) = RuleStore::load_or_seed(&path).expect("open");
      let first = sample_rule("first");
      let other = sample_rule("untouched");
      store.upsert_many(&[first.clone(), other.clone()]).expect("insert both");

      let mut changed = first.clone();
      changed.enabled = false;
      changed.dest = DestMatcher::Set(vec![
         DestMatcher::Domain {
            host: "api.github.com".to_owned(),
            subdomains: false,
         },
         DestMatcher::Ip("140.82.0.0/16".parse().unwrap()),
      ]);
      store.upsert(changed.clone()).expect("replace");

      assert!(store.rules().contains(&changed));
      assert!(
         store.rules().contains(&other),
         "the rule the edit did not touch keeps its value"
      );
      assert_eq!(
         store.rules().iter().filter(|rule| rule.id == first.id).count(),
         1,
         "a replacement must not append a second row"
      );
      drop(store);

      let (reloaded, _) = RuleStore::load_or_seed(&path).expect("reload");
      assert!(reloaded.rules().contains(&changed));
      assert!(reloaded.rules().contains(&other));
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn remove_persists_and_reports_whether_it_existed() {
      let path = temp_path("remove");
      let (mut store, _) = RuleStore::load_or_seed(&path).expect("open");
      let rule = sample_rule("doomed");
      store.upsert(rule.clone()).expect("insert");
      assert!(store.remove(&rule.id).expect("remove"));
      assert!(!store.rules().iter().any(|existing| existing.id == rule.id));
      assert!(!store.remove(&rule.id).expect("remove again"));
      drop(store);

      let (reloaded, _) = RuleStore::load_or_seed(&path).expect("reload");
      assert!(!reloaded.rules().iter().any(|existing| existing.id == rule.id));
      let _ = fs::remove_file(&path);
   }

   #[test]
   fn a_file_that_is_not_a_database_is_moved_aside() {
      // The daemon loads its store before it installs the firewall, so a file it cannot open must
      // never stop it: the file is kept, the rules are gone from the policy, and the machine is
      // filtered by a fresh store instead of by nothing.
      let path = temp_path("not-a-database");
      fs::write(&path, b"this is not a database\n").expect("fixture");

      let (store, seeded) =
         RuleStore::load_or_seed(&path).expect("a foreign file must not stop the daemon");
      assert_eq!(seeded, resolver_seed(0).is_some());
      assert_eq!(
         store.rules().len(),
         usize::from(resolver_seed(0).is_some())
      );

      let aside = unreadable_path(&path);
      assert!(
         aside.exists(),
         "the file is kept for the user to inspect"
      );
      assert!(
         fs::read(&aside).expect("read the kept file") == b"this is not a database\n",
         "the bytes are not touched on the way past"
      );
      drop(store);
      let (reloaded, seeded) = RuleStore::load_or_seed(&path).expect("second run");
      assert!(
         !seeded,
         "the second run opens the database it just created"
      );
      assert_eq!(
         reloaded.rules().len(),
         usize::from(resolver_seed(0).is_some())
      );
      let _ = fs::remove_file(&path);
      let _ = fs::remove_file(&aside);
   }

   #[test]
   fn a_database_of_an_unknown_schema_is_refused() {
      // A real database written by another version is not moved aside: discarding it would destroy
      // rules the user still owns, so this one refuses loudly instead.
      let path = temp_path("foreign");
      drop(Database::create(&path).expect("create a foreign database"));

      assert!(matches!(
         RuleStore::load_or_seed(&path),
         Err(StoreError::Schema(0))
      ));
      assert!(
         path.exists(),
         "the foreign database is left alone"
      );
      let _ = fs::remove_file(&path);
   }
}
