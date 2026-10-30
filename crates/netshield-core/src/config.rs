use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// What to do when no rule matches a connection.
///
/// `Prompt` is the v1 default: a firewall that silently allows unmatched traffic is not
/// enforcing anything, so the unattributed case has to ask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
   #[default]
   Prompt,
   Allow,
   Deny,
}

/// What to do with a flow whose socket was already closed when the daemon attributed it.
///
/// `Drop` is the default. The application has closed the descriptor, so nothing is waiting for
/// an answer, and a process must not be able to reach the network by closing its socket fast.
/// `Allow` exists for applications that send one datagram and close immediately; `Prompt`
/// restores the pre-2026 behaviour and should not be the default, because a prompt about a
/// flow that can no longer happen teaches the owner to dismiss prompts unread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClosedFlowAction {
   #[default]
   Drop,
   Allow,
   Prompt,
}

/// What to do with a queued flow whose L4 protocol has no ports.
///
/// `Deny` is the default: SCTP, DCCP, GRE, ESP and IP-in-IP carry no port pair, so no rule
/// can express a decision about them, and an unfiltered channel is exactly what this
/// firewall exists to remove. `Allow` is the explicit way to restore the pre-2026
/// pass-through for those transports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnmatchedTransport {
   #[default]
   Deny,
   Allow,
}

/// What to do with an ICMP echo request.
///
/// `Deny` is the default: an echo request is an outbound connection attempt by any
/// reasonable reading, and an ICMP tunnel rides on it; allowing it unfiltered would keep a
/// channel no rule can gate. `Allow` restores the pre-2026 pass-through for ping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IcmpAction {
   #[default]
   Deny,
   Allow,
}

/// Verbosity of the daemon log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
   Error,
   Warn,
   #[default]
   Info,
   Debug,
   Trace,
}

/// Daemon settings, persisted as `/etc/netshield/config.json`.
///
/// Paths are kept as `PathBuf` so the daemon can pass them around without re-parsing
/// lossy strings; the defaults match the paths in ARCHITECTURE §9.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
   /// The nftables table this daemon owns and the only one it ever touches.
   ///
   /// Configurable so a second daemon can take its own table instead of colliding with the
   /// real one. The name is interpolated into an `nft` command, so it must be a plain
   /// nftables table name: no whitespace, quotes or semicolons. `#[serde(default)]` keeps
   /// every config written before this field existed loading with the original name.
   #[serde(default = "default_table")]
   pub table: String,
   /// NFQUEUE number for connection packets.
   pub queue_num: u16,
   /// NFQUEUE number for DNS answers; must differ from `queue_num`.
   pub dns_queue_num: u16,
   /// How long a prompt may stay unanswered before the configured default applies.
   pub prompt_timeout_secs: u64,
   /// Verdict for connections that match no rule.
   pub default_action: DefaultAction,
   /// How an unattributable flow whose socket is already gone is decided.
   ///
   /// `#[serde(default)]` is load-bearing: [`Config::load`] treats a JSON parse error as
   /// fatal, and every config written by the current installer lacks this key.
   #[serde(default)]
   pub unattributable_closed_flow: ClosedFlowAction,
   /// How a queued flow whose L4 protocol has no ports is decided.
   ///
   /// `#[serde(default)]` is load-bearing twice: every installed config predates the key,
   /// and the default is `deny`, so an upgrade must not open the transports this setting
   /// exists to close.
   #[serde(default)]
   pub unmatched_transport: UnmatchedTransport,
   /// How an ICMP echo request is decided.
   ///
   /// `#[serde(default)]` because every installed config predates the key, and the default
   /// is `deny`: an echo request is an outbound attempt an ICMP tunnel can ride on.
   #[serde(default)]
   pub icmp_echo: IcmpAction,
   /// The only non-root UID allowed to use the control socket.
   ///
   /// `None` means root only. It is never a wildcard: a missing value must not widen the
   /// socket permissions to every user.
   pub allowed_uid: Option<u32>,
   /// The only executable allowed to change firewall state over the control socket.
   ///
   /// Every other process of `allowed_uid` keeps read-only access. `None` means any process
   /// of `allowed_uid` may change state, which the daemon warns about at startup; a path
   /// that does not exist is a runtime refusal, not a configuration error, so that a
   /// temporarily missing GUI binary cannot stop the firewall from starting.
   /// `#[serde(default)]` keeps a config written before this key loading with the
   /// compatibility behavior instead of failing the daemon's fatal parse.
   #[serde(default)]
   pub gui_path: Option<PathBuf>,
   pub log_level: LogLevel,
   /// Unix socket the GUI connects to.
   pub socket_path: PathBuf,
   /// Where `Forever` rules are persisted.
   pub rules_path: PathBuf,
}

/// The nftables table name used when the configuration does not name one.
fn default_table() -> String {
   "netshield".to_owned()
}

impl Default for Config {
   fn default() -> Self {
      Self {
         table: default_table(),
         queue_num: 0,
         dns_queue_num: 1,
         prompt_timeout_secs: 30,
         default_action: DefaultAction::Prompt,
         unattributable_closed_flow: ClosedFlowAction::Drop,
         unmatched_transport: UnmatchedTransport::Deny,
         icmp_echo: IcmpAction::Deny,
         allowed_uid: None,
         gui_path: None,
         log_level: LogLevel::Info,
         socket_path: PathBuf::from("/run/netshield/control.sock"),
         rules_path: PathBuf::from("/etc/netshield/rules.db"),
      }
   }
}

/// Everything that can go wrong loading, validating or saving the configuration.
#[derive(Debug)]
pub enum ConfigError {
   Io(io::Error),
   Json(serde_json::Error),
   Invalid(String),
}

impl fmt::Display for ConfigError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Io(error) => write!(f, "configuration I/O error: {error}"),
         Self::Json(error) => write!(f, "configuration JSON error: {error}"),
         Self::Invalid(message) => write!(f, "invalid configuration: {message}"),
      }
   }
}

impl std::error::Error for ConfigError {
   fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
      match self {
         Self::Io(error) => Some(error),
         Self::Json(error) => Some(error),
         Self::Invalid(_) => None,
      }
   }
}

impl From<io::Error> for ConfigError {
   fn from(error: io::Error) -> Self {
      Self::Io(error)
   }
}

impl From<serde_json::Error> for ConfigError {
   fn from(error: serde_json::Error) -> Self {
      Self::Json(error)
   }
}

impl Config {
   /// The nftables table this daemon owns.
   pub fn table_name(&self) -> &str {
      &self.table
   }

   /// Rejects settings the daemon cannot run with.
   ///
   /// Two queues sharing a number would make DNS answers compete with connection
   /// packets for the same verdict path, and an out-of-range timeout would either make
   /// prompts unusable or leave flows queued indefinitely.
   pub fn validate(&self) -> Result<(), ConfigError> {
      if self.queue_num == self.dns_queue_num {
         return Err(ConfigError::Invalid(format!(
            "queue_num and dns_queue_num must differ (both are {})",
            self.queue_num
         )));
      }
      if !(1..=600).contains(&self.prompt_timeout_secs) {
         return Err(ConfigError::Invalid(format!(
            "prompt_timeout_secs must be in 1..=600, got {}",
            self.prompt_timeout_secs
         )));
      }
      // The name goes straight into an `nft` command, so anything that could be read as
      // syntax — or as a second argument — must be refused rather than quoted away.
      if self.table.is_empty()
         || self
            .table
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == ';')
      {
         return Err(ConfigError::Invalid(format!(
            "table must be a plain nftables table name (no whitespace, quotes or semicolon), \
             got {:?}",
            self.table
         )));
      }
      Ok(())
   }

   /// Loads settings from `path`.
   ///
   /// A missing file yields [`Config::default`] so a first run needs no bootstrap file;
   /// every other failure is surfaced. Falling back to defaults on a parse error would
   /// silently discard the operator's queue numbers and default action.
   pub fn load(path: &Path) -> Result<Self, ConfigError> {
      let bytes = match fs::read(path) {
         Ok(bytes) => bytes,
         Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
         Err(error) => return Err(ConfigError::Io(error)),
      };

      let config: Self = serde_json::from_slice(&bytes)?;
      config.validate()?;
      Ok(config)
   }

   /// Writes the configuration atomically: temp file, fsync, rename.
   ///
   /// A partial write must never be observable as the live configuration, so the rename
   /// is the only step that replaces the real file. The temp file is cleaned up on
   /// failure rather than left for the next run to trip over.
   pub fn save_atomic(&self, path: &Path) -> Result<(), ConfigError> {
      self.validate()?;

      let mut tmp = path.as_os_str().to_owned();
      tmp.push(".tmp");
      let tmp = PathBuf::from(tmp);

      let bytes = serde_json::to_vec_pretty(self)?;
      let write_result = write_synced(&tmp, &bytes).and_then(|()| fs::rename(&tmp, path));
      if write_result.is_err() {
         let _ = fs::remove_file(&tmp);
      }
      write_result?;
      Ok(())
   }
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
      std::env::temp_dir().join(format!("netshield-{name}-{nanos}.json"))
   }

   #[test]
   fn defaults_match_the_documented_paths() {
      let config = Config::default();
      assert_eq!(config.queue_num, 0);
      assert_eq!(config.dns_queue_num, 1);
      assert_eq!(config.prompt_timeout_secs, 30);
      assert_eq!(config.default_action, DefaultAction::Prompt);
      assert_eq!(
         config.unattributable_closed_flow,
         ClosedFlowAction::Drop,
         "a closed flow is dropped unless the owner says otherwise"
      );
      assert_eq!(config.allowed_uid, None);
      assert_eq!(config.log_level, LogLevel::Info);
      assert_eq!(
         config.socket_path,
         PathBuf::from("/run/netshield/control.sock")
      );
      assert_eq!(
         config.rules_path,
         PathBuf::from("/etc/netshield/rules.db")
      );
      assert!(config.validate().is_ok());
   }

   #[test]
   fn an_installed_config_without_the_new_keys_still_loads() {
      // Exactly what the current installer writes: neither the flow-action key nor the
      // table key exists yet, and both must take their documented defaults.
      let installed = r#"{
  "queue_num": 0,
  "dns_queue_num": 1,
  "prompt_timeout_secs": 30,
  "default_action": "prompt",
  "allowed_uid": null,
  "log_level": "info",
  "socket_path": "/run/netshield/control.sock",
  "rules_path": "/etc/netshield/rules.db"
}"#;
      let config: Config = serde_json::from_str(installed).expect("the installed config must load");
      assert_eq!(
         config.unattributable_closed_flow,
         ClosedFlowAction::Drop
      );
      assert_eq!(
         config.unmatched_transport,
         UnmatchedTransport::Deny,
         "an installed config without the key must not open port-less transports"
      );
      assert_eq!(
         config.icmp_echo,
         IcmpAction::Deny,
         "an installed config without the key must not allow ICMP echo"
      );
      assert_eq!(config.table_name(), "netshield");
      assert_eq!(Config::default().table_name(), "netshield");
      assert_eq!(Config::default().table, "netshield");
      assert_eq!(
         config.gui_path, None,
         "an installed config without the key keeps the compatibility behavior"
      );

      for (json, expected) in [
         ("\"allow\"", ClosedFlowAction::Allow),
         ("\"prompt\"", ClosedFlowAction::Prompt),
         ("\"drop\"", ClosedFlowAction::Drop),
      ] {
         let action: ClosedFlowAction =
            serde_json::from_str(json).expect("a valid ClosedFlowAction");
         assert_eq!(
            action, expected,
            "{json} must decode to {expected:?}"
         );
      }

      // The default config serializes `drop`, and the daemon can read that back: the
      // installer's sample and the save path must agree with the field's default.
      let json = serde_json::to_string(&Config::default()).expect("serialize the default config");
      let back: Config = serde_json::from_str(&json).expect("read our own default back");
      assert_eq!(
         back.unattributable_closed_flow,
         ClosedFlowAction::Drop
      );
      assert_eq!(back, Config::default());
   }

   #[test]
   fn the_transport_settings_default_to_deny_and_round_trip() {
      // The defaults are the security posture: a missing key must deny, never allow.
      assert_eq!(
         UnmatchedTransport::default(),
         UnmatchedTransport::Deny
      );
      assert_eq!(IcmpAction::default(), IcmpAction::Deny);
      assert_eq!(
         Config::default().unmatched_transport,
         UnmatchedTransport::Deny
      );
      assert_eq!(Config::default().icmp_echo, IcmpAction::Deny);

      let config = Config {
         unmatched_transport: UnmatchedTransport::Allow,
         icmp_echo: IcmpAction::Allow,
         ..Config::default()
      };
      let json = serde_json::to_string(&config).expect("serialize the transport settings");
      assert!(
         json.contains("\"unmatched_transport\":\"allow\""),
         "the key must be written lowercase, got: {json}"
      );
      assert!(
         json.contains("\"icmp_echo\":\"allow\""),
         "the key must be written lowercase, got: {json}"
      );
      let back: Config = serde_json::from_str(&json).expect("read the transport settings back");
      assert_eq!(back, config);

      // An explicit `deny` also round-trips, so the owner can spell out the default.
      let config = Config {
         unmatched_transport: UnmatchedTransport::Deny,
         icmp_echo: IcmpAction::Deny,
         ..Config::default()
      };
      let back: Config = serde_json::from_str(&serde_json::to_string(&config).expect("serialize"))
         .expect("deserialize");
      assert_eq!(back, config);
   }

   #[test]
   fn the_table_name_is_configured_and_validated() {
      let json = "{\"table\": \"netshielddiag\", \"queue_num\": 0, \"dns_queue_num\": 1, \
                  \"prompt_timeout_secs\": 30, \"default_action\": \"prompt\", \
                  \"allowed_uid\": null, \"log_level\": \"info\", \
                  \"socket_path\": \"/run/x\", \"rules_path\": \"/etc/x\"}";
      let config: Config = serde_json::from_str(json).expect("a valid table name must load");
      assert_eq!(config.table_name(), "netshielddiag");
      assert!(config.validate().is_ok());

      for bad in ["", " ", "a b", "a;b", "a\"b", "a'b", "a\tb"] {
         let config = Config {
            table: bad.to_owned(),
            ..Config::default()
         };
         let err = config.validate().expect_err("a bad table name must be refused");
         assert!(
            matches!(err, ConfigError::Invalid(_)),
            "{bad:?} must be a config error"
         );
         let message = err.to_string();
         assert!(
            message.contains("table"),
            "the message must name the field, got: {message}"
         );
      }
   }

   #[test]
   fn validate_rejects_the_documented_errors() {
      let equal_queues = Config {
         queue_num: 7,
         dns_queue_num: 7,
         ..Config::default()
      };
      assert!(
         matches!(
            equal_queues.validate(),
            Err(ConfigError::Invalid(_))
         ),
         "equal queue numbers must be rejected"
      );

      for bad in [0, 601] {
         let config = Config {
            prompt_timeout_secs: bad,
            ..Config::default()
         };
         assert!(
            matches!(config.validate(), Err(ConfigError::Invalid(_))),
            "timeout {bad} should be rejected"
         );
      }
      for good in [1, 600] {
         let config = Config {
            prompt_timeout_secs: good,
            ..Config::default()
         };
         assert!(
            config.validate().is_ok(),
            "timeout {good} should be accepted"
         );
      }
   }

   #[test]
   fn a_configured_gui_path_is_preserved_and_an_absent_one_defaults() {
      // The key is what lets the daemon tell the configured GUI from any other process of
      // the same uid, so a configured path must survive serialisation exactly.
      let path = PathBuf::from("/usr/local/bin/netshield-gui");
      let config = Config {
         gui_path: Some(path.clone()),
         ..Config::default()
      };
      assert_eq!(config.gui_path.as_deref(), Some(path.as_path()));
      let json = serde_json::to_string(&config).expect("serialize");
      let back: Config = serde_json::from_str(&json).expect("deserialize");
      assert_eq!(back.gui_path, Some(path));

      // A config that predates the key must not fail to load: the daemon then warns and
      // keeps the historical uid-only rule.
      let without = "{\"queue_num\": 0, \"dns_queue_num\": 1, \"prompt_timeout_secs\": 30, \
                     \"default_action\": \"prompt\", \"allowed_uid\": 1000, \
                     \"log_level\": \"info\", \"socket_path\": \"/run/x\", \
                     \"rules_path\": \"/etc/x\"}";
      let config: Config = serde_json::from_str(without).expect("an old config must load");
      assert_eq!(config.gui_path, None);
   }

   #[test]
   fn the_config_round_trips_through_serde() {
      let config = Config {
         queue_num: 3,
         dns_queue_num: 4,
         prompt_timeout_secs: 45,
         default_action: DefaultAction::Deny,
         allowed_uid: Some(1000),
         gui_path: Some(PathBuf::from("/usr/local/bin/netshield-gui")),
         log_level: LogLevel::Trace,
         ..Config::default()
      };
      let json = serde_json::to_string(&config).unwrap();
      let back: Config = serde_json::from_str(&json).unwrap();
      assert_eq!(back, config);

      assert_eq!(
         serde_json::to_string(&DefaultAction::Prompt).unwrap(),
         "\"prompt\""
      );
      assert_eq!(
         serde_json::to_string(&LogLevel::Warn).unwrap(),
         "\"warn\""
      );
      assert_eq!(
         serde_json::to_string(&ClosedFlowAction::Drop).unwrap(),
         "\"drop\""
      );
   }

   #[test]
   fn the_store_round_trips_and_refuses_an_invalid_config() {
      let path = temp_path("roundtrip");
      let config = Config {
         queue_num: 5,
         dns_queue_num: 6,
         ..Config::default()
      };
      config.save_atomic(&path).expect("save");
      assert_eq!(Config::load(&path).expect("load"), config);

      let mut tmp = path.as_os_str().to_owned();
      tmp.push(".tmp");
      assert!(
         !Path::new(&tmp).exists(),
         "temp file must be renamed away"
      );
      let _ = fs::remove_file(&path);

      let path = temp_path("refused");
      let invalid = Config {
         prompt_timeout_secs: 0,
         ..Config::default()
      };
      assert!(matches!(
         invalid.save_atomic(&path),
         Err(ConfigError::Invalid(_))
      ));
      assert!(!path.exists());
   }

   #[test]
   fn load_defaults_a_missing_file_and_rejects_a_bad_one() {
      let path = temp_path("missing");
      assert!(!path.exists());
      assert_eq!(
         Config::load(&path).expect("missing is default"),
         Config::default()
      );

      let path = temp_path("malformed");
      fs::write(&path, b"{ not json").expect("write fixture");
      assert!(matches!(
         Config::load(&path),
         Err(ConfigError::Json(_))
      ));
      let _ = fs::remove_file(&path);

      let path = temp_path("invalid");
      let mut config = Config::default();
      config.dns_queue_num = config.queue_num;
      fs::write(&path, serde_json::to_vec(&config).unwrap()).expect("write fixture");
      assert!(matches!(
         Config::load(&path),
         Err(ConfigError::Invalid(_))
      ));
      let _ = fs::remove_file(&path);
   }
}
