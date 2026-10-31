//! `netshieldctl`: the control-socket actions only root may make.
//!
//! The daemon refuses `SetMode`, a `Forever` rule and deleting a `Deny` rule from any peer
//! whose uid is not 0. The socket is already owned by the desktop user and accepts uid 0,
//! so this binary is simply that second peer: it connects, handshakes, performs one
//! mutation and reads the state back to prove the mutation took effect.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration as ReadTimeout, SystemTime, UNIX_EPOCH};

use netshield_core::ipc::{
   ClientKind, MAX_FRAME_LEN, Mode, PROTOCOL_VERSION, Request, Response, decode_line, encode_line,
};
use netshield_core::ipnet::IpNet;
use netshield_core::rule::{Action, AppMatcher, DestMatcher, Duration, Rule, RuleId};

const DEFAULT_SOCKET: &str = "/run/netshield/control.sock";

/// How long a reply that the daemon is expected to send may take.
const REPLY_TIMEOUT: ReadTimeout = ReadTimeout::from_secs(5);

/// How long to wait for the error frame a mutation may produce. The daemon sends nothing
/// on success, so this timeout expires on the successful path.
const MUTATION_TIMEOUT: ReadTimeout = ReadTimeout::from_secs(1);

const USAGE: &str = "\
netshieldctl — perform the NetShield changes only root may make

USAGE:
    netshieldctl [--socket PATH] set-mode <alert|silent>
    netshieldctl [--socket PATH] allow --exe PATH --dest SPEC [--note TEXT] [--subdomains]
    netshieldctl [--socket PATH] deny  --exe PATH --dest SPEC [--note TEXT] [--subdomains]
    netshieldctl [--socket PATH] enable  <RULE-ID>
    netshieldctl [--socket PATH] disable <RULE-ID>
    netshieldctl [--socket PATH] delete  <RULE-ID>

--socket defaults to /run/netshield/control.sock. SPEC is one of:
    any
    ip:<addr> or ip:<addr>/<prefix>
    domain:<host>
    port:<n>
";

/// The accepted `--dest` forms, repeated in every destination parse error.
const DEST_FORMS: &str = "any, ip:<addr>[/<prefix>], domain:<host>, or port:<n>";

/// What the command line asks the daemon to do.
#[derive(Debug)]
enum Command {
   SetMode(Mode),
   Upsert {
      action: Action,
      exe: PathBuf,
      dest: DestMatcher,
      note: Option<String>,
   },
   SetEnabled {
      id: RuleId,
      enabled: bool,
   },
   Delete {
      id: RuleId,
   },
}

/// The parsed socket path and exactly one command.
#[derive(Debug)]
struct Args {
   socket: PathBuf,
   command: Command,
}

fn main() -> ExitCode {
   match run() {
      Ok(()) => ExitCode::SUCCESS,
      Err(reason) => {
         eprintln!("netshieldctl: {reason}");
         ExitCode::FAILURE
      }
   }
}

fn run() -> Result<(), String> {
   let args = parse_args(std::env::args().skip(1).collect())?;

   // Refusing before connecting keeps a non-root invocation from even touching the socket.
   if effective_uid()? != 0 {
      return Err("must run as root: sudo netshieldctl …".to_owned());
   }

   let mut stream = UnixStream::connect(&args.socket)
      .map_err(|err| format!("cannot connect to {:?}: {err}", args.socket))?;

   set_read_timeout(&stream, REPLY_TIMEOUT)?;
   handshake(&mut stream)?;

   match args.command {
      Command::SetMode(mode) => {
         mutate(&mut stream, &Request::SetMode { mode })?;
         let status = match query(&mut stream, &Request::Status)? {
            Response::Status(status) => status,
            other => return Err(format!("unexpected reply to Status: {other:?}")),
         };
         println!("mode: {:?}", status.mode);
      }
      Command::Upsert {
         action,
         exe,
         dest,
         note,
      } => {
         let rule = build_rule(exe.clone(), dest, action, note, now());
         let id = rule.id.clone();
         mutate(&mut stream, &Request::UpsertRule { rule })?;
         let rules = list_rules(&mut stream)?;
         if !rules.iter().any(|rule| rule.id == id) {
            return Err(format!("rule {id} was not created"));
         }
         for rule in rules
            .iter()
            .filter(|rule| matches!(&rule.app, AppMatcher::Exe(path) if path == &exe))
         {
            println!("{}", rule_line(rule));
         }
      }
      Command::SetEnabled { id, enabled } => {
         mutate(
            &mut stream,
            &Request::SetRuleEnabled {
               id: id.clone(),
               enabled,
            },
         )?;
         let rules = list_rules(&mut stream)?;
         let rule = rules
            .iter()
            .find(|rule| rule.id == id)
            .ok_or_else(|| format!("rule {id} is not present"))?;
         if rule.enabled != enabled {
            return Err(format!(
               "the daemon still reports rule {id} as {}",
               enabled_label(rule.enabled)
            ));
         }
         println!(
            "{} {}",
            rule_line(rule),
            enabled_label(rule.enabled)
         );
      }
      Command::Delete { id } => {
         mutate(
            &mut stream,
            &Request::DeleteRule { id: id.clone() },
         )?;
         let rules = list_rules(&mut stream)?;
         if rules.iter().any(|rule| rule.id == id) {
            return Err(format!("rule {id} is still present"));
         }
         println!("deleted {id}; {} rule(s) remain", rules.len());
      }
   }

   Ok(())
}

/// Parses the whole command line without touching the socket.
fn parse_args(args: Vec<String>) -> Result<Args, String> {
   let (socket, rest) = match args.split_first() {
      Some((flag, rest)) if flag == "--socket" => {
         let (path, rest) = rest.split_first().ok_or_else(|| "--socket needs a path".to_owned())?;
         (PathBuf::from(path), rest)
      }
      _ => (PathBuf::from(DEFAULT_SOCKET), args.as_slice()),
   };

   let (command, tail) = rest.split_first().ok_or_else(|| {
      usage();
      "missing command".to_owned()
   })?;

   let command = match command.as_str() {
      "set-mode" => {
         let mode = match tail {
            [mode] => parse_mode(mode)?,
            [] => {
               usage();
               return Err("set-mode needs a mode (alert or silent)".to_owned());
            }
            _ => {
               usage();
               return Err("set-mode takes exactly one mode (alert or silent)".to_owned());
            }
         };
         Command::SetMode(mode)
      }
      "allow" => parse_upsert(tail, Action::Allow)?,
      "deny" => parse_upsert(tail, Action::Deny)?,
      "enable" => Command::SetEnabled {
         id: one_rule_id(tail, "enable")?,
         enabled: true,
      },
      "disable" => Command::SetEnabled {
         id: one_rule_id(tail, "disable")?,
         enabled: false,
      },
      "delete" => Command::Delete {
         id: one_rule_id(tail, "delete")?,
      },
      other => {
         usage();
         return Err(format!("unknown command: {other}"));
      }
   };

   Ok(Args { socket, command })
}

fn parse_mode(raw: &str) -> Result<Mode, String> {
   match raw {
      "alert" => Ok(Mode::Alert),
      "silent" => Ok(Mode::Silent),
      other => {
         usage();
         Err(format!(
            "unknown mode: {other} (expected alert or silent)"
         ))
      }
   }
}

/// Parses the flags of `allow`/`deny`, refusing anything outside the documented surface.
fn parse_upsert(tail: &[String], action: Action) -> Result<Command, String> {
   let mut exe: Option<PathBuf> = None;
   let mut dest_spec: Option<String> = None;
   let mut note: Option<String> = None;
   let mut subdomains = false;

   let mut index = 0;
   while index < tail.len() {
      match tail[index].as_str() {
         "--exe" => {
            let value = tail.get(index + 1).ok_or_else(|| "--exe needs a path".to_owned())?;
            if exe.replace(PathBuf::from(value)).is_some() {
               return Err("--exe given more than once".to_owned());
            }
            index += 2;
         }
         "--dest" => {
            let value = tail.get(index + 1).ok_or_else(|| "--dest needs a spec".to_owned())?;
            if dest_spec.replace(value.clone()).is_some() {
               return Err("--dest given more than once".to_owned());
            }
            index += 2;
         }
         "--note" => {
            let value = tail.get(index + 1).ok_or_else(|| "--note needs text".to_owned())?;
            if note.replace(value.clone()).is_some() {
               return Err("--note given more than once".to_owned());
            }
            index += 2;
         }
         "--subdomains" => {
            if subdomains {
               return Err("--subdomains given more than once".to_owned());
            }
            subdomains = true;
            index += 1;
         }
         other => {
            usage();
            return Err(format!("unknown argument: {other}"));
         }
      }
   }

   let exe = exe.ok_or_else(|| "--exe is required".to_owned())?;
   let dest_spec = dest_spec.ok_or_else(|| "--dest is required".to_owned())?;
   let dest = parse_dest(&dest_spec, subdomains)?;

   Ok(Command::Upsert {
      action,
      exe,
      dest,
      note,
   })
}

fn one_rule_id(tail: &[String], command: &str) -> Result<RuleId, String> {
   match tail {
      [raw] => parse_rule_id(raw),
      [] => {
         usage();
         Err(format!("{command} needs a rule id"))
      }
      _ => {
         usage();
         Err(format!("{command} takes exactly one rule id"))
      }
   }
}

/// Parses the sixteen lowercase hex digits [`RuleId`] displays.
///
/// `RuleId` deliberately has no `FromStr`; [`RuleId::from_bytes`] is its inverse and the
/// one way to rebuild the identifier a caller read from `ListRules`.
fn parse_rule_id(raw: &str) -> Result<RuleId, String> {
   if raw.len() != 16 {
      return Err(format!(
         "invalid rule id {raw:?}: expected 16 hex digits"
      ));
   }
   let mut bytes = [0u8; 8];
   for (slot, pair) in bytes.iter_mut().zip(raw.as_bytes().as_chunks::<2>().0) {
      let text = std::str::from_utf8(pair).map_err(|_| format!("invalid rule id {raw:?}"))?;
      *slot = u8::from_str_radix(text, 16)
         .map_err(|_| format!("invalid rule id {raw:?}: expected 16 hex digits"))?;
   }
   RuleId::from_bytes(&bytes).ok_or_else(|| format!("invalid rule id {raw:?}"))
}

/// Turns a `--dest` spec into the matcher the daemon stores.
fn parse_dest(spec: &str, subdomains: bool) -> Result<DestMatcher, String> {
   if spec == "any" {
      return Ok(DestMatcher::Any);
   }
   if let Some(raw) = spec.strip_prefix("ip:") {
      let net: IpNet = raw.parse().map_err(|err| {
         format!("invalid destination {spec:?}: {err}; accepted forms: {DEST_FORMS}")
      })?;
      return Ok(DestMatcher::Ip(net));
   }
   if let Some(raw) = spec.strip_prefix("domain:") {
      if raw.is_empty() || raw.contains("://") || raw.contains('/') {
         return Err(format!(
            "invalid destination {spec:?}: a host must not be empty, carry a scheme, or contain a \
             path; accepted forms: {DEST_FORMS}"
         ));
      }
      return Ok(DestMatcher::Domain {
         host: raw.to_ascii_lowercase(),
         subdomains,
      });
   }
   if let Some(raw) = spec.strip_prefix("port:") {
      let port: u16 = raw.parse().map_err(|_| {
         format!("invalid destination {spec:?}: a port is a number from 1 to 65535; accepted forms: {DEST_FORMS}")
      })?;
      if port == 0 {
         return Err(format!(
            "invalid destination {spec:?}: port 0 is not a destination; accepted forms: {DEST_FORMS}"
         ));
      }
      return Ok(DestMatcher::Port(port));
   }

   Err(format!(
      "invalid destination {spec:?}: accepted forms: {DEST_FORMS}"
   ))
}

/// Builds the permanent rule a `allow`/`deny` invocation asks the daemon to store.
fn build_rule(
   app: PathBuf,
   dest: DestMatcher,
   action: Action,
   note: Option<String>,
   now: u64,
) -> Rule {
   Rule {
      id: RuleId::new_unique(),
      enabled: true,
      app: AppMatcher::Exe(app),
      dest,
      action,
      duration: Duration::Forever,
      note,
      created_at: now,
      updated_at: now,
      last_matched: None,
      hits: 0,
   }
}

/// Sends one newline-framed request, refusing to buffer past the protocol's frame limit.
fn send(stream: &mut UnixStream, request: &Request) -> Result<(), String> {
   let bytes = encode_line(request).map_err(|err| format!("cannot encode request: {err}"))?;
   if bytes.len() > MAX_FRAME_LEN {
      return Err(format!(
         "request is {} bytes, over the {MAX_FRAME_LEN}-byte frame limit",
         bytes.len()
      ));
   }
   stream.write_all(&bytes).map_err(|err| format!("cannot send request: {err}"))?;
   stream.flush().map_err(|err| format!("cannot send request: {err}"))
}

/// Reads one reply frame.
///
/// A read timeout is `Ok(None)`: the daemon answers a successful mutation with nothing at
/// all, so the absence of a frame is how success is observed. An `Error` frame is surfaced
/// as `Err`; every other reply is returned to the caller to verify.
fn recv(stream: &mut UnixStream) -> Result<Option<Response>, String> {
   let mut frame = Vec::new();
   let mut buffer = [0u8; 4096];
   loop {
      match stream.read(&mut buffer) {
         Ok(0) if frame.is_empty() => {
            return Err("the daemon closed the connection without a reply".to_owned());
         }
         Ok(0) => return Err("the daemon closed the connection mid-frame".to_owned()),
         Ok(read) => {
            frame.extend_from_slice(&buffer[..read]);
            if let Some(end) = frame.iter().position(|byte| *byte == b'\n') {
               if end + 1 > MAX_FRAME_LEN {
                  return Err(format!(
                     "reply exceeds the {MAX_FRAME_LEN}-byte frame limit"
                  ));
               }
               frame.truncate(end + 1);
               return decode_reply(&frame);
            }
            if frame.len() >= MAX_FRAME_LEN {
               return Err(format!(
                  "reply exceeds the {MAX_FRAME_LEN}-byte frame limit"
               ));
            }
         }
         Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
         Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
               || err.kind() == std::io::ErrorKind::TimedOut =>
         {
            if frame.is_empty() {
               return Ok(None);
            }
            return Err("timed out in the middle of a reply".to_owned());
         }
         Err(err) => return Err(format!("cannot read reply: {err}")),
      }
   }
}

fn decode_reply(frame: &[u8]) -> Result<Option<Response>, String> {
   match decode_line::<Response>(frame) {
      Ok(Response::Error { message }) => Err(message),
      Ok(response) => Ok(Some(response)),
      Err(err) => Err(format!("malformed reply: {err}")),
   }
}

fn set_read_timeout(stream: &UnixStream, timeout: ReadTimeout) -> Result<(), String> {
   stream
      .set_read_timeout(Some(timeout))
      .map_err(|err| format!("cannot set the read timeout: {err}"))
}

/// Performs the hello exchange and checks that the daemon speaks this protocol.
fn handshake(stream: &mut UnixStream) -> Result<(), String> {
   send(
      stream,
      &Request::Hello {
         version: PROTOCOL_VERSION,
         client: ClientKind::Cli,
      },
   )?;

   match recv(stream)? {
      Some(Response::Hello { version, .. }) if version == PROTOCOL_VERSION => Ok(()),
      Some(Response::Hello { version, .. }) => Err(format!(
         "the daemon speaks protocol version {version}, this client speaks {PROTOCOL_VERSION}"
      )),
      Some(other) => Err(format!("unexpected reply to Hello: {other:?}")),
      None => Err("timed out waiting for the daemon's hello".to_owned()),
   }
}

/// Sends a mutation and accepts a silent timeout as success.
///
/// The daemon answers `UpsertRule`, `SetRuleEnabled` and `DeleteRule` only when it refuses, and never
/// answers `SetMode` at all, so an `Error` frame is an error and the timeout is the expected outcome.
fn mutate(stream: &mut UnixStream, request: &Request) -> Result<(), String> {
   set_read_timeout(stream, MUTATION_TIMEOUT)?;
   send(stream, request)?;
   match recv(stream)? {
      None => Ok(()),
      Some(reply) => Err(format!(
         "unexpected reply to {request:?}: {reply:?}"
      )),
   }
}

/// Sends a request the daemon does answer, and returns that answer.
fn query(stream: &mut UnixStream, request: &Request) -> Result<Response, String> {
   set_read_timeout(stream, REPLY_TIMEOUT)?;
   send(stream, request)?;
   recv(stream)?.ok_or_else(|| format!("timed out waiting for the daemon to answer {request:?}"))
}

fn list_rules(stream: &mut UnixStream) -> Result<Vec<Rule>, String> {
   match query(stream, &Request::ListRules)? {
      Response::Rules { rules } => Ok(rules),
      other => Err(format!(
         "unexpected reply to ListRules: {other:?}"
      )),
   }
}

/// The effective uid, read from the owner of `/proc/self/status`.
///
/// procfs stamps that file with the process's effective uid, so [`MetadataExt::uid`] is
/// the effective field without a raw `geteuid` call. An unreadable status file is treated
/// as "not root" by the caller.
fn effective_uid() -> Result<u32, String> {
   use std::os::unix::fs::MetadataExt;

   std::fs::metadata("/proc/self/status")
      .map(|metadata| metadata.uid())
      .map_err(|err| format!("cannot read /proc/self/status: {err}"))
}

fn now() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |elapsed| elapsed.as_secs())
}

fn enabled_label(enabled: bool) -> &'static str {
   if enabled { "enabled" } else { "disabled" }
}

fn action_label(action: Action) -> &'static str {
   match action {
      Action::Allow => "allow",
      Action::Deny => "deny",
   }
}

fn duration_label(duration: Duration) -> &'static str {
   match duration {
      Duration::Once => "once",
      Duration::Session => "session",
      Duration::Forever => "forever",
   }
}

fn app_label(app: &AppMatcher) -> String {
   match app {
      AppMatcher::Any => "any".to_owned(),
      AppMatcher::Exe(path) => path.display().to_string(),
      AppMatcher::Unknown => "unknown".to_owned(),
   }
}

fn dest_label(dest: &DestMatcher) -> String {
   match dest {
      DestMatcher::Any => "any".to_owned(),
      DestMatcher::Domain { host, subdomains } => {
         if *subdomains {
            format!("{host} (subdomains)")
         } else {
            host.clone()
         }
      }
      DestMatcher::Ip(net) => net.to_string(),
      DestMatcher::Port(port) => format!("port:{port}"),
      DestMatcher::Set(entries) => entries.iter().map(dest_label).collect::<Vec<_>>().join(", "),
   }
}

fn rule_line(rule: &Rule) -> String {
   format!(
      "{} {} {} -> {} ({})",
      action_label(rule.action),
      duration_label(rule.duration),
      app_label(&rule.app),
      dest_label(&rule.dest),
      rule.id
   )
}

fn usage() {
   eprint!("{USAGE}");
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn a_dest_spec_parses_any_ip_domain_and_port() {
      assert_eq!(parse_dest("any", false), Ok(DestMatcher::Any));
      assert!(matches!(
         parse_dest("ip:198.51.100.7/32", false),
         Ok(DestMatcher::Ip(_))
      ));
      match parse_dest("domain:Example.COM", false) {
         Ok(DestMatcher::Domain { host, subdomains }) => {
            assert_eq!(host, "example.com");
            assert!(!subdomains);
         }
         other => panic!("expected a domain matcher, got {other:?}"),
      }
      assert_eq!(
         parse_dest("port:443", false),
         Ok(DestMatcher::Port(443))
      );
   }

   #[test]
   fn an_invalid_dest_spec_is_refused() {
      for spec in [
         "ip:nonsense",
         "domain:",
         "domain:http://x",
         "port:0",
         "port:99999",
      ] {
         assert!(
            parse_dest(spec, false).is_err(),
            "{spec} must be refused"
         );
      }
   }

   #[test]
   fn a_rule_carries_the_requested_action_and_duration() {
      let rule = build_rule(
         PathBuf::from("/usr/bin/git"),
         DestMatcher::Any,
         Action::Deny,
         Some("note".into()),
         1_700_000_000,
      );
      assert_eq!(rule.duration, Duration::Forever);
      assert_eq!(rule.action, Action::Deny);
      assert!(rule.enabled);
      assert_eq!(
         rule.app,
         AppMatcher::Exe(PathBuf::from("/usr/bin/git"))
      );
      assert_eq!(rule.created_at, 1_700_000_000);
      assert_eq!(rule.updated_at, 1_700_000_000);
   }
}
