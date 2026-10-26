use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Address family of a connection, kept explicit because IPv4 and IPv6 are distinct
/// nftables paths even when the policy is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
   V4,
   V6,
}

/// Transport protocol as far as policy cares.
///
/// Unrecognised protocol numbers stay representable so a rule engine never has to drop a
/// flow it does not understand; they simply match no protocol-specific rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum L4Proto {
   Tcp,
   Udp,
   Icmp,
   Other(u8),
}

impl L4Proto {
   /// Stable wire/log label; `Other` deliberately collapses to `"other"` so log parsers
   /// do not depend on numeric protocol numbers.
   pub fn as_str(&self) -> &'static str {
      match self {
         Self::Tcp => "tcp",
         Self::Udp => "udp",
         Self::Icmp => "icmp",
         Self::Other(_) => "other",
      }
   }
}

impl fmt::Display for L4Proto {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(self.as_str())
   }
}

/// One side of a connection: the address the kernel reported plus the transport port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
   pub addr: IpAddr,
   pub port: u16,
}

/// What `/proc` told us about the socket owner.
///
/// Every field is optional-by-nature except the identifiers: a short-lived process can
/// vanish between the socket scan and the `/proc` read, and the model must be able to
/// carry that partial truth rather than invent an owner.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProcessInfo {
   pub pid: u32,
   pub uid: u32,
   pub exe: Option<PathBuf>,
   pub comm: Option<String>,
   pub cmdline: Option<String>,
}

/// Socket ownership as the daemon could establish it.
///
/// `Unknown` is a first-class outcome, not an absence to be papered over: the rule model
/// has a matcher for it so unattributable traffic is governed explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Attribution {
   Process(ProcessInfo),
   Unknown,
}

impl Attribution {
   /// Returns the owning UID when the socket could be attributed.
   pub fn uid(&self) -> Option<u32> {
      match self {
         Self::Process(process) => Some(process.uid),
         Self::Unknown => None,
      }
   }

   /// Returns the executable path when attribution found one.
   ///
   /// This is the exact path, not a basename: [`crate::AppMatcher::Exe`] compares paths
   /// verbatim, so a rule cannot accidentally match every binary called `firefox`.
   pub fn exe(&self) -> Option<&Path> {
      match self {
         Self::Process(process) => process.exe.as_deref(),
         Self::Unknown => None,
      }
   }
}

/// A single observed connection, the input to policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Connection {
   pub family: Family,
   pub proto: L4Proto,
   pub local: Endpoint,
   pub remote: Endpoint,
   pub process: Attribution,
   /// Hostname learned from DNS for `remote.addr`, when one was observed.
   pub domain: Option<String>,
}

/// The identity of a flow for grant caching and prompt de-duplication.
///
/// The local port is intentionally absent: a reconnecting client gets a new source port
/// but is still the same application talking to the same service, which is the unit the
/// user was asked about.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
   pub pid: Option<u32>,
   pub remote: Endpoint,
   pub proto: L4Proto,
}

impl Connection {
   /// The key under which a short-lived grant for this connection is stored.
   pub fn flow_key(&self) -> FlowKey {
      FlowKey {
         pid: self.pid(),
         remote: self.remote,
         proto: self.proto,
      }
   }

   /// Display name for prompts and logs: executable file name, then `comm`, then a
   /// literal `"unknown"`. Never empty, because an empty alert title is unreadable.
   pub fn app_name(&self) -> String {
      let process = match &self.process {
         Attribution::Process(process) => process,
         Attribution::Unknown => return "unknown".to_owned(),
      };
      if let Some(name) = process.exe.as_deref().and_then(Path::file_name) {
         return name.to_string_lossy().into_owned();
      }
      match &process.comm {
         Some(comm) if !comm.is_empty() => comm.clone(),
         _ => "unknown".to_owned(),
      }
   }

   /// The PID behind this connection, if it was attributed.
   fn pid(&self) -> Option<u32> {
      match &self.process {
         Attribution::Process(process) => Some(process.pid),
         Attribution::Unknown => None,
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::net::{Ipv4Addr, Ipv6Addr};

   fn process(pid: u32, exe: Option<&str>, comm: Option<&str>) -> Attribution {
      Attribution::Process(ProcessInfo {
         pid,
         uid: 1000,
         exe: exe.map(PathBuf::from),
         comm: comm.map(str::to_owned),
         cmdline: None,
      })
   }

   fn conn(pid: u32, port: u16) -> Connection {
      Connection {
         family: Family::V4,
         proto: L4Proto::Tcp,
         local: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 50000,
         },
         remote: Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(140, 82, 121, 78)),
            port,
         },
         process: process(
            pid,
            Some("/usr/lib/firefox/firefox"),
            Some("firefox"),
         ),
         domain: Some("api.github.com".to_owned()),
      }
   }

   #[test]
   fn flow_key_is_stable_for_equal_connections() {
      assert_eq!(conn(42, 443).flow_key(), conn(42, 443).flow_key());
   }

   #[test]
   fn flow_key_changes_with_pid_or_port() {
      assert_ne!(conn(42, 443).flow_key(), conn(43, 443).flow_key());
      assert_ne!(
         conn(42, 443).flow_key(),
         conn(42, 8443).flow_key()
      );
   }

   #[test]
   fn flow_key_of_unknown_attribution_has_no_pid() {
      let mut c = conn(42, 443);
      c.process = Attribution::Unknown;
      assert_eq!(c.flow_key().pid, None);
   }

   #[test]
   fn app_name_prefers_exe_basename_then_comm_then_unknown() {
      assert_eq!(conn(1, 443).app_name(), "firefox");

      let mut c = conn(1, 443);
      c.process = process(1, None, Some("curl"));
      assert_eq!(c.app_name(), "curl");

      c.process = process(1, None, None);
      assert_eq!(c.app_name(), "unknown");

      c.process = Attribution::Unknown;
      assert_eq!(c.app_name(), "unknown");
   }

   #[test]
   fn l4proto_labels() {
      assert_eq!(L4Proto::Tcp.as_str(), "tcp");
      assert_eq!(L4Proto::Udp.to_string(), "udp");
      assert_eq!(L4Proto::Icmp.to_string(), "icmp");
      assert_eq!(L4Proto::Other(132).to_string(), "other");
   }

   #[test]
   fn attribution_accessors() {
      let attributed = conn(7, 443);
      assert_eq!(attributed.process.uid(), Some(1000));
      assert_eq!(
         attributed.process.exe(),
         Some(Path::new("/usr/lib/firefox/firefox"))
      );

      let unknown = Attribution::Unknown;
      assert_eq!(unknown.uid(), None);
      assert_eq!(unknown.exe(), None);
   }

   #[test]
   fn ipv6_connection_keeps_its_family() {
      let mut c = conn(1, 443);
      c.family = Family::V6;
      c.remote.addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
      assert_eq!(
         c.flow_key().remote.addr,
         IpAddr::V6(Ipv6Addr::LOCALHOST)
      );
   }
}
