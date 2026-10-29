use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, de};

/// An IPv4 or IPv6 network in CIDR form.
///
/// `addr` always holds the masked network address, so two values that denote the same
/// network compare equal even when the caller supplied host bits. Matching is pure: a
/// firewall decision must not depend on resolver state or any other I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct IpNet {
   pub addr: IpAddr,
   pub prefix: u8,
}

/// Why a CIDR string could not be turned into an [`IpNet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpNetError {
   /// The prefix length is not a number, is empty, or exceeds the family width.
   BadPrefix,
   /// The address part is not a valid IPv4 or IPv6 literal.
   BadAddress,
   /// A trailing slash was present with no prefix length after it.
   MissingPrefix,
}

impl fmt::Display for IpNetError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::BadPrefix => f.write_str("invalid CIDR prefix length"),
         Self::BadAddress => f.write_str("invalid IP address"),
         Self::MissingPrefix => f.write_str("missing CIDR prefix length after '/'"),
      }
   }
}

impl std::error::Error for IpNetError {}

impl IpNet {
   /// Builds a network, rejecting a prefix wider than the address family allows.
   ///
   /// The stored address is masked so [`IpNet::contains`] never has to trust the caller
   /// to have cleared host bits.
   pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, IpNetError> {
      let width = match addr {
         IpAddr::V4(_) => 32,
         IpAddr::V6(_) => 128,
      };
      if prefix > width {
         return Err(IpNetError::BadPrefix);
      }
      Ok(Self {
         addr: mask(addr, prefix),
         prefix,
      })
   }

   /// Returns whether `ip` falls inside this network.
   ///
   /// Addresses from the other family are never contained; there is no implicit
   /// IPv4-in-IPv6 mapping that could widen a rule by accident.
   pub fn contains(&self, ip: IpAddr) -> bool {
      match (self.addr, ip) {
         (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let net = u32::from(net) & v4_mask(self.prefix);
            let ip = u32::from(ip) & v4_mask(self.prefix);
            net == ip
         }
         (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let net = u128::from(net) & v6_mask(self.prefix);
            let ip = u128::from(ip) & v6_mask(self.prefix);
            net == ip
         }
         _ => false,
      }
   }
}

impl FromStr for IpNet {
   type Err = IpNetError;

   /// Parses `addr/prefix`, or a bare address whose prefix is the full width.
   ///
   /// A missing prefix on a bare address is common in configuration written by hand, so
   /// `1.2.3.4` means `/32` and `::1` means `/128` rather than an error.
   fn from_str(s: &str) -> Result<Self, Self::Err> {
      let (addr_part, prefix_part) = match s.split_once('/') {
         Some((addr, prefix)) => {
            if prefix.contains('/') {
               return Err(IpNetError::BadAddress);
            }
            (addr, Some(prefix))
         }
         None => (s, None),
      };

      let addr: IpAddr = addr_part.parse().map_err(|_| IpNetError::BadAddress)?;
      let prefix = match prefix_part {
         Some("") => return Err(IpNetError::MissingPrefix),
         Some(prefix) => prefix.parse::<u8>().map_err(|_| IpNetError::BadPrefix)?,
         None if addr.is_ipv4() => 32,
         None => 128,
      };
      Self::new(addr, prefix)
   }
}

impl fmt::Display for IpNet {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "{}/{}", self.addr, self.prefix)
   }
}

impl<'de> Deserialize<'de> for IpNet {
   /// Deserializes through [`IpNet::new`] so a hand-edited rule file cannot smuggle in a
   /// prefix wider than the address family or an unmasked network.
   fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
      #[derive(Deserialize)]
      struct Raw {
         addr: IpAddr,
         prefix: u8,
      }

      let raw = Raw::deserialize(deserializer)?;
      Self::new(raw.addr, raw.prefix).map_err(de::Error::custom)
   }
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
   match addr {
      IpAddr::V4(addr) => IpAddr::V4(Ipv4Addr::from(u32::from(addr) & v4_mask(prefix))),
      IpAddr::V6(addr) => IpAddr::V6(Ipv6Addr::from(u128::from(addr) & v6_mask(prefix))),
   }
}

/// Masks defensively rather than assuming `prefix <= 32`: fields are public, so a value
/// built outside [`IpNet::new`] must not be able to shift-overflow in a debug build.
fn v4_mask(prefix: u8) -> u32 {
   if prefix >= 32 {
      u32::MAX
   } else if prefix == 0 {
      0
   } else {
      u32::MAX << (32 - prefix)
   }
}

/// Same defensive range handling as [`v4_mask`], for IPv6.
fn v6_mask(prefix: u8) -> u128 {
   if prefix >= 128 {
      u128::MAX
   } else if prefix == 0 {
      0
   } else {
      u128::MAX << (128 - prefix)
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   fn net(s: &str) -> IpNet {
      s.parse().expect("test CIDR must parse")
   }

   fn ip(s: &str) -> IpAddr {
      s.parse().expect("test address must parse")
   }

   #[test]
   fn a_cidr_parses_and_masks_its_host_bits() {
      let cases = [
         ("10.1.2.3/8", "10.0.0.0", 8, "10.0.0.0/8"),
         (
            "2001:db8:1::abcd/32",
            "2001:db8::",
            32,
            "2001:db8::/32",
         ),
         ("1.2.3.4", "1.2.3.4", 32, "1.2.3.4/32"),
         ("::1", "::1", 128, "::1/128"),
      ];
      for (input, addr, prefix, display) in cases {
         let net = net(input);
         assert_eq!(net.addr, ip(addr), "{input}");
         assert_eq!(net.prefix, prefix, "{input}");
         assert_eq!(net.to_string(), display, "{input}");
      }
   }

   #[test]
   fn a_bad_cidr_is_rejected() {
      let cases = [
         (
            "prefix wider than v4",
            "10.0.0.0/33".parse::<IpNet>(),
            IpNetError::BadPrefix,
         ),
         (
            "prefix wider than v6",
            "2001:db8::/129".parse::<IpNet>(),
            IpNetError::BadPrefix,
         ),
         (
            "v4 prefix passed to new",
            IpNet::new(ip("10.0.0.1"), 33),
            IpNetError::BadPrefix,
         ),
         (
            "v6 prefix passed to new",
            IpNet::new(ip("2001:db8::1"), 129),
            IpNetError::BadPrefix,
         ),
         (
            "not an address",
            "not-an-ip/8".parse::<IpNet>(),
            IpNetError::BadAddress,
         ),
         (
            "missing prefix",
            "10.0.0.0/".parse::<IpNet>(),
            IpNetError::MissingPrefix,
         ),
         (
            "two prefixes",
            "10.0.0.0/8/9".parse::<IpNet>(),
            IpNetError::BadAddress,
         ),
         (
            "non-numeric prefix",
            "10.0.0.0/x".parse::<IpNet>(),
            IpNetError::BadPrefix,
         ),
      ];
      for (case, parsed, expected) in cases {
         assert_eq!(parsed, Err(expected), "{case}");
      }
   }

   #[test]
   fn contains_covers_the_network_and_stops_one_past() {
      let v4 = net("192.168.1.0/24");
      let v6 = net("2001:db8::/32");
      let cases = [
         ("v4 network address", &v4, ip("192.168.1.0"), true),
         (
            "v4 broadcast address",
            &v4,
            ip("192.168.1.255"),
            true,
         ),
         ("v4 host address", &v4, ip("192.168.1.77"), true),
         (
            "v4 one past broadcast",
            &v4,
            ip("192.168.2.0"),
            false,
         ),
         (
            "v4 one before network",
            &v4,
            ip("192.168.0.255"),
            false,
         ),
         ("v6 first address", &v6, ip("2001:db8::"), true),
         (
            "v6 last address",
            &v6,
            ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
            true,
         ),
         (
            "v6 one past the prefix",
            &v6,
            ip("2001:db9::"),
            false,
         ),
         (
            "v6 address in a v4 net",
            &net("0.0.0.0/0"),
            ip("::1"),
            false,
         ),
         (
            "v4 address in a v6 net",
            &net("::/0"),
            ip("127.0.0.1"),
            false,
         ),
      ];
      for (case, net, addr, expected) in cases {
         assert_eq!(net.contains(addr), expected, "{case}");
      }
   }

   #[test]
   fn serde_round_trip_rejects_unmasked_and_wide_prefix() {
      let original = net("10.9.9.9/8");
      let json = serde_json::to_string(&original).expect("serialize");
      let parsed: IpNet = serde_json::from_str(&json).expect("deserialize");
      assert_eq!(parsed, original);

      let bad = r#"{"addr":"10.0.0.0","prefix":33}"#;
      assert!(serde_json::from_str::<IpNet>(bad).is_err());
      let unmasked = r#"{"addr":"10.9.9.9","prefix":8}"#;
      assert_eq!(
         serde_json::from_str::<IpNet>(unmasked).expect("deserialize"),
         original
      );
   }
}
