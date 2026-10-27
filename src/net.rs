//! Address and name helpers shared by the policy, the egress filter and the
//! DNS proxy: CIDR blocks, domain patterns, address classes and the parsing
//! of `struct sockaddr` bytes read from the sandboxed process.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

/// An IPv4 or IPv6 network in CIDR notation. Host bits must be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (a, p) = s
            .split_once('/')
            .ok_or_else(|| format!("CIDR {s:?}: expected ADDRESS/PREFIX, e.g. 10.0.0.0/8 or 2001:db8::/32"))?;
        let addr: IpAddr = a
            .parse()
            .map_err(|_| format!("CIDR {s:?}: {a:?} is not an IP address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix: u8 = p
            .parse()
            .ok()
            .filter(|&n| n <= max)
            .ok_or_else(|| format!("CIDR {s:?}: prefix must be an integer between 0 and {max}"))?;
        if let IpAddr::V6(v6) = addr {
            if v6.to_ipv4_mapped().is_some() {
                return Err(format!(
                    "CIDR {s:?}: IPv4-mapped IPv6 networks are not accepted; write the IPv4 form"
                ));
            }
        }
        let cidr = Cidr { addr, prefix };
        let net = cidr.network();
        if net != addr {
            return Err(format!("CIDR {s:?}: host bits are set; the network is {net}/{prefix}"));
        }
        Ok(cidr)
    }

    fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask32(self.prefix))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask128(self.prefix))),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => u32::from(ip) & mask32(self.prefix) == u32::from(net),
            (IpAddr::V6(net), IpAddr::V6(ip)) => u128::from(ip) & mask128(self.prefix) == u128::from(net),
            _ => false,
        }
    }
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// `api.example.com` matches exactly that name; `*.example.com` matches any
/// name with one or more labels below `example.com` (but not `example.com`).
/// Matching is case-insensitive, as DNS names are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    Exact(Vec<String>),
    Below(Vec<String>),
}

impl DomainPattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (wild, rest) = match s.strip_prefix("*.") {
            Some(r) => (true, r),
            None => (false, s),
        };
        if rest.contains('*') {
            return Err(format!(
                "domain {s:?}: '*' is only allowed as the whole first label, e.g. *.example.com"
            ));
        }
        let labels = parse_name(rest).map_err(|e| format!("domain {s:?}: {e}"))?;
        if wild && labels.len() < 2 {
            return Err(format!("domain {s:?}: a wildcard needs at least two labels after '*.'"));
        }
        Ok(if wild {
            DomainPattern::Below(labels)
        } else {
            DomainPattern::Exact(labels)
        })
    }

    pub fn matches(&self, name: &[String]) -> bool {
        match self {
            DomainPattern::Exact(l) => name == l.as_slice(),
            DomainPattern::Below(l) => name.len() > l.len() && name.ends_with(l),
        }
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainPattern::Exact(l) => write!(f, "{}", l.join(".")),
            DomainPattern::Below(l) => write!(f, "*.{}", l.join(".")),
        }
    }
}

/// Split a textual host name into lowercase labels, validating the syntax.
/// A trailing dot is rejected so that patterns are written one way only.
pub fn parse_name(s: &str) -> Result<Vec<String>, String> {
    if s.is_empty() {
        return Err("empty name".into());
    }
    if s.ends_with('.') {
        return Err("trailing dot; write the name without it".into());
    }
    if s.len() > 253 {
        return Err("longer than 253 characters".into());
    }
    s.split('.')
        .map(|l| {
            if l.is_empty() || l.len() > 63 {
                return Err(format!("label {l:?} must be 1 to 63 characters"));
            }
            if !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err(format!("label {l:?} may only contain letters, digits, '-' and '_'"));
            }
            Ok(l.to_ascii_lowercase())
        })
        .collect()
}

/// Which DNS answers may add an address to the egress allow-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnswerScope {
    /// Publicly routable unicast addresses.
    Global,
    /// RFC 1918, carrier-grade NAT (100.64.0.0/10) and IPv6 unique-local (fc00::/7).
    Private,
    /// 127.0.0.0/8 and ::1.
    Loopback,
}

/// Address class used to decide whether a DNS answer may be learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrClass {
    Scope(AnswerScope),
    /// Never learned from DNS, whatever the policy says.
    Never(&'static str),
}

pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u8) -> bool {
    u32::from(ip) & mask32(prefix) == u32::from(Ipv4Addr::from(net))
}

fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    use AddrClass::*;
    if in_v4(ip, [0, 0, 0, 0], 8) {
        Never("unspecified (0.0.0.0/8)")
    } else if in_v4(ip, [127, 0, 0, 0], 8) {
        Scope(AnswerScope::Loopback)
    } else if in_v4(ip, [169, 254, 0, 0], 16) {
        Never("link-local (169.254.0.0/16, includes the cloud metadata server)")
    } else if in_v4(ip, [10, 0, 0, 0], 8)
        || in_v4(ip, [172, 16, 0, 0], 12)
        || in_v4(ip, [192, 168, 0, 0], 16)
        || in_v4(ip, [100, 64, 0, 0], 10)
    {
        Scope(AnswerScope::Private)
    } else if in_v4(ip, [224, 0, 0, 0], 4) {
        Never("multicast (224.0.0.0/4)")
    } else if in_v4(ip, [240, 0, 0, 0], 4) {
        Never("reserved or broadcast (240.0.0.0/4)")
    } else if in_v4(ip, [192, 0, 0, 0], 24)
        || in_v4(ip, [192, 0, 2, 0], 24)
        || in_v4(ip, [198, 51, 100, 0], 24)
        || in_v4(ip, [203, 0, 113, 0], 24)
        || in_v4(ip, [198, 18, 0, 0], 15)
    {
        Never("reserved for protocol assignments, documentation or benchmarking")
    } else {
        Scope(AnswerScope::Global)
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    use AddrClass::*;
    let bits = u128::from(ip);
    let in6 = |net: u128, prefix: u8| bits & mask128(prefix) == net;
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    if ip.is_unspecified() {
        Never("unspecified (::)")
    } else if ip.is_loopback() {
        Scope(AnswerScope::Loopback)
    } else if in6(0x0064_ff9b_u128 << 96, 96) {
        // NAT64: the class is that of the embedded IPv4 address.
        classify_v4(Ipv4Addr::from(bits as u32))
    } else if in6(0xfe80_u128 << 112, 10) {
        Never("link-local (fe80::/10)")
    } else if in6(0xfc00_u128 << 112, 7) {
        Scope(AnswerScope::Private)
    } else if in6(0xff00_u128 << 112, 8) {
        Never("multicast (ff00::/8)")
    } else if in6(0x2001_0db8_u128 << 96, 32) {
        Never("documentation (2001:db8::/32)")
    } else if in6(0x2000_u128 << 112, 3) {
        Scope(AnswerScope::Global)
    } else {
        Never("reserved IPv6 range")
    }
}

/// Destination of a connect(2) call, decoded from the caller's sockaddr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectTarget {
    /// AF_UNSPEC: dissolves the association (disconnect).
    Unspec,
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

impl ConnectTarget {
    /// The address that packets would actually be sent to: IPv4-mapped IPv6
    /// addresses are reported as IPv4.
    pub fn effective(&self) -> Option<(IpAddr, u16)> {
        match self {
            ConnectTarget::Unspec => None,
            ConnectTarget::V4(a) => Some((IpAddr::V4(*a.ip()), a.port())),
            ConnectTarget::V6(a) => match a.ip().to_ipv4_mapped() {
                Some(v4) => Some((IpAddr::V4(v4), a.port())),
                None => Some((IpAddr::V6(*a.ip()), a.port())),
            },
        }
    }
}

/// Decode a `struct sockaddr` the way the kernel's TCP connect path does,
/// returning the errno it would return for malformed input.
pub fn parse_sockaddr(b: &[u8]) -> Result<ConnectTarget, i32> {
    if b.len() < 2 {
        return Err(libc::EINVAL);
    }
    let family = u16::from_ne_bytes([b[0], b[1]]) as i32;
    match family {
        libc::AF_UNSPEC => Ok(ConnectTarget::Unspec),
        libc::AF_INET => {
            if b.len() < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(libc::EINVAL);
            }
            let port = u16::from_be_bytes([b[2], b[3]]);
            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Ok(ConnectTarget::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            // SIN6_LEN_RFC2133: the kernel accepts a sockaddr_in6 without sin6_scope_id.
            if b.len() < 24 {
                return Err(libc::EINVAL);
            }
            let port = u16::from_be_bytes([b[2], b[3]]);
            let flowinfo = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[8..24]);
            let scope = if b.len() >= 28 {
                u32::from_ne_bytes([b[24], b[25], b[26], b[27]])
            } else {
                0
            };
            Ok(ConnectTarget::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                flowinfo,
                scope,
            )))
        }
        _ => Err(libc::EAFNOSUPPORT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parse_and_contains() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        let host = Cidr::parse("127.0.0.1/32").unwrap();
        assert!(host.contains("127.0.0.1".parse().unwrap()));
        assert!(!host.contains("127.0.0.2".parse().unwrap()));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert_eq!(Cidr::parse("::/0").unwrap().to_string(), "::/0");
    }

    #[test]
    fn cidr_rejects_sloppy_input() {
        assert!(Cidr::parse("10.0.0.1/8").unwrap_err().contains("host bits"));
        assert!(Cidr::parse("10.0.0.0").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("example.com/8").is_err());
        assert!(Cidr::parse("::ffff:10.0.0.0/104").unwrap_err().contains("IPv4-mapped"));
    }

    fn name(s: &str) -> Vec<String> {
        parse_name(s).unwrap()
    }

    #[test]
    fn domain_patterns() {
        let exact = DomainPattern::parse("API.github.com").unwrap();
        assert!(exact.matches(&name("api.GitHub.com")));
        assert!(!exact.matches(&name("x.api.github.com")));
        let below = DomainPattern::parse("*.github.com").unwrap();
        assert!(below.matches(&name("api.github.com")));
        assert!(below.matches(&name("a.b.github.com")));
        assert!(!below.matches(&name("github.com")));
        assert!(!below.matches(&name("evilgithub.com")));
        assert_eq!(below.to_string(), "*.github.com");
    }

    #[test]
    fn domain_patterns_reject_bad_syntax() {
        assert!(DomainPattern::parse("*.com").is_err());
        assert!(DomainPattern::parse("a.*.com").is_err());
        assert!(DomainPattern::parse("example.com.").is_err());
        assert!(DomainPattern::parse("exa mple.com").is_err());
        assert!(DomainPattern::parse("").is_err());
        assert!(DomainPattern::parse("a..b").is_err());
    }

    #[test]
    fn address_classes() {
        let c = |s: &str| classify(s.parse().unwrap());
        assert_eq!(c("8.8.8.8"), AddrClass::Scope(AnswerScope::Global));
        assert_eq!(c("10.1.1.1"), AddrClass::Scope(AnswerScope::Private));
        assert_eq!(c("100.64.0.1"), AddrClass::Scope(AnswerScope::Private));
        assert_eq!(c("127.0.0.2"), AddrClass::Scope(AnswerScope::Loopback));
        assert!(matches!(c("169.254.169.254"), AddrClass::Never(_)));
        assert!(matches!(c("0.0.0.0"), AddrClass::Never(_)));
        assert!(matches!(c("224.0.0.1"), AddrClass::Never(_)));
        assert_eq!(c("2606:4700::1111"), AddrClass::Scope(AnswerScope::Global));
        assert_eq!(c("fd00::1"), AddrClass::Scope(AnswerScope::Private));
        assert_eq!(c("::1"), AddrClass::Scope(AnswerScope::Loopback));
        assert!(matches!(c("fe80::1"), AddrClass::Never(_)));
        assert!(matches!(c("::ffff:169.254.169.254"), AddrClass::Never(_)));
        assert!(matches!(c("64:ff9b::a9fe:a9fe"), AddrClass::Never(_)));
        assert!(matches!(c("2001:db8::1"), AddrClass::Never(_)));
    }

    fn sockaddr_in(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[4..8].copy_from_slice(&ip);
        b
    }

    #[test]
    fn sockaddr_decoding() {
        let t = parse_sockaddr(&sockaddr_in([1, 2, 3, 4], 443)).unwrap();
        assert_eq!(t.effective(), Some(("1.2.3.4".parse().unwrap(), 443)));
        assert_eq!(parse_sockaddr(&sockaddr_in([1, 2, 3, 4], 443)[..15]), Err(libc::EINVAL));
        assert_eq!(parse_sockaddr(&[0]), Err(libc::EINVAL));
        assert_eq!(
            parse_sockaddr(&(libc::AF_UNSPEC as u16).to_ne_bytes()),
            Ok(ConnectTarget::Unspec)
        );
        let mut unix = vec![0u8; 110];
        unix[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        assert_eq!(parse_sockaddr(&unix), Err(libc::EAFNOSUPPORT));

        let mut v6 = vec![0u8; 28];
        v6[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        v6[2..4].copy_from_slice(&80u16.to_be_bytes());
        let mapped: Ipv6Addr = "::ffff:10.0.0.7".parse().unwrap();
        v6[8..24].copy_from_slice(&mapped.octets());
        let t = parse_sockaddr(&v6).unwrap();
        assert_eq!(t.effective(), Some(("10.0.0.7".parse().unwrap(), 80)));
        assert!(parse_sockaddr(&v6[..24]).is_ok());
        assert_eq!(parse_sockaddr(&v6[..23]), Err(libc::EINVAL));
    }
}
