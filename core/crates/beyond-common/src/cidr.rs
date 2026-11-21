//! IPv4 CIDR arithmetic used for split tunnelling.
//!
//! WireGuard routes by `AllowedIPs`. To *exclude* networks (LAN, a bank's
//! range, ...) we compute the complement of the excluded set inside
//! 0.0.0.0/0 — the same approach as the official AllowedIPs calculator.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr4 {
    pub addr: u32,
    pub prefix: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CidrError {
    #[error("invalid CIDR: {0}")]
    Invalid(String),
}

impl Cidr4 {
    pub fn new(addr: u32, prefix: u8) -> Self {
        let mask = Self::mask_of(prefix);
        Cidr4 { addr: addr & mask, prefix }
    }

    fn mask_of(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix as u32)
        }
    }

    pub fn mask(&self) -> u32 {
        Self::mask_of(self.prefix)
    }

    pub fn first(&self) -> u32 {
        self.addr
    }

    pub fn last(&self) -> u32 {
        self.addr | !self.mask()
    }

    pub fn contains(&self, other: &Cidr4) -> bool {
        other.prefix >= self.prefix && (other.addr & self.mask()) == self.addr
    }

    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask()) == self.addr
    }

    /// Split into two halves (prefix + 1).
    fn halves(&self) -> (Cidr4, Cidr4) {
        let p = self.prefix + 1;
        let bit = 1u32 << (32 - p as u32);
        (Cidr4::new(self.addr, p), Cidr4::new(self.addr | bit, p))
    }

    /// Number of host addresses (including network/broadcast).
    pub fn size(&self) -> u64 {
        1u64 << (32 - self.prefix as u32)
    }

    /// The n-th address in the block.
    pub fn nth(&self, n: u64) -> Option<Ipv4Addr> {
        if n >= self.size() {
            None
        } else {
            Some(Ipv4Addr::from(self.addr.wrapping_add(n as u32)))
        }
    }
}

impl FromStr for Cidr4 {
    type Err = CidrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, p.parse::<u8>().map_err(|_| CidrError::Invalid(s.into()))?),
            None => (s, 32),
        };
        if prefix > 32 {
            return Err(CidrError::Invalid(s.into()));
        }
        let ip: Ipv4Addr = ip.parse().map_err(|_| CidrError::Invalid(s.into()))?;
        Ok(Cidr4::new(u32::from(ip), prefix))
    }
}

impl fmt::Display for Cidr4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.addr), self.prefix)
    }
}

fn subtract_one(net: Cidr4, ex: &Cidr4, out: &mut Vec<Cidr4>) {
    if ex.contains(&net) {
        return; // fully excluded
    }
    if !net.contains(ex) {
        out.push(net); // disjoint
        return;
    }
    let (a, b) = net.halves();
    subtract_one(a, ex, out);
    subtract_one(b, ex, out);
}

/// Compute `include \ excludes` as a minimal, sorted list of CIDRs.
pub fn subtract(include: &[Cidr4], excludes: &[Cidr4]) -> Vec<Cidr4> {
    let mut current: Vec<Cidr4> = include.to_vec();
    for ex in excludes {
        let mut next = Vec::new();
        for net in current {
            subtract_one(net, ex, &mut next);
        }
        current = next;
    }
    current.sort();
    current.dedup();
    current
}

/// Standard private/link-local ranges users typically want to keep local
/// ("allow LAN" option in Proton/Forti clients).
pub fn lan_ranges() -> Vec<Cidr4> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"]
        .iter()
        .map(|s| s.parse().expect("static cidr"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr4 {
        s.parse().unwrap()
    }

    #[test]
    fn parse_and_display() {
        assert_eq!(c("10.1.2.3/8").to_string(), "10.0.0.0/8");
        assert_eq!(c("1.2.3.4").to_string(), "1.2.3.4/32");
        assert!("1.2.3.4/33".parse::<Cidr4>().is_err());
        assert!("300.1.1.1/8".parse::<Cidr4>().is_err());
    }

    #[test]
    fn subtract_single_host_from_default_route() {
        let r = subtract(&[c("0.0.0.0/0")], &[c("1.2.3.4/32")]);
        assert_eq!(r.len(), 32);
        assert!(r.iter().all(|n| !n.contains_ip("1.2.3.4".parse().unwrap())));
        // Every other address is still covered.
        let total: u64 = r.iter().map(|n| n.size()).sum();
        assert_eq!(total, (1u64 << 32) - 1);
    }

    #[test]
    fn subtract_lan() {
        let r = subtract(&[c("0.0.0.0/0")], &lan_ranges());
        for ip in ["10.1.1.1", "192.168.1.10", "172.20.0.1"] {
            assert!(r.iter().all(|n| !n.contains_ip(ip.parse().unwrap())), "{ip} leaked into tunnel");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1"] {
            assert!(r.iter().any(|n| n.contains_ip(ip.parse().unwrap())), "{ip} not tunnelled");
        }
    }

    #[test]
    fn subtract_everything_and_nothing() {
        assert!(subtract(&[c("10.0.0.0/8")], &[c("0.0.0.0/0")]).is_empty());
        assert_eq!(subtract(&[c("10.0.0.0/8")], &[c("11.0.0.0/8")]), vec![c("10.0.0.0/8")]);
    }

    #[test]
    fn nth_address() {
        let n = c("10.8.0.0/24");
        assert_eq!(n.nth(1).unwrap().to_string(), "10.8.0.1");
        assert_eq!(n.nth(256), None);
    }
}
