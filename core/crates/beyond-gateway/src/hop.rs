//! Multi-hop uplinks on an ENTRY gateway.
//!
//! For every exit server in use we keep a WireGuard interface `bhop<slot>` whose only
//! peer is the exit gateway (AllowedIPs 0.0.0.0/0, no routes installed by wg itself).
//! Policy routing then sends traffic *from* each multi-hop client's tunnel IP into
//! table `51000 + slot`, whose default route is that uplink:
//!
//! ```text
//! ip rule add from 10.8.0.5/32 lookup 51001 priority 5000
//! ip route replace default dev bhop1 table 51001
//! ```
//!
//! Replies come back on bhop1, are de-NATed (nft masquerade on `bhop*`, see
//! gateway-entrypoint.sh) and reach the client through the main table's wg0 route.
//! The exit gateway sees one ordinary WireGuard peer (this gateway) and NATs it as usual,
//! so neither side learns both the user's real IP and their destinations.

use beyond_common::telemetry::{HopSpec, PeerSpec};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const TABLE_BASE: u32 = 51_000;
pub const TABLE_MAX: u32 = TABLE_BASE + 10_000;
pub const RULE_PRIORITY: u32 = 5_000;
pub const MTU: u32 = 1420;

pub fn iface(slot: u16) -> String {
    format!("bhop{slot}")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule {
    pub from: Ipv4Addr,
    pub table: u32,
}

/// Rules wanted for the current peer set.
pub fn desired_rules(peers: &[PeerSpec], hops: &[HopSpec]) -> BTreeSet<Rule> {
    let slots: BTreeMap<&str, u16> = hops.iter().map(|h| (h.exit_server_id.as_str(), h.slot)).collect();
    peers
        .iter()
        .filter_map(|p| {
            let slot = slots.get(p.exit_server_id.as_deref()?)?;
            Some(Rule { from: p.tunnel_ip.parse().ok()?, table: TABLE_BASE + *slot as u32 })
        })
        .collect()
}

/// Parse `ip -4 rule show`, keeping only rules that point at our tables.
pub fn parse_rules(out: &str) -> BTreeSet<Rule> {
    out.lines()
        .filter_map(|l| {
            let toks: Vec<&str> = l.split_whitespace().collect();
            let from = toks.iter().position(|t| *t == "from").and_then(|i| toks.get(i + 1))?;
            let table = toks.iter().position(|t| *t == "lookup").and_then(|i| toks.get(i + 1))?.parse::<u32>().ok()?;
            if !(TABLE_BASE..TABLE_MAX).contains(&table) {
                return None;
            }
            Some(Rule { from: from.trim_end_matches("/32").parse().ok()?, table })
        })
        .collect()
}

/// Parse `ip -o link show` for existing `bhop<N>` interfaces.
pub fn parse_links(out: &str) -> BTreeSet<u16> {
    out.lines()
        .filter_map(|l| {
            let name = l.split(':').nth(1)?.trim();
            let name = name.split('@').next()?;
            name.strip_prefix("bhop")?.parse().ok()
        })
        .collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct HopPlan {
    pub configure: Vec<HopSpec>,
    pub remove_links: Vec<u16>,
    pub add_rules: Vec<Rule>,
    pub del_rules: Vec<Rule>,
}

pub fn plan(cur_rules: &BTreeSet<Rule>, cur_links: &BTreeSet<u16>, peers: &[PeerSpec], hops: &[HopSpec]) -> HopPlan {
    let want = desired_rules(peers, hops);
    let want_links: BTreeSet<u16> = hops.iter().map(|h| h.slot).collect();
    HopPlan {
        // `wg set` / `ip ... replace` are idempotent, so re-apply every uplink each sync.
        configure: hops.to_vec(),
        remove_links: cur_links.difference(&want_links).copied().collect(),
        add_rules: want.difference(cur_rules).cloned().collect(),
        del_rules: cur_rules.difference(&want).cloned().collect(),
    }
}

pub struct Hops {
    pub dry_run: bool,
    pub key_file: PathBuf,
}

fn run(args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(args[0]).args(&args[1..]).output()?;
    if !out.status.success() {
        anyhow::bail!("{} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Hops {
    /// Load (or create) the uplink private key and return its public key.
    pub fn public_key(&self) -> anyhow::Result<String> {
        if self.dry_run && !self.key_file.exists() {
            return Ok(beyond_common::keys::generate_keypair().public_key);
        }
        if !self.key_file.exists() {
            let kp = beyond_common::keys::generate_keypair();
            if let Some(dir) = self.key_file.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&self.key_file)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(kp.private_key.as_bytes())?;
        }
        Ok(beyond_common::keys::public_from_private(std::fs::read_to_string(&self.key_file)?.trim())?)
    }

    pub fn sync(&self, peers: &[PeerSpec], hops: &[HopSpec]) -> anyhow::Result<HopPlan> {
        let (rules, links) = if self.dry_run {
            (BTreeSet::new(), BTreeSet::new())
        } else {
            (parse_rules(&run(&["ip", "-4", "rule", "show"])?), parse_links(&run(&["ip", "-o", "link", "show"])?))
        };
        let p = plan(&rules, &links, peers, hops);
        if !self.dry_run {
            self.apply(&p, &links)?;
        }
        Ok(p)
    }

    fn apply(&self, p: &HopPlan, existing: &BTreeSet<u16>) -> anyhow::Result<()> {
        let key = self.key_file.to_string_lossy().into_owned();
        for h in &p.configure {
            beyond_common::keys::validate_key(&h.public_key).map_err(|e| anyhow::anyhow!("exit key: {e}"))?;
            let addr: Ipv4Addr = h.address.parse()?;
            let (host, port) = h.endpoint.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("bad endpoint"))?;
            anyhow::ensure!(port.parse::<u16>().is_ok() && host.chars().all(|c| c.is_ascii_alphanumeric() || ".-[]:".contains(c)), "bad endpoint");
            let dev = iface(h.slot);
            let table = (TABLE_BASE + h.slot as u32).to_string();
            if !existing.contains(&h.slot) {
                run(&["ip", "link", "add", &dev, "type", "wireguard"])?;
            }
            let mut cmd = Command::new("wg");
            cmd.args(["set", &dev, "private-key", &key, "peer", &h.public_key, "endpoint", &h.endpoint, "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25"]);
            if h.preshared_key.is_some() {
                cmd.args(["preshared-key", "/dev/stdin"]);
            }
            let mut child = cmd.stdin(Stdio::piped()).spawn()?;
            if let Some(psk) = &h.preshared_key {
                beyond_common::keys::validate_key(psk).map_err(|e| anyhow::anyhow!("psk: {e}"))?;
                child.stdin.take().unwrap().write_all(psk.as_bytes())?;
            }
            drop(child.stdin.take());
            anyhow::ensure!(child.wait()?.success(), "wg set {dev} failed");
            run(&["ip", "-4", "address", "replace", &format!("{addr}/32"), "dev", &dev])?;
            run(&["ip", "link", "set", &dev, "mtu", &MTU.to_string(), "up"])?;
            run(&["ip", "-4", "route", "replace", "default", "dev", &dev, "table", &table])?;
            // Loose reverse-path filter: replies from the internet arrive on the uplink.
            let _ = run(&["sysctl", "-qw", &format!("net.ipv4.conf.{dev}.rp_filter=2")]);
        }
        for r in &p.del_rules {
            let _ = run(&["ip", "-4", "rule", "del", "from", &format!("{}/32", r.from), "lookup", &r.table.to_string(), "priority", &RULE_PRIORITY.to_string()]);
        }
        for r in &p.add_rules {
            run(&["ip", "-4", "rule", "add", "from", &format!("{}/32", r.from), "lookup", &r.table.to_string(), "priority", &RULE_PRIORITY.to_string()])?;
        }
        for slot in &p.remove_links {
            let _ = run(&["ip", "-4", "route", "flush", "table", &(TABLE_BASE + *slot as u32).to_string()]);
            let _ = run(&["ip", "link", "del", &iface(*slot)]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(ip: &str, exit: Option<&str>) -> PeerSpec {
        PeerSpec { public_key: format!("k{ip}"), preshared_key: None, tunnel_ip: ip.into(), user_id: "u".into(), device_id: "d".into(), exit_server_id: exit.map(Into::into) }
    }

    fn hop(exit: &str, slot: u16) -> HopSpec {
        HopSpec { exit_server_id: exit.into(), slot, endpoint: "ch.example:51820".into(), public_key: "x".into(), preshared_key: None, address: "10.9.0.2".into() }
    }

    #[test]
    fn rules_follow_peer_exits() {
        let peers = [peer("10.8.0.2", Some("ch")), peer("10.8.0.3", None), peer("10.8.0.4", Some("unknown")), peer("10.8.0.5", Some("se"))];
        let r = desired_rules(&peers, &[hop("ch", 1), hop("se", 2)]);
        assert_eq!(
            r.into_iter().collect::<Vec<_>>(),
            vec![Rule { from: "10.8.0.2".parse().unwrap(), table: 51_001 }, Rule { from: "10.8.0.5".parse().unwrap(), table: 51_002 }]
        );
    }

    #[test]
    fn parses_ip_output() {
        let rules = parse_rules("0:\tfrom all lookup local\n5000:\tfrom 10.8.0.2 lookup 51001\n5000:\tfrom 10.8.0.9/32 lookup 51003\n32766:\tfrom all lookup main\n");
        assert_eq!(rules.len(), 2);
        assert!(rules.contains(&Rule { from: "10.8.0.9".parse().unwrap(), table: 51_003 }));
        let links = parse_links("1: lo: <LOOPBACK,UP> mtu 65536\n4: wg0: <POINTOPOINT,NOARP,UP> mtu 1420\n7: bhop1: <POINTOPOINT,NOARP,UP> mtu 1420\n9: bhop12: <POINTOPOINT> mtu 1420\n");
        assert_eq!(links.into_iter().collect::<Vec<_>>(), vec![1, 12]);
    }

    #[test]
    fn plan_diffs_rules_and_links() {
        let cur_rules: BTreeSet<Rule> = [Rule { from: "10.8.0.7".parse().unwrap(), table: 51_001 }].into();
        let cur_links: BTreeSet<u16> = [1, 3].into();
        let p = plan(&cur_rules, &cur_links, &[peer("10.8.0.2", Some("ch"))], &[hop("ch", 1)]);
        assert_eq!(p.add_rules, vec![Rule { from: "10.8.0.2".parse().unwrap(), table: 51_001 }]);
        assert_eq!(p.del_rules, vec![Rule { from: "10.8.0.7".parse().unwrap(), table: 51_001 }]);
        assert_eq!(p.remove_links, vec![3]);
        assert_eq!(p.configure.len(), 1);
    }
}
