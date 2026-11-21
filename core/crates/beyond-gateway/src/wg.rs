//! Thin wrapper over the `wg(8)` tool. Kernel WireGuard does the crypto;
//! we only reconcile peers and read counters.

use beyond_common::telemetry::PeerSpec;
use beyond_common::wgdump::{self, InterfaceDump};
use std::collections::HashSet;
use std::io::Write;
use std::process::{Command, Stdio};

pub struct Wg {
    pub iface: String,
    pub dry_run: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub add: Vec<PeerSpec>,
    pub remove: Vec<String>,
}

/// Decide which peers to add/update and which to remove.
pub fn plan(current: &HashSet<String>, desired: &[PeerSpec]) -> Plan {
    let want: HashSet<&str> = desired.iter().map(|p| p.public_key.as_str()).collect();
    Plan {
        // `wg set` is idempotent so re-applying existing peers keeps PSK/IP in sync.
        add: desired.to_vec(),
        remove: current.iter().filter(|k| !want.contains(k.as_str())).cloned().collect(),
    }
}

impl Wg {
    pub fn dump(&self) -> anyhow::Result<Option<InterfaceDump>> {
        if self.dry_run {
            return Ok(None);
        }
        let out = Command::new("wg").args(["show", &self.iface, "dump"]).output()?;
        if !out.status.success() {
            anyhow::bail!("wg show failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(wgdump::parse_dump(&String::from_utf8_lossy(&out.stdout)))
    }

    pub fn apply(&self, plan: &Plan) -> anyhow::Result<()> {
        if self.dry_run {
            return Ok(());
        }
        for p in &plan.add {
            beyond_common::keys::validate_key(&p.public_key).map_err(|e| anyhow::anyhow!("peer key: {e}"))?;
            let ip: std::net::Ipv4Addr = p.tunnel_ip.parse()?; // rejects anything but a bare IPv4
            let allowed = format!("{ip}/32");
            let mut cmd = Command::new("wg");
            cmd.args(["set", &self.iface, "peer", &p.public_key, "allowed-ips", &allowed]);
            if p.preshared_key.is_some() {
                // PSK via stdin so it never shows in `ps` output.
                cmd.args(["preshared-key", "/dev/stdin"]);
            }
            let mut child = cmd.stdin(Stdio::piped()).spawn()?;
            if let Some(psk) = &p.preshared_key {
                beyond_common::keys::validate_key(psk).map_err(|e| anyhow::anyhow!("psk: {e}"))?;
                child.stdin.take().unwrap().write_all(psk.as_bytes())?;
            } else {
                drop(child.stdin.take());
            }
            let st = child.wait()?;
            if !st.success() {
                anyhow::bail!("wg set peer failed for {}", p.public_key);
            }
        }
        for k in &plan.remove {
            let st = Command::new("wg").args(["set", &self.iface, "peer", k, "remove"]).status()?;
            if !st.success() {
                tracing::warn!(peer = %k, "failed to remove peer");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(k: &str) -> PeerSpec {
        PeerSpec { public_key: k.into(), preshared_key: None, tunnel_ip: "10.8.0.2".into(), user_id: "u".into(), device_id: "d".into(), exit_server_id: None }
    }

    #[test]
    fn plan_removes_stale_peers() {
        let current: HashSet<String> = ["A".to_string(), "B".to_string()].into();
        let p = plan(&current, &[peer("B"), peer("C")]);
        assert_eq!(p.remove, vec!["A".to_string()]);
        assert_eq!(p.add.len(), 2);
    }
}
