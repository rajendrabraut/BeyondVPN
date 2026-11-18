//! Parser for `wg show <iface> dump` and per-peer traffic delta tracking.

use crate::telemetry::UsageSample;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDump {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: u64,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDump {
    pub public_key: String,
    pub listen_port: u16,
    pub peers: Vec<PeerDump>,
}

/// Parse tab-separated dump output. The interface line has 4 columns,
/// peer lines have 8.
pub fn parse_dump(text: &str) -> Option<InterfaceDump> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let first: Vec<&str> = lines.next()?.split('\t').collect();
    if first.len() < 3 {
        return None;
    }
    let mut iface = InterfaceDump {
        public_key: first[1].to_string(),
        listen_port: first[2].parse().unwrap_or(0),
        peers: Vec::new(),
    };
    for l in lines {
        let c: Vec<&str> = l.split('\t').collect();
        if c.len() < 8 {
            continue;
        }
        iface.peers.push(PeerDump {
            public_key: c[0].to_string(),
            endpoint: if c[2] == "(none)" { None } else { Some(c[2].to_string()) },
            allowed_ips: c[3].split(',').filter(|s| *s != "(none)").map(|s| s.to_string()).collect(),
            latest_handshake: c[4].parse().unwrap_or(0),
            rx: c[5].parse().unwrap_or(0),
            tx: c[6].parse().unwrap_or(0),
        });
    }
    Some(iface)
}

/// Converts monotonically increasing WireGuard counters into deltas.
/// Counters reset when a peer is removed and re-added; that is detected
/// when the new value is lower than the last one.
#[derive(Debug, Default)]
pub struct DeltaTracker {
    last: HashMap<String, (u64, u64)>,
}

impl DeltaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, peers: &[PeerDump]) -> Vec<UsageSample> {
        let mut out = Vec::new();
        let mut seen = HashMap::new();
        for p in peers {
            let (lrx, ltx) = self.last.get(&p.public_key).copied().unwrap_or((0, 0));
            let drx = if p.rx >= lrx { p.rx - lrx } else { p.rx };
            let dtx = if p.tx >= ltx { p.tx - ltx } else { p.tx };
            seen.insert(p.public_key.clone(), (p.rx, p.tx));
            if drx > 0 || dtx > 0 {
                out.push(UsageSample {
                    public_key: p.public_key.clone(),
                    rx_bytes: drx,
                    tx_bytes: dtx,
                    last_handshake: p.latest_handshake,
                    endpoint: p.endpoint.clone(),
                });
            }
        }
        self.last = seen;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "PRIV\tPUBSRV\t51820\toff\nPEER1\tPSK\t1.2.3.4:5555\t10.8.0.2/32\t1700000000\t1000\t2000\t25\nPEER2\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff\n";

    #[test]
    fn parses_dump() {
        let d = parse_dump(DUMP).unwrap();
        assert_eq!(d.public_key, "PUBSRV");
        assert_eq!(d.listen_port, 51820);
        assert_eq!(d.peers.len(), 2);
        assert_eq!(d.peers[0].endpoint.as_deref(), Some("1.2.3.4:5555"));
        assert_eq!(d.peers[1].endpoint, None);
        assert_eq!(d.peers[0].rx, 1000);
    }

    #[test]
    fn deltas_and_resets() {
        let mut t = DeltaTracker::new();
        let mut d = parse_dump(DUMP).unwrap();
        let s = t.update(&d.peers);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].rx_bytes, 1000);
        d.peers[0].rx = 1500;
        d.peers[0].tx = 2000;
        let s = t.update(&d.peers);
        assert_eq!((s[0].rx_bytes, s[0].tx_bytes), (500, 0));
        d.peers[0].rx = 100; // counter reset
        let s = t.update(&d.peers);
        assert_eq!(s[0].rx_bytes, 100);
        assert!(t.update(&d.peers).is_empty());
    }
}
