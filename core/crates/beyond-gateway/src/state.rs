use beyond_common::blocklist::Blocklist;
use beyond_common::telemetry::{DnsLogEntry, PeerSpec, ProxyLogEntry};
use ed25519_dalek::VerifyingKey;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, RwLock};

/// Logs are buffered in memory and flushed to the control plane; the buffer
/// is bounded so a control-plane outage cannot exhaust gateway memory.
pub const MAX_BUFFER: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggingMode {
    Off,
    Metadata,
    Full,
}

impl LoggingMode {
    pub fn parse(s: &str) -> Self {
        match s {
            "off" => LoggingMode::Off,
            "metadata" => LoggingMode::Metadata,
            _ => LoggingMode::Full,
        }
    }
}

pub struct State {
    pub gateway_id: String,
    /// tunnel ip (no prefix) -> peer
    pub peers_by_ip: RwLock<HashMap<String, PeerSpec>>,
    pub signing_key: RwLock<Option<VerifyingKey>>,
    pub revoked: RwLock<HashSet<String>>,
    pub static_blocklist: Blocklist,
    pub policy_blocklist: RwLock<Blocklist>,
    pub logging: RwLock<LoggingMode>,
    pub dns_logs: Mutex<Vec<DnsLogEntry>>,
    pub proxy_logs: Mutex<Vec<ProxyLogEntry>>,
}

impl State {
    pub fn new(gateway_id: String, static_blocklist: Blocklist) -> Self {
        State {
            gateway_id,
            peers_by_ip: RwLock::new(HashMap::new()),
            signing_key: RwLock::new(None),
            revoked: RwLock::new(HashSet::new()),
            static_blocklist,
            policy_blocklist: RwLock::new(Blocklist::new()),
            logging: RwLock::new(LoggingMode::Full),
            dns_logs: Mutex::new(Vec::new()),
            proxy_logs: Mutex::new(Vec::new()),
        }
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        self.static_blocklist.is_blocked(domain) || self.policy_blocklist.read().unwrap().is_blocked(domain)
    }

    pub fn logging_mode(&self) -> LoggingMode {
        *self.logging.read().unwrap()
    }

    pub fn push_dns(&self, e: DnsLogEntry) {
        if self.logging_mode() != LoggingMode::Full {
            return;
        }
        let mut b = self.dns_logs.lock().unwrap();
        if b.len() < MAX_BUFFER {
            b.push(e);
        }
    }

    pub fn push_proxy(&self, mut e: ProxyLogEntry) {
        match self.logging_mode() {
            LoggingMode::Off => return,
            LoggingMode::Metadata => e.host = "-".into(), // bytes only, no destination
            LoggingMode::Full => {}
        }
        let mut b = self.proxy_logs.lock().unwrap();
        if b.len() < MAX_BUFFER {
            b.push(e);
        }
    }

    pub fn take_dns(&self) -> Vec<DnsLogEntry> {
        std::mem::take(&mut *self.dns_logs.lock().unwrap())
    }

    pub fn take_proxy(&self) -> Vec<ProxyLogEntry> {
        std::mem::take(&mut *self.proxy_logs.lock().unwrap())
    }

    /// Put logs back after a failed upload (bounded).
    pub fn requeue_dns(&self, mut v: Vec<DnsLogEntry>) {
        let mut b = self.dns_logs.lock().unwrap();
        v.truncate(MAX_BUFFER.saturating_sub(b.len()));
        b.extend(v);
    }

    pub fn requeue_proxy(&self, mut v: Vec<ProxyLogEntry>) {
        let mut b = self.proxy_logs.lock().unwrap();
        v.truncate(MAX_BUFFER.saturating_sub(b.len()));
        b.extend(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(host: &str) -> ProxyLogEntry {
        ProxyLogEntry {
            user_id: "u".into(),
            device_id: None,
            host: host.into(),
            port: 443,
            bytes_up: 1,
            bytes_down: 2,
            ts: 0,
            duration_ms: 0,
            blocked: false,
        }
    }

    #[test]
    fn logging_modes_are_enforced() {
        let s = State::new("gw".into(), Blocklist::new());
        s.push_proxy(entry("a.com"));
        *s.logging.write().unwrap() = LoggingMode::Metadata;
        s.push_proxy(entry("b.com"));
        *s.logging.write().unwrap() = LoggingMode::Off;
        s.push_proxy(entry("c.com"));
        let v = s.take_proxy();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].host, "a.com");
        assert_eq!(v[1].host, "-");
        assert!(s.take_proxy().is_empty());
    }
}
