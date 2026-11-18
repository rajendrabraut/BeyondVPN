//! Wire types exchanged between gateways and the control plane.
//! Field names match the FastAPI pydantic schemas in `control-plane/`.

use serde::{Deserialize, Serialize};

/// A WireGuard peer the gateway must install (from `GET /gateway/peers`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerSpec {
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    pub tunnel_ip: String,
    pub user_id: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeersResponse {
    pub peers: Vec<PeerSpec>,
    /// Control-plane Ed25519 public key (base64) used to verify proxy tokens.
    #[serde(default)]
    pub signing_public_key: Option<String>,
    /// Domains to sinkhole in addition to local lists (admin policy).
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// "off" | "metadata" | "full" — what the gateway is allowed to log.
    #[serde(default = "default_logging")]
    pub logging_mode: String,
    /// User ids whose proxy tokens must be rejected immediately
    /// (account disabled / sessions revoked) even before token expiry.
    #[serde(default)]
    pub revoked_subjects: Vec<String>,
}

fn default_logging() -> String {
    "full".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageSample {
    pub public_key: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(default)]
    pub last_handshake: u64,
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageReport {
    pub samples: Vec<UsageSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsLogEntry {
    pub client_ip: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    pub domain: String,
    pub qtype: String,
    pub blocked: bool,
    pub ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsLogBatch {
    pub entries: Vec<DnsLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyLogEntry {
    pub user_id: String,
    #[serde(default)]
    pub device_id: Option<String>,
    pub host: String,
    pub port: u16,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub ts: u64,
    pub duration_ms: u64,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyLogBatch {
    pub entries: Vec<ProxyLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Heartbeat {
    pub public_key: String,
    pub listen_port: u16,
    pub active_peers: u32,
    pub load: f32,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_response_defaults() {
        let r: PeersResponse = serde_json::from_str(r#"{"peers":[]}"#).unwrap();
        assert_eq!(r.logging_mode, "full");
        assert!(r.blocked_domains.is_empty());
    }
}
