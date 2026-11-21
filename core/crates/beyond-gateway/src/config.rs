use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Server id as registered in the control plane.
    pub gateway_id: String,
    /// Secret issued once by the control plane when the server was created.
    /// Prefer the BEYOND_GATEWAY_KEY env var over writing it to disk.
    #[serde(default)]
    pub gateway_key: String,
    pub control_plane_url: String,
    #[serde(default = "d_iface")]
    pub interface: String,
    #[serde(default = "d_port")]
    pub listen_port: u16,
    /// File containing the WireGuard private key of this gateway.
    #[serde(default)]
    pub private_key_file: Option<PathBuf>,
    /// Do not call `wg`; useful for tests and non-Linux hosts.
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "d_sync")]
    pub sync_interval_secs: u64,
    #[serde(default = "d_capacity")]
    pub capacity: u32,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub multihop: MultihopConfig,
    #[serde(default)]
    pub stealth: StealthConfig,
}

/// Multi-hop uplinks to exit gateways (see hop.rs). Linux only.
#[derive(Debug, Clone, Deserialize)]
pub struct MultihopConfig {
    #[serde(default = "t")]
    pub enabled: bool,
    #[serde(default = "d_hop_key")]
    pub key_file: PathBuf,
}

impl Default for MultihopConfig {
    fn default() -> Self {
        MultihopConfig { enabled: true, key_file: d_hop_key() }
    }
}

/// Anti-blocking mode: WireGuard carried over TLS (see beyond-stealth).
#[derive(Debug, Clone, Deserialize)]
pub struct StealthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "d_stealth_listen")]
    pub listen: String,
    /// Port clients connect to (when a load balancer maps it differently). Defaults to the listen port.
    #[serde(default)]
    pub public_port: Option<u16>,
    /// PEM cert/key; default to the proxy's. Plain TCP only when both are absent (tests / TLS LB in front).
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
}

impl Default for StealthConfig {
    fn default() -> Self {
        StealthConfig { enabled: false, listen: d_stealth_listen(), public_port: None, tls_cert: None, tls_key: None }
    }
}

fn d_hop_key() -> PathBuf {
    "/etc/beyondvpn/hop.key".into()
}
fn d_stealth_listen() -> String {
    "0.0.0.0:443".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "t")]
    pub enabled: bool,
    #[serde(default = "d_dns_listen")]
    pub listen: String,
    /// `udp://1.1.1.1:53` or `https://cloudflare-dns.com/dns-query` (DoH, encrypted upstream).
    #[serde(default = "d_upstream")]
    pub upstream: String,
    #[serde(default)]
    pub blocklist_files: Vec<PathBuf>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig { enabled: true, listen: d_dns_listen(), upstream: d_upstream(), blocklist_files: vec![] }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "t")]
    pub enabled: bool,
    #[serde(default = "d_proxy_listen")]
    pub listen: String,
    /// PEM cert/key. When absent the proxy speaks plain HTTP: only acceptable
    /// behind a TLS terminator or on loopback for tests.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    #[serde(default = "d_ports")]
    pub allowed_ports: Vec<u16>,
    /// Allow proxying to private/loopback addresses (never in production).
    #[serde(default)]
    pub allow_private_destinations: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: true,
            listen: d_proxy_listen(),
            tls_cert: None,
            tls_key: None,
            allowed_ports: d_ports(),
            allow_private_destinations: false,
        }
    }
}

fn t() -> bool {
    true
}
fn d_iface() -> String {
    "wg0".into()
}
fn d_port() -> u16 {
    51820
}
fn d_sync() -> u64 {
    10
}
fn d_capacity() -> u32 {
    250
}
fn d_dns_listen() -> String {
    "10.8.0.1:53".into()
}
fn d_upstream() -> String {
    "https://cloudflare-dns.com/dns-query".into()
}
fn d_proxy_listen() -> String {
    "0.0.0.0:8443".into()
}
fn d_ports() -> Vec<u16> {
    vec![80, 443, 8080, 8443]
}

impl GatewayConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut cfg: GatewayConfig = toml::from_str(&text)?;
        if let Ok(k) = std::env::var("BEYOND_GATEWAY_KEY") {
            cfg.gateway_key = k;
        }
        if cfg.gateway_key.is_empty() {
            anyhow::bail!("gateway_key missing (set BEYOND_GATEWAY_KEY)");
        }
        if !cfg.control_plane_url.starts_with("https://") && !cfg.control_plane_url.starts_with("http://127.0.0.1") && !cfg.control_plane_url.starts_with("http://localhost") && !cfg.control_plane_url.starts_with("http://control-plane") {
            anyhow::bail!("control_plane_url must use https:// (plain http only allowed for localhost / compose network)");
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config_with_defaults() {
        let c: GatewayConfig = toml::from_str(
            r#"gateway_id = "gw1"
gateway_key = "k"
control_plane_url = "https://cp.example"
"#,
        )
        .unwrap();
        assert_eq!(c.interface, "wg0");
        assert!(c.dns.enabled);
        assert_eq!(c.proxy.allowed_ports, vec![80, 443, 8080, 8443]);
        assert!(!c.proxy.allow_private_destinations);
    }
}
