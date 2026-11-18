//! Control-plane REST client used by the desktop agent.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub country: String,
    #[serde(default)]
    pub city: String,
    pub hostname: String,
    pub endpoint: String,
    #[serde(default)]
    pub proxy_port: u16,
    #[serde(default)]
    pub load: f32,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPolicy {
    #[serde(default)]
    pub kill_switch_required: bool,
    #[serde(default = "t")]
    pub split_tunnel_allowed: bool,
}

fn t() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub session_id: String,
    pub address: String,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub mtu: Option<u16>,
    pub peer_public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive: u16,
    pub policy: ConnectPolicy,
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    MfaRequired,
    Http(u16, String),
    Net(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized => write!(f, "not logged in or session expired"),
            ApiError::MfaRequired => write!(f, "two-factor code required"),
            ApiError::Http(c, m) => write!(f, "server error {c}: {m}"),
            ApiError::Net(m) => write!(f, "network error: {m}"),
        }
    }
}

impl std::error::Error for ApiError {}

pub struct Api {
    base: String,
    http: reqwest::Client,
}

impl Api {
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let local = base.starts_with("http://127.0.0.1") || base.starts_with("http://localhost");
        anyhow::ensure!(base.starts_with("https://") || local, "control plane URL must be https://");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("beyond-agent/", env!("CARGO_PKG_VERSION")))
            .https_only(!local)
            .build()?;
        Ok(Api { base: base.trim_end_matches('/').into(), http })
    }

    async fn call<T: for<'de> Deserialize<'de>>(&self, method: reqwest::Method, path: &str, token: Option<&str>, body: Option<serde_json::Value>) -> Result<T, ApiError> {
        let mut rb = self.http.request(method, format!("{}/api/v1{}", self.base, path));
        if let Some(t) = token {
            rb = rb.bearer_auth(t);
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.map_err(|e| ApiError::Net(e.to_string()))?;
        let status = r.status().as_u16();
        let text = r.text().await.map_err(|e| ApiError::Net(e.to_string()))?;
        if status == 401 {
            return Err(if text.contains("mfa_required") { ApiError::MfaRequired } else { ApiError::Unauthorized });
        }
        if !(200..300).contains(&status) {
            return Err(ApiError::Http(status, text.chars().take(300).collect()));
        }
        serde_json::from_str(if text.is_empty() { "null" } else { &text }).map_err(|e| ApiError::Http(status, format!("bad json: {e}")))
    }

    pub async fn login(&self, email: &str, password: &str, totp: Option<&str>) -> Result<Tokens, ApiError> {
        self.call(reqwest::Method::POST, "/auth/login", None, Some(json!({"email": email, "password": password, "totp_code": totp}))).await
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens, ApiError> {
        self.call(reqwest::Method::POST, "/auth/refresh", None, Some(json!({"refresh_token": refresh_token}))).await
    }

    pub async fn logout(&self, refresh_token: &str) -> Result<serde_json::Value, ApiError> {
        self.call(reqwest::Method::POST, "/auth/logout", None, Some(json!({"refresh_token": refresh_token}))).await
    }

    pub async fn servers(&self, token: &str) -> Result<Vec<Server>, ApiError> {
        self.call(reqwest::Method::GET, "/servers", Some(token), None).await
    }

    pub async fn register_device(&self, token: &str, name: &str, platform: &str, public_key: &str, posture: serde_json::Value) -> Result<Device, ApiError> {
        self.call(reqwest::Method::POST, "/devices", Some(token), Some(json!({"name": name, "platform": platform, "public_key": public_key, "posture": posture}))).await
    }

    pub async fn connect(&self, token: &str, device_id: &str, server_id: &str) -> Result<ConnectResponse, ApiError> {
        self.call(reqwest::Method::POST, "/sessions/connect", Some(token), Some(json!({"device_id": device_id, "server_id": server_id}))).await
    }

    pub async fn disconnect(&self, token: &str, session_id: &str) -> Result<serde_json::Value, ApiError> {
        self.call(reqwest::Method::POST, &format!("/sessions/{session_id}/disconnect"), Some(token), None).await
    }

    pub async fn usage(&self, token: &str) -> Result<serde_json::Value, ApiError> {
        self.call(reqwest::Method::GET, "/me/usage", Some(token), None).await
    }
}

/// Fastest-server selection: weighted by measured RTT and reported load
/// (Proton "Quick Connect" / Forti "best available gateway").
pub fn score(rtt_ms: Option<u128>, load: f32) -> f64 {
    match rtt_ms {
        Some(r) => r as f64 * (1.0 + 2.0 * load.clamp(0.0, 1.0) as f64),
        None => f64::MAX,
    }
}

pub async fn probe(host: &str, port: u16) -> Option<u128> {
    let start = std::time::Instant::now();
    match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => Some(start.elapsed().as_millis()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_prefers_low_latency_and_load() {
        assert!(score(Some(20), 0.1) < score(Some(20), 0.9));
        assert!(score(Some(20), 0.5) < score(Some(80), 0.5));
        assert_eq!(score(None, 0.0), f64::MAX);
    }

    #[test]
    fn rejects_plain_http_remote() {
        assert!(Api::new("http://evil.example").is_err());
        assert!(Api::new("https://vpn.example").is_ok());
        assert!(Api::new("http://127.0.0.1:8000").is_ok());
    }
}
