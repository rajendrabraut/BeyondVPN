//! Control-plane client used by the gateway.

use beyond_common::telemetry::*;
use serde::Serialize;
use std::time::Duration;

pub struct ControlPlane {
    base: String,
    id: String,
    key: String,
    http: reqwest::Client,
}

impl ControlPlane {
    pub fn new(base: &str, id: &str, key: &str) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("beyond-gateway/", env!("CARGO_PKG_VERSION")))
            .https_only(base.starts_with("https://"))
            .build()?;
        Ok(ControlPlane { base: base.trim_end_matches('/').to_string(), id: id.into(), key: key.into(), http })
    }

    fn url(&self, p: &str) -> String {
        format!("{}/api/v1/gateway/{}", self.base, p)
    }

    pub async fn peers(&self) -> anyhow::Result<PeersResponse> {
        let r = self
            .http
            .get(self.url("peers"))
            .header("X-Gateway-Id", &self.id)
            .header("X-Gateway-Key", &self.key)
            .send()
            .await?
            .error_for_status()?;
        Ok(r.json().await?)
    }

    pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> anyhow::Result<()> {
        self.http
            .post(self.url(path))
            .header("X-Gateway-Id", &self.id)
            .header("X-Gateway-Key", &self.key)
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
