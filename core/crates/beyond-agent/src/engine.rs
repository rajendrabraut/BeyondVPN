//! Connection engine shared by the CLI and the local daemon API.

use crate::api::{self, Api, ApiError, Server};
use crate::store::{AgentState, Settings, Store};
use crate::tunnel::{self, Backend};
use beyond_common::wgconf::{ClientOptions, TunnelConfig};
use serde::Serialize;
use tokio::sync::Mutex;

pub struct Engine {
    pub store: Store,
    pub backend: Box<dyn Backend>,
    lock: Mutex<()>,
    relay: std::sync::Mutex<Option<beyond_stealth::ClientRelay>>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub logged_in: bool,
    pub email: Option<String>,
    pub connected: bool,
    pub server: Option<String>,
    pub connected_at: Option<u64>,
    pub backend: &'static str,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub latest_handshake: u64,
    pub settings: Settings,
}

impl Engine {
    pub fn new(store: Store, backend: Box<dyn Backend>) -> Self {
        Engine { store, backend, lock: Mutex::new(()), relay: std::sync::Mutex::new(None) }
    }

    fn api(&self, st: &AgentState) -> anyhow::Result<Api> {
        let url = st.api_url.clone().ok_or_else(|| anyhow::anyhow!("not logged in: run `beyond-agent login`"))?;
        Api::new(&url)
    }

    pub async fn login(&self, url: &str, email: &str, password: &str, totp: Option<&str>) -> anyhow::Result<()> {
        let _g = self.lock.lock().await;
        let api = Api::new(url)?;
        let t = api.login(email, password, totp).await?;
        let mut st = self.store.load();
        st.api_url = Some(url.trim_end_matches('/').into());
        st.email = Some(email.into());
        st.access_token = Some(t.access_token);
        st.refresh_token = Some(t.refresh_token);
        // Register device (idempotent on public key server-side).
        let (_, public) = self.store.ensure_keypair()?;
        let host = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "desktop".into());
        let posture = serde_json::json!({
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "agent_version": env!("CARGO_PKG_VERSION"),
        });
        let dev = api.register_device(st.access_token.as_deref().unwrap(), &host, tunnel::platform_name(), &public, posture).await?;
        st.device_id = Some(dev.id);
        st.device_public_key = Some(public);
        self.store.save(&st)?;
        Ok(())
    }

    /// Run an authenticated call, transparently refreshing the access token once.
    async fn authed<T, F, Fut>(&self, f: F) -> anyhow::Result<T>
    where
        F: Fn(Api, String) -> Fut,
        Fut: std::future::Future<Output = Result<T, ApiError>>,
    {
        let mut st = self.store.load();
        let token = st.access_token.clone().ok_or_else(|| anyhow::anyhow!("not logged in"))?;
        match f(self.api(&st)?, token).await {
            Err(ApiError::Unauthorized) => {
                let rt = st.refresh_token.clone().ok_or_else(|| anyhow::anyhow!("session expired, log in again"))?;
                let t = self.api(&st)?.refresh(&rt).await.map_err(|_| anyhow::anyhow!("session expired, log in again"))?;
                st.access_token = Some(t.access_token.clone());
                st.refresh_token = Some(t.refresh_token);
                self.store.save(&st)?;
                Ok(f(self.api(&st)?, t.access_token).await?)
            }
            other => Ok(other?),
        }
    }

    pub async fn servers(&self) -> anyhow::Result<Vec<Server>> {
        self.authed(|api, t| async move { api.servers(&t).await }).await
    }

    pub async fn usage(&self) -> anyhow::Result<serde_json::Value> {
        self.authed(|api, t| async move { api.usage(&t).await }).await
    }

    pub async fn fastest(&self, servers: &[Server]) -> Option<Server> {
        // Probe all servers concurrently (each probe is capped at 2 s).
        let mut set = tokio::task::JoinSet::new();
        for s in servers.iter().filter(|s| s.status != "offline").cloned() {
            set.spawn(async move {
                let host = s.endpoint.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| s.hostname.clone());
                let port = if s.proxy_port > 0 { s.proxy_port } else { 443 };
                let rtt = api::probe(&host, port).await;
                (api::score(rtt, s.load), s)
            });
        }
        let mut best: Option<(f64, Server)> = None;
        while let Some(Ok((sc, s))) = set.join_next().await {
            if best.as_ref().map(|(b, _)| sc < *b).unwrap_or(true) {
                best = Some((sc, s));
            }
        }
        best.map(|(_, s)| s).or_else(|| servers.first().cloned())
    }

    pub async fn connect(&self, server_id: Option<String>) -> anyhow::Result<String> {
        let _g = self.lock.lock().await;
        let mut st = self.store.load();
        let device = st.device_id.clone().ok_or_else(|| anyhow::anyhow!("device not registered: log in first"))?;
        let servers = self.servers().await?;
        let target = match server_id.or(st.settings.preferred_server.clone()) {
            Some(id) => servers.iter().find(|s| s.id == id || s.name.eq_ignore_ascii_case(&id)).cloned().ok_or_else(|| anyhow::anyhow!("unknown server {id}"))?,
            None => self.fastest(&servers).await.ok_or_else(|| anyhow::anyhow!("no servers available"))?,
        };
        let exit = match st.settings.exit_server.as_deref().filter(|e| !e.is_empty()) {
            Some(e) => Some(servers.iter().find(|s| s.id == e || s.name.eq_ignore_ascii_case(e)).map(|s| s.id.clone()).ok_or_else(|| anyhow::anyhow!("unknown exit server {e}"))?),
            None => None,
        }
        .filter(|e| *e != target.id);
        let sid = target.id.clone();
        let dev = device.clone();
        let ex = exit.clone();
        let resp = self.authed(move |api, t| {
            let (dev, sid, ex) = (dev.clone(), sid.clone(), ex.clone());
            async move { api.connect(&t, &dev, &sid, ex.as_deref()).await }
        })
        .await?;
        self.stop_relay();
        let mut endpoint = resp.endpoint.clone();
        let mut relay_excludes = Vec::new();
        if st.settings.stealth {
            let port = resp.stealth_port.ok_or_else(|| anyhow::anyhow!("{} does not offer stealth mode; pick another server or turn stealth off", target.name))?;
            // Dial the gateway over IPv4 and keep that address outside the tunnel,
            // otherwise the relay's own TLS connection would loop into WireGuard.
            let addr = tokio::net::lookup_host((target.hostname.as_str(), port))
                .await?
                .find(|a| a.is_ipv4())
                .ok_or_else(|| anyhow::anyhow!("{} has no IPv4 address for stealth mode", target.hostname))?;
            relay_excludes.push(format!("{}/32", addr.ip()));
            let relay = beyond_stealth::ClientRelay::start(beyond_stealth::ClientConfig {
                host: target.hostname.clone(),
                port,
                addr: Some(addr),
                insecure_plaintext: std::env::var("BEYOND_STEALTH_PLAINTEXT").as_deref() == Ok("1"),
            })
            .await?;
            endpoint = relay.local_addr.to_string();
            *self.relay.lock().unwrap() = Some(relay);
        }
        let private_key = self.store.private_key().ok_or_else(|| anyhow::anyhow!("device key missing"))?;
        let cfg = TunnelConfig {
            private_key,
            address: resp.address.clone(),
            dns: resp.dns.clone(),
            mtu: resp.mtu,
            peer_public_key: resp.peer_public_key.clone(),
            preshared_key: resp.preshared_key.clone(),
            endpoint,
            allowed_ips: resp.allowed_ips.clone(),
            persistent_keepalive: resp.persistent_keepalive,
        };
        let s = &st.settings;
        let split_ok = resp.policy.split_tunnel_allowed;
        let mut exclude_routes = if split_ok { s.exclude_routes.clone() } else { vec![] };
        exclude_routes.extend(relay_excludes);
        let opts = ClientOptions {
            kill_switch: s.kill_switch || resp.policy.kill_switch_required,
            allow_lan: s.allow_lan && split_ok,
            exclude_routes,
            platform: tunnel::platform_name().into(),
        };
        let text = cfg.render(&opts)?;
        let path = self.store.tunnel_conf_path();
        crate::store::write_private(&path, text.as_bytes())?;
        let up = self.backend.up(&path);
        if up.is_err() {
            self.stop_relay();
        }
        // The private key must not linger in a readable file longer than needed
        // on platforms where the service has already imported it.
        if cfg!(windows) && up.is_ok() {
            let _ = std::fs::remove_file(&path);
        }
        up?;
        st.session_id = Some(resp.session_id);
        let label = match resp.exit_server_id.as_deref().and_then(|e| servers.iter().find(|s| s.id == e)) {
            Some(x) => format!("{} via {}", x.name, target.name),
            None => target.name.clone(),
        };
        st.connected_server = Some(label.clone());
        st.connected_at = Some(beyond_common::now_unix());
        self.store.save(&st)?;
        Ok(label)
    }

    fn stop_relay(&self) {
        if let Some(r) = self.relay.lock().unwrap().take() {
            r.stop();
        }
    }

    /// True while a stealth relay is running in this process (CLI must stay alive for it).
    pub fn relay_active(&self) -> bool {
        self.relay.lock().unwrap().is_some()
    }

    pub async fn disconnect(&self) -> anyhow::Result<()> {
        let _g = self.lock.lock().await;
        let mut st = self.store.load();
        let path = self.store.tunnel_conf_path();
        let down = self.backend.down(&path);
        self.stop_relay();
        if let Some(sid) = st.session_id.take() {
            let r = self.authed(move |api, t| {
                let sid = sid.clone();
                async move { api.disconnect(&t, &sid).await }
            })
            .await;
            if let Err(e) = r {
                tracing::warn!(error = %e, "failed to report disconnect");
            }
        }
        st.connected_server = None;
        st.connected_at = None;
        self.store.save(&st)?;
        let _ = std::fs::remove_file(&path);
        down.or_else(|e| if self.backend.name() == "dry-run" { Ok(()) } else { Err(e) })
    }

    pub async fn logout(&self) -> anyhow::Result<()> {
        let _ = self.disconnect().await;
        let mut st = self.store.load();
        if let (Ok(api), Some(rt)) = (self.api(&st), st.refresh_token.clone()) {
            let _ = api.logout(&rt).await;
        }
        st.access_token = None;
        st.refresh_token = None;
        self.store.save(&st)?;
        Ok(())
    }

    pub fn status(&self) -> Status {
        let st = self.store.load();
        let ts = self.backend.stats();
        Status {
            logged_in: st.access_token.is_some(),
            email: st.email,
            connected: ts.up && st.connected_server.is_some(),
            server: st.connected_server,
            connected_at: st.connected_at,
            backend: self.backend.name(),
            rx_bytes: ts.rx_bytes,
            tx_bytes: ts.tx_bytes,
            latest_handshake: ts.latest_handshake,
            settings: st.settings,
        }
    }

    pub fn update_settings(&self, s: Settings) -> anyhow::Result<Settings> {
        for r in &s.exclude_routes {
            r.parse::<beyond_common::cidr::Cidr4>().map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        let mut st = self.store.load();
        st.settings = s;
        self.store.save(&st)?;
        Ok(st.settings)
    }
}
