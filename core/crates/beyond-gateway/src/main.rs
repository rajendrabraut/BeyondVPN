//! beyond-gateway — runs next to kernel WireGuard on each VPN node.

mod config;
mod cp;
mod dns;
mod hop;
mod proxy;
mod state;
mod wg;

use beyond_common::blocklist::Blocklist;
use beyond_common::telemetry::{DnsLogBatch, Heartbeat, ProxyLogBatch, UsageReport};
use beyond_common::wgdump::DeltaTracker;
use clap::{Parser, Subcommand};
use state::{LoggingMode, State};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "beyond-gateway", version, about = "Beyond VPN gateway node agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the gateway services.
    Run {
        #[arg(short, long, default_value = "/etc/beyondvpn/gateway.toml")]
        config: PathBuf,
    },
    /// Generate a WireGuard keypair (private key to stdout, public to stderr).
    Genkey,
    /// Validate a config file and exit.
    CheckConfig {
        #[arg(short, long)]
        config: PathBuf,
    },
}

fn load_blocklists(files: &[PathBuf]) -> Blocklist {
    let mut bl = Blocklist::new();
    for f in files {
        match std::fs::read_to_string(f) {
            Ok(t) => {
                let n = bl.load_text(&t);
                tracing::info!(file = %f.display(), entries = n, "blocklist loaded");
            }
            Err(e) => tracing::warn!(file = %f.display(), error = %e, "blocklist unreadable"),
        }
    }
    bl
}

fn public_key(cfg: &config::GatewayConfig) -> anyhow::Result<String> {
    match &cfg.private_key_file {
        Some(p) => Ok(beyond_common::keys::public_from_private(&std::fs::read_to_string(p)?)?),
        None => {
            anyhow::ensure!(cfg.dry_run, "private_key_file is required unless dry_run = true");
            Ok(beyond_common::keys::generate_keypair().public_key)
        }
    }
}

fn stealth_port(cfg: &config::GatewayConfig) -> Option<u16> {
    if !cfg.stealth.enabled {
        return None;
    }
    cfg.stealth.public_port.or_else(|| cfg.stealth.listen.rsplit_once(':').and_then(|(_, p)| p.parse().ok()))
}

#[allow(clippy::too_many_arguments)]
async fn sync_once(st: &State, cp: &cp::ControlPlane, wg: &wg::Wg, hops: Option<&hop::Hops>, hop_pub: Option<&str>, cfg: &config::GatewayConfig, pubkey: &str) -> anyhow::Result<()> {
    let resp = cp.peers().await?;
    if let Some(k) = &resp.signing_public_key {
        *st.signing_key.write().unwrap() = Some(beyond_common::token::parse_public_key(k).map_err(|e| anyhow::anyhow!("{e}"))?);
    }
    *st.logging.write().unwrap() = LoggingMode::parse(&resp.logging_mode);
    *st.revoked.write().unwrap() = resp.revoked_subjects.iter().cloned().collect();
    let mut pol = Blocklist::new();
    for d in &resp.blocked_domains {
        pol.insert(d);
    }
    *st.policy_blocklist.write().unwrap() = pol;
    let by_ip: HashMap<String, _> = resp.peers.iter().map(|p| (p.tunnel_ip.clone(), p.clone())).collect();
    *st.peers_by_ip.write().unwrap() = by_ip;

    let current: HashSet<String> = wg.dump()?.map(|d| d.peers.into_iter().map(|p| p.public_key).collect()).unwrap_or_default();
    // Entry gateways that use us as their multi-hop exit are ordinary wg0 peers.
    let mut desired = resp.peers.clone();
    desired.extend(resp.hop_peers.iter().cloned());
    let plan = wg::plan(&current, &desired);
    wg.apply(&plan)?;
    if let Some(h) = hops {
        if let Err(e) = h.sync(&resp.peers, &resp.hops) {
            tracing::warn!(error = %e, "multi-hop sync failed");
        }
    }
    let n = resp.peers.len() as u32;
    cp.post(
        "heartbeat",
        &Heartbeat {
            public_key: pubkey.to_string(),
            listen_port: cfg.listen_port,
            active_peers: n,
            load: (n as f32 / cfg.capacity.max(1) as f32).min(1.0),
            version: env!("CARGO_PKG_VERSION").into(),
            hop_public_key: hop_pub.map(Into::into),
            stealth_port: stealth_port(cfg),
        },
    )
    .await?;
    tracing::debug!(peers = n, removed = plan.remove.len(), "peer sync complete");
    Ok(())
}

async fn run(cfg: config::GatewayConfig) -> anyhow::Result<()> {
    let st = Arc::new(State::new(cfg.gateway_id.clone(), load_blocklists(&cfg.dns.blocklist_files)));
    let cp = Arc::new(cp::ControlPlane::new(&cfg.control_plane_url, &cfg.gateway_id, &cfg.gateway_key)?);
    let wg = Arc::new(wg::Wg { iface: cfg.interface.clone(), dry_run: cfg.dry_run });
    let pubkey = public_key(&cfg)?;
    tracing::info!(gateway = %cfg.gateway_id, %pubkey, dry_run = cfg.dry_run, "starting");
    let hops = (cfg.multihop.enabled && (cfg.dry_run || cfg!(target_os = "linux"))).then(|| hop::Hops { dry_run: cfg.dry_run, key_file: cfg.multihop.key_file.clone() });
    let hop_pub = match &hops {
        Some(h) => match h.public_key() {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::warn!(error = %e, "multi-hop disabled: uplink key unavailable");
                None
            }
        },
        None => None,
    };
    let hops = if hop_pub.is_some() { hops } else { None };

    // Peer/policy sync + heartbeat.
    {
        let (st, cp, wg, cfg, pubkey) = (st.clone(), cp.clone(), wg.clone(), cfg.clone(), pubkey.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(cfg.sync_interval_secs.max(2)));
            loop {
                tick.tick().await;
                if let Err(e) = sync_once(&st, &cp, &wg, hops.as_ref(), hop_pub.as_deref(), &cfg, &pubkey).await {
                    tracing::warn!(error = %e, "sync failed");
                }
            }
        });
    }
    // Usage metering from WireGuard counters.
    {
        let (cp, wg) = (cp.clone(), wg.clone());
        tokio::spawn(async move {
            let mut tracker = DeltaTracker::new();
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                match wg.dump() {
                    Ok(Some(d)) => {
                        let samples = tracker.update(&d.peers);
                        if !samples.is_empty() {
                            if let Err(e) = cp.post("usage", &UsageReport { samples }).await {
                                tracing::warn!(error = %e, "usage upload failed");
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(error = %e, "wg dump failed"),
                }
            }
        });
    }
    // Activity log flushing.
    {
        let (st, cp) = (st.clone(), cp.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let d = st.take_dns();
                if !d.is_empty() {
                    if let Err(e) = cp.post("dns-logs", &DnsLogBatch { entries: d.clone() }).await {
                        tracing::warn!(error = %e, "dns log upload failed");
                        st.requeue_dns(d);
                    }
                }
                let p = st.take_proxy();
                if !p.is_empty() {
                    if let Err(e) = cp.post("proxy-logs", &ProxyLogBatch { entries: p.clone() }).await {
                        tracing::warn!(error = %e, "proxy log upload failed");
                        st.requeue_proxy(p);
                    }
                }
            }
        });
    }

    let mut tasks = Vec::new();
    if cfg.dns.enabled {
        let up = dns::Upstream::parse(&cfg.dns.upstream)?;
        tasks.push(tokio::spawn(dns::serve(st.clone(), cfg.dns.listen.clone(), up)));
    }
    if cfg.proxy.enabled {
        tasks.push(tokio::spawn(proxy::serve(st.clone(), cfg.proxy.clone())));
    }
    if cfg.stealth.enabled {
        let s = &cfg.stealth;
        let cert = s.tls_cert.as_deref().or(cfg.proxy.tls_cert.as_deref());
        let key = s.tls_key.as_deref().or(cfg.proxy.tls_key.as_deref());
        let tls = proxy::tls_from_files(cert, key)?;
        if tls.is_none() {
            tracing::warn!("stealth relay running WITHOUT TLS: only behind a TLS terminator or for tests");
        }
        let listener = tokio::net::TcpListener::bind(&s.listen).await?;
        let wg_target: std::net::SocketAddr = format!("127.0.0.1:{}", cfg.listen_port).parse()?;
        tracing::info!(listen = %s.listen, tls = tls.is_some(), "stealth relay listening");
        tasks.push(tokio::spawn(beyond_stealth::serve(listener, tls, wg_target)));
    }
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
        r = futures_first(tasks) => tracing::error!(?r, "service exited"),
    }
    Ok(())
}

async fn futures_first(tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>>) -> String {
    if tasks.is_empty() {
        std::future::pending::<()>().await;
    }
    let mut set = tokio::task::JoinSet::new();
    for t in tasks {
        set.spawn(t);
    }
    match set.join_next().await {
        Some(Ok(Ok(Err(e)))) => e.to_string(),
        other => format!("{other:?}"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match Cli::parse().cmd {
        Cmd::Run { config } => run(config::GatewayConfig::load(&config)?).await,
        Cmd::Genkey => {
            let kp = beyond_common::keys::generate_keypair();
            println!("{}", kp.private_key);
            eprintln!("public: {}", kp.public_key);
            Ok(())
        }
        Cmd::CheckConfig { config } => {
            let c = config::GatewayConfig::load(&config)?;
            dns::Upstream::parse(&c.dns.upstream)?;
            println!("config OK: gateway {}", c.gateway_id);
            Ok(())
        }
    }
}
