//! Filtering + logging DNS forwarder bound to the tunnel address.
//!
//! Every tunnelled client uses this resolver (pushed via `DNS =` in the
//! client config), which gives: DNS-leak protection, NetShield-style
//! blocking, and per-user "where did they go" activity logs.

use crate::state::State;
use beyond_common::dns;
use beyond_common::telemetry::DnsLogEntry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Clone)]
pub enum Upstream {
    Udp(SocketAddr),
    Doh(String, reqwest::Client),
}

impl Upstream {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some(rest) = s.strip_prefix("udp://") {
            Ok(Upstream::Udp(rest.parse()?))
        } else if s.starts_with("https://") {
            let c = reqwest::Client::builder().timeout(Duration::from_secs(4)).https_only(true).build()?;
            Ok(Upstream::Doh(s.to_string(), c))
        } else {
            anyhow::bail!("unsupported DNS upstream {s}")
        }
    }

    pub async fn resolve(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Upstream::Udp(addr) => {
                let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
                let sock = UdpSocket::bind(bind).await?;
                sock.connect(addr).await?;
                sock.send(query).await?;
                let mut buf = vec![0u8; 4096];
                let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await??;
                buf.truncate(n);
                Ok(buf)
            }
            Upstream::Doh(url, http) => {
                // RFC 8484 wire-format POST: upstream queries are encrypted.
                let r = http
                    .post(url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .body(query.to_vec())
                    .send()
                    .await?
                    .error_for_status()?;
                Ok(r.bytes().await?.to_vec())
            }
        }
    }
}

/// Decide the response for a query. Returns (response, log entry).
pub async fn handle(state: &State, up: &Upstream, pkt: &[u8], src: SocketAddr) -> Option<(Vec<u8>, Option<DnsLogEntry>)> {
    let q = dns::parse_query(pkt).ok()?;
    let blocked = state.is_blocked(&q.name);
    let ip = src.ip().to_string();
    let peer = state.peers_by_ip.read().unwrap().get(&ip).cloned();
    let entry = DnsLogEntry {
        client_ip: ip,
        user_id: peer.as_ref().map(|p| p.user_id.clone()),
        device_id: peer.as_ref().map(|p| p.device_id.clone()),
        domain: q.name.clone(),
        qtype: dns::qtype_name(q.qtype).into(),
        blocked,
        ts: beyond_common::now_unix(),
    };
    // Don't log the client's own reverse lookups / noise.
    let log = if q.name.is_empty() || q.name.ends_with(".arpa") { None } else { Some(entry) };
    if blocked {
        return Some((dns::blocked_response(pkt, &q), log));
    }
    match up.resolve(pkt).await {
        Ok(resp) => Some((resp, log)),
        Err(e) => {
            tracing::warn!(error = %e, "upstream DNS failed");
            None
        }
    }
}

pub async fn serve(state: Arc<State>, listen: String, upstream: Upstream) -> anyhow::Result<()> {
    let sock = Arc::new(UdpSocket::bind(&listen).await?);
    tracing::info!(%listen, "DNS resolver listening");
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let pkt = buf[..n].to_vec();
        let (state, up, sock) = (state.clone(), upstream.clone(), sock.clone());
        tokio::spawn(async move {
            if let Some((resp, log)) = handle(&state, &up, &pkt, src).await {
                let _ = sock.send_to(&resp, src).await;
                if let Some(l) = log {
                    state.push_dns(l);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beyond_common::blocklist::Blocklist;
    use beyond_common::telemetry::PeerSpec;

    #[tokio::test]
    async fn blocked_domain_is_sinkholed_and_attributed() {
        let mut bl = Blocklist::new();
        bl.insert("ads.test");
        let st = State::new("gw".into(), bl);
        st.peers_by_ip.write().unwrap().insert(
            "10.8.0.2".into(),
            PeerSpec { public_key: "k".into(), preshared_key: None, tunnel_ip: "10.8.0.2".into(), user_id: "u1".into(), device_id: "d1".into(), exit_server_id: None },
        );
        // Upstream that would fail: blocked names must never reach it.
        let up = Upstream::Udp("127.0.0.1:9".parse().unwrap());
        let q = dns::build_query(42, "x.ads.test", dns::TYPE_A);
        let (resp, log) = handle(&st, &up, &q, "10.8.0.2:5353".parse().unwrap()).await.unwrap();
        assert_eq!(&resp[0..2], &[0, 42]);
        let log = log.unwrap();
        assert!(log.blocked);
        assert_eq!(log.user_id.as_deref(), Some("u1"));
        assert_eq!(log.domain, "x.ads.test");
    }

    #[tokio::test]
    async fn forwards_to_udp_upstream() {
        // Fake upstream echoing a canned answer.
        let fake = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = fake.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            let (n, from) = fake.recv_from(&mut b).await.unwrap();
            let mut r = b[..n].to_vec();
            r[2] |= 0x80;
            fake.send_to(&r, from).await.unwrap();
        });
        let st = State::new("gw".into(), Blocklist::new());
        let q = dns::build_query(9, "example.com", dns::TYPE_A);
        let (resp, log) = handle(&st, &Upstream::Udp(addr), &q, "10.8.0.9:1".parse().unwrap()).await.unwrap();
        assert_eq!(resp[2] & 0x80, 0x80);
        assert!(!log.unwrap().blocked);
    }

    #[test]
    fn upstream_parsing() {
        assert!(Upstream::parse("udp://1.1.1.1:53").is_ok());
        assert!(Upstream::parse("https://dns.example/dns-query").is_ok());
        assert!(Upstream::parse("tcp://x").is_err());
    }
}
