//! Authenticated HTTP(S) forward proxy for the browser extension.
//!
//! Browsers cannot run WireGuard from an extension, so the extension
//! routes browser traffic through this proxy instead (like Proton's
//! browser extension). Clients authenticate with a short-lived Ed25519
//! token minted by the control plane; the proxy is reached over TLS.

use crate::config::ProxyConfig;
use crate::state::State;
use base64::{engine::general_purpose::STANDARD, Engine};
use beyond_common::telemetry::ProxyLogEntry;
use beyond_common::token::{self, Claims};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub fn parse_head(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut rl = lines.next()?.split(' ');
    let (method, target, version) = (rl.next()?, rl.next()?, rl.next()?);
    if rl.next().is_some() || !version.starts_with("HTTP/1.") {
        return None;
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':')?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Some(Request { method: method.into(), target: target.into(), version: version.into(), headers })
}

/// Token from `Proxy-Authorization: Basic base64(user:token)` or `Bearer token`.
pub fn extract_token(req: &Request) -> Option<String> {
    let v = req.header("proxy-authorization")?;
    if let Some(b) = v.strip_prefix("Bearer ") {
        return Some(b.trim().to_string());
    }
    let b = v.strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(b.trim()).ok()?).ok()?;
    let (_, pass) = decoded.split_once(':')?;
    Some(pass.to_string())
}

fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']')
}

/// Returns (host, port, origin-form path) for CONNECT or absolute-form requests.
pub fn parse_target(req: &Request) -> Option<(String, u16, String)> {
    if req.method.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = split_authority(&req.target, None)?;
        return Some((h, p, String::new()));
    }
    let rest = req.target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (h, p) = split_authority(authority, Some(80))?;
    Some((h, p, path.to_string()))
}

/// Split `host:port` / `[v6]:port`; `default_port` applies when no port is given.
fn split_authority(a: &str, default_port: Option<u16>) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        match tail.strip_prefix(':') {
            Some(p) => (h, p.parse().ok()?),
            None if tail.is_empty() => (h, default_port?),
            None => return None,
        }
    } else {
        match a.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (a, default_port?),
        }
    };
    valid_host(host).then(|| (host.to_ascii_lowercase(), port))
}

/// SSRF protection: never let the proxy reach internal networks.
pub fn is_forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // CGNAT 100.64/10
                || o[0] == 0
        }
        IpAddr::V6(v6) => {
            if let Some(m) = v6.to_ipv4_mapped() {
                return is_forbidden(IpAddr::V4(m));
            }
            let s = v6.segments();
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("eof before headers");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            anyhow::bail!("headers too large");
        }
    }
}

async fn respond<S: AsyncWrite + Unpin>(s: &mut S, status: &str, extra: &str) -> anyhow::Result<()> {
    let msg = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n");
    s.write_all(msg.as_bytes()).await?;
    s.flush().await?;
    Ok(())
}

pub fn authenticate(state: &State, req: &Request) -> Option<Claims> {
    let tok = extract_token(req)?;
    let key = (*state.signing_key.read().unwrap())?;
    let c = token::verify(&tok, &key, "proxy", Some(&state.gateway_id), beyond_common::now_unix(), 30).ok()?;
    if state.revoked.read().unwrap().contains(&c.sub) {
        return None;
    }
    Some(c)
}

pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(state: Arc<State>, cfg: Arc<ProxyConfig>, mut s: S) -> anyhow::Result<()> {
    let (head, leftover) = tokio::time::timeout(Duration::from_secs(15), read_head(&mut s)).await??;
    let Some(req) = parse_head(&head) else {
        return respond(&mut s, "400 Bad Request", "").await;
    };
    let Some(claims) = authenticate(&state, &req) else {
        return respond(&mut s, "407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"Beyond VPN\"\r\n").await;
    };
    let Some((host, port, path)) = parse_target(&req) else {
        return respond(&mut s, "400 Bad Request", "").await;
    };
    let started = Instant::now();
    let mut log = ProxyLogEntry {
        user_id: claims.sub.clone(),
        device_id: claims.sid.clone(),
        host: host.clone(),
        port,
        bytes_up: 0,
        bytes_down: 0,
        ts: beyond_common::now_unix(),
        duration_ms: 0,
        blocked: false,
    };
    if !cfg.allowed_ports.contains(&port) {
        return respond(&mut s, "403 Forbidden", "").await;
    }
    if state.is_blocked(&host) {
        log.blocked = true;
        state.push_proxy(log);
        return respond(&mut s, "403 Forbidden", "X-Beyond-Block: policy\r\n").await;
    }
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(a) => a.collect(),
        Err(_) => return respond(&mut s, "502 Bad Gateway", "").await,
    };
    if addrs.is_empty() || (!cfg.allow_private_destinations && addrs.iter().any(|a| is_forbidden(a.ip()))) {
        return respond(&mut s, "403 Forbidden", "X-Beyond-Block: destination\r\n").await;
    }
    let mut up = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addrs[..])).await {
        Ok(Ok(u)) => u,
        _ => return respond(&mut s, "504 Gateway Timeout", "").await,
    };
    if req.method.eq_ignore_ascii_case("CONNECT") {
        s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    } else {
        // Rewrite to origin-form and strip hop-by-hop / credential headers.
        let mut out = format!("{} {} {}\r\n", req.method, path, req.version);
        for (k, v) in &req.headers {
            let lk = k.to_ascii_lowercase();
            if lk.starts_with("proxy-") || lk == "connection" || lk == "keep-alive" {
                continue;
            }
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("Connection: close\r\n\r\n");
        up.write_all(out.as_bytes()).await?;
    }
    if !leftover.is_empty() {
        up.write_all(&leftover).await?;
        log.bytes_up += leftover.len() as u64;
    }
    let res = tokio::io::copy_bidirectional(&mut s, &mut up).await;
    if let Ok((a, b)) = res {
        log.bytes_up += a;
        log.bytes_down += b;
    }
    log.duration_ms = started.elapsed().as_millis() as u64;
    state.push_proxy(log);
    Ok(())
}

fn tls_acceptor(cfg: &ProxyConfig) -> anyhow::Result<Option<tokio_rustls::TlsAcceptor>> {
    tls_from_files(cfg.tls_cert.as_deref(), cfg.tls_key.as_deref())
}

/// TLS acceptor from PEM files; `None` when either path is missing.
pub fn tls_from_files(cert: Option<&std::path::Path>, key: Option<&std::path::Path>) -> anyhow::Result<Option<tokio_rustls::TlsAcceptor>> {
    use tokio_rustls::rustls;
    let (Some(cert), Some(key)) = (cert, key) else {
        return Ok(None);
    };
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?)).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", key.display()))?;
    let sc = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(sc))))
}

pub async fn serve(state: Arc<State>, cfg: ProxyConfig) -> anyhow::Result<()> {
    let tls = tls_acceptor(&cfg)?;
    if tls.is_none() {
        tracing::warn!("proxy running WITHOUT TLS: only use behind a TLS terminator or for local tests");
    }
    let listener = TcpListener::bind(&cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, tls = tls.is_some(), "proxy listening");
    let cfg = Arc::new(cfg);
    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let (state, cfg, tls) = (state.clone(), cfg.clone(), tls.clone());
        tokio::spawn(async move {
            let r = match tls {
                Some(acc) => match tokio::time::timeout(Duration::from_secs(10), acc.accept(sock)).await {
                    Ok(Ok(t)) => handle(state, cfg, t).await,
                    _ => Ok(()),
                },
                None => handle(state, cfg, sock).await,
            };
            if let Err(e) = r {
                tracing::debug!(%peer, error = %e, "proxy connection ended");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beyond_common::blocklist::Blocklist;
    use ed25519_dalek::SigningKey;

    fn req(raw: &str) -> Request {
        parse_head(raw.as_bytes()).unwrap()
    }

    #[test]
    fn parses_connect_and_absolute_targets() {
        let r = req("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(parse_target(&r), Some(("example.com".into(), 443, String::new())));
        let r = req("GET http://Example.com/a?b=1 HTTP/1.1\r\n\r\n");
        assert_eq!(parse_target(&r), Some(("example.com".into(), 80, "/a?b=1".into())));
        let r = req("GET http://example.com:8080 HTTP/1.1\r\n\r\n");
        assert_eq!(parse_target(&r), Some(("example.com".into(), 8080, "/".into())));
        let r = req("GET /relative HTTP/1.1\r\n\r\n");
        assert_eq!(parse_target(&r), None);
        let r = req("CONNECT bad\u{1}host:443 HTTP/1.1\r\n\r\n");
        assert_eq!(parse_target(&r), None);
        assert!(parse_head(b"GARBAGE\r\n\r\n").is_none());
    }

    #[test]
    fn extracts_basic_and_bearer_tokens() {
        let b = STANDARD.encode("beyond:TOKEN123");
        let r = req(&format!("CONNECT a.b:443 HTTP/1.1\r\nProxy-Authorization: Basic {b}\r\n\r\n"));
        assert_eq!(extract_token(&r).as_deref(), Some("TOKEN123"));
        let r = req("CONNECT a.b:443 HTTP/1.1\r\nproxy-authorization: Bearer XYZ\r\n\r\n");
        assert_eq!(extract_token(&r).as_deref(), Some("XYZ"));
    }

    #[test]
    fn ssrf_guard() {
        for ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "0.0.0.0"] {
            assert!(is_forbidden(ip.parse().unwrap()), "{ip} should be forbidden");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700::1111"] {
            assert!(!is_forbidden(ip.parse().unwrap()), "{ip} should be allowed");
        }
    }

    async fn start(state: Arc<State>, cfg: ProxyConfig) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let cfg = Arc::new(cfg);
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let (st, c) = (state.clone(), cfg.clone());
                tokio::spawn(async move {
                    let _ = handle(st, c, s).await;
                });
            }
        });
        addr
    }

    async fn roundtrip(proxy: SocketAddr, raw: String) -> String {
        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(raw.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await.unwrap().unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    #[tokio::test]
    async fn end_to_end_auth_block_and_tunnel() {
        // Echo server standing in for a website.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });

        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut bl = Blocklist::new();
        bl.insert("blocked.test");
        let st = Arc::new(State::new("gw-1".into(), bl));
        *st.signing_key.write().unwrap() = Some(sk.verifying_key());
        let cfg = ProxyConfig { allowed_ports: vec![443, echo_addr.port()], allow_private_destinations: true, ..Default::default() };
        let proxy = start(st.clone(), cfg).await;

        // 1. no credentials -> 407
        let r = roundtrip(proxy, "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n".into()).await;
        assert!(r.starts_with("HTTP/1.1 407"), "{r}");

        let claims = Claims {
            sub: "user-1".into(),
            typ: "proxy".into(),
            exp: beyond_common::now_unix() + 600,
            iat: 0,
            nbf: None,
            aud: Some("gw-1".into()),
            sid: Some("dev-1".into()),
            jti: None,
            email: None,
        };
        let auth = STANDARD.encode(format!("beyond:{}", token::sign(&claims, &sk)));

        // 2. token for another gateway -> 407
        let mut other = claims.clone();
        other.aud = Some("gw-2".into());
        let bad = STANDARD.encode(format!("beyond:{}", token::sign(&other, &sk)));
        let r = roundtrip(proxy, format!("CONNECT 127.0.0.1:443 HTTP/1.1\r\nProxy-Authorization: Basic {bad}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 407"), "{r}");

        // 3. blocked domain -> 403 and logged as blocked
        let r = roundtrip(proxy, format!("CONNECT ads.blocked.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");

        // 4. disallowed port -> 403
        let r = roundtrip(proxy, format!("CONNECT 127.0.0.1:25 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");

        // 5. valid tunnel echoes data
        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n", echo_addr.port()).as_bytes()).await.unwrap();
        let mut b = vec![0u8; 39];
        c.read_exact(&mut b).await.unwrap();
        assert!(String::from_utf8_lossy(&b).starts_with("HTTP/1.1 200"));
        c.write_all(b"hello").await.unwrap();
        let mut e = [0u8; 5];
        c.read_exact(&mut e).await.unwrap();
        assert_eq!(&e, b"hello");
        drop(c);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let logs = st.take_proxy();
        assert!(logs.iter().any(|l| l.blocked && l.host == "ads.blocked.test"));
        assert!(logs.iter().any(|l| !l.blocked && l.bytes_up >= 5 && l.bytes_down >= 5 && l.user_id == "user-1"));

        // 6. revoked user -> 407 even with valid token
        st.revoked.write().unwrap().insert("user-1".into());
        let r = roundtrip(proxy, format!("CONNECT 127.0.0.1:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 407"), "{r}");
    }

    #[tokio::test]
    async fn private_destinations_blocked_by_default() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let st = Arc::new(State::new("gw-1".into(), Blocklist::new()));
        *st.signing_key.write().unwrap() = Some(sk.verifying_key());
        let proxy = start(st, ProxyConfig::default()).await;
        let claims = Claims { sub: "u".into(), typ: "proxy".into(), exp: beyond_common::now_unix() + 60, iat: 0, nbf: None, aud: Some("gw-1".into()), sid: None, jti: None, email: None };
        let auth = STANDARD.encode(format!("x:{}", token::sign(&claims, &sk)));
        let r = roundtrip(proxy, format!("CONNECT 127.0.0.1:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 403") && r.contains("destination"), "{r}");
    }
}
