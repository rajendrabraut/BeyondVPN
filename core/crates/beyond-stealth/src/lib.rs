//! Stealth transport ("anti-blocking mode").
//!
//! Some networks (corporate firewalls, hotel Wi-Fi, censoring ISPs) drop UDP or
//! fingerprint the WireGuard handshake. Stealth mode carries the unchanged,
//! already-encrypted WireGuard datagrams inside an ordinary TLS connection to
//! port 443, so on the wire it looks like HTTPS.
//!
//! ```text
//!  WireGuard ──UDP──▶ 127.0.0.1:<local>  [client relay]  ══TLS/443══▶  [gateway relay] ──UDP──▶ 127.0.0.1:51820 (wg0)
//! ```
//!
//! Protocol (inside TLS):
//!   client → `GET /beyond-wg HTTP/1.1\r\nHost: <sni>\r\nUpgrade: beyond-wg\r\nConnection: Upgrade\r\n\r\n`
//!   server → `HTTP/1.1 101 Switching Protocols\r\nUpgrade: beyond-wg\r\nConnection: Upgrade\r\n\r\n`
//!   then both directions: frames of `u16 big-endian length || datagram`.
//!
//! Anything else gets a plain `404` like a normal web server (active-probe resistance).
//! Security still comes from WireGuard itself; TLS only hides the protocol.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub const PATH: &str = "/beyond-wg";
pub const MAX_DATAGRAM: usize = 65_535;
const MAX_HEAD: usize = 8 * 1024;
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 146\r\nConnection: close\r\n\r\n<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
const SWITCH: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: beyond-wg\r\nConnection: Upgrade\r\n\r\n";

pub fn upgrade_request(host: &str) -> Vec<u8> {
    format!("GET {PATH} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nUpgrade: beyond-wg\r\nConnection: Upgrade\r\n\r\n").into_bytes()
}

/// True when an HTTP request head asks for the stealth upgrade.
pub fn is_upgrade(head: &[u8]) -> bool {
    let text = match std::str::from_utf8(head) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    if parts.next() != Some("GET") || parts.next() != Some(PATH) {
        return false;
    }
    lines.any(|l| {
        l.split_once(':')
            .map(|(k, v)| k.trim().eq_ignore_ascii_case("upgrade") && v.trim().eq_ignore_ascii_case("beyond-wg"))
            .unwrap_or(false)
    })
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> anyhow::Result<Vec<u8>> {
    // Byte-at-a-time so no frame bytes after the head are consumed.
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(head.len() < MAX_HEAD, "request head too large");
        if s.read(&mut b).await? == 0 {
            anyhow::bail!("connection closed during handshake");
        }
        head.push(b[0]);
    }
    Ok(head)
}

pub async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "datagram too large"))?;
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    s.write_all(&buf).await?;
    s.flush().await
}

/// Returns `Ok(None)` on clean EOF.
pub async fn read_frame<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> std::io::Result<Option<usize>> {
    let mut len = [0u8; 2];
    match s.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u16::from_be_bytes(len) as usize;
    buf.resize(n, 0);
    s.read_exact(&mut buf[..n]).await?;
    Ok(Some(n))
}

/// Pump frames between a byte stream and a *connected* UDP socket until either side closes.
pub async fn pump<S: AsyncRead + AsyncWrite + Unpin>(stream: S, udp: Arc<UdpSocket>) -> anyhow::Result<()> {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let u2 = udp.clone();
    let up = async move {
        let mut buf = Vec::with_capacity(2048);
        while let Some(n) = read_frame(&mut rd, &mut buf).await? {
            u2.send(&buf[..n]).await?;
        }
        anyhow::Ok(())
    };
    let down = async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let n = udp.recv(&mut buf).await?;
            write_frame(&mut wr, &buf[..n]).await?;
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

// ------------------------------------------------------------------ server (gateway)

/// Handle one accepted (already TLS-terminated) connection.
pub async fn handle_server_conn<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, wg_target: SocketAddr) -> anyhow::Result<()> {
    let head = match tokio::time::timeout(Duration::from_secs(10), read_head(&mut s)).await {
        Ok(Ok(h)) => h,
        _ => return Ok(()),
    };
    if !is_upgrade(&head) {
        let _ = s.write_all(NOT_FOUND).await;
        let _ = s.shutdown().await;
        return Ok(());
    }
    s.write_all(SWITCH).await?;
    s.flush().await?;
    let bind: SocketAddr = if wg_target.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let udp = UdpSocket::bind(bind).await?;
    udp.connect(wg_target).await?;
    pump(s, Arc::new(udp)).await
}

/// Accept loop. `acceptor = None` means plain TCP (tests, or behind a TLS-terminating LB).
pub async fn serve(listener: TcpListener, acceptor: Option<tokio_rustls::TlsAcceptor>, wg_target: SocketAddr) -> anyhow::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let acc = acceptor.clone();
        tokio::spawn(async move {
            let r = match acc {
                Some(a) => match tokio::time::timeout(Duration::from_secs(10), a.accept(tcp)).await {
                    Ok(Ok(tls)) => handle_server_conn(tls, wg_target).await,
                    _ => Ok(()),
                },
                None => handle_server_conn(tcp, wg_target).await,
            };
            if let Err(e) = r {
                tracing::debug!(%peer, error = %e, "stealth connection ended");
            }
        });
    }
}

// ------------------------------------------------------------------ client (agent)

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Gateway host name (also the TLS SNI and certificate name).
    pub host: String,
    pub port: u16,
    /// Pre-resolved address to dial (keeps the relay on IPv4 that the tunnel excludes).
    /// `None` resolves `host`.
    pub addr: Option<SocketAddr>,
    /// Plain TCP instead of TLS. Only for tests.
    pub insecure_plaintext: bool,
}

fn tls_connector() -> tokio_rustls::TlsConnector {
    use tokio_rustls::rustls;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

async fn client_session<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, host: &str, local: Arc<UdpSocket>) -> anyhow::Result<()> {
    s.write_all(&upgrade_request(host)).await?;
    s.flush().await?;
    let head = tokio::time::timeout(Duration::from_secs(10), read_head(&mut s)).await??;
    anyhow::ensure!(head.starts_with(b"HTTP/1.1 101"), "gateway refused stealth upgrade");
    pump(s, local).await
}

/// Running client relay. Point WireGuard's `Endpoint` at [`ClientRelay::local_addr`].
pub struct ClientRelay {
    pub local_addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl ClientRelay {
    pub async fn start(cfg: ClientConfig) -> anyhow::Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = sock.local_addr()?;
        let sock = Arc::new(sock);
        let task = tokio::spawn(async move {
            let connector = tls_connector();
            let mut backoff = Duration::from_millis(250);
            // Full-size buffer: Windows fails a peek into a buffer smaller than the datagram (WSAEMSGSIZE).
            let mut probe = vec![0u8; MAX_DATAGRAM];
            loop {
                // WireGuard sends first; learn its source port so the socket can be connected.
                let from = match sock.peek_from(&mut probe).await {
                    Ok((_, from)) => from,
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue, // Windows ICMP noise
                    Err(_) => {
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                };
                if sock.connect(from).await.is_err() {
                    continue;
                }
                let r: anyhow::Result<()> = async {
                    let tcp = match cfg.addr {
                        Some(a) => TcpStream::connect(a).await?,
                        None => TcpStream::connect((cfg.host.as_str(), cfg.port)).await?,
                    };
                    let _ = tcp.set_nodelay(true);
                    if cfg.insecure_plaintext {
                        client_session(tcp, &cfg.host, sock.clone()).await
                    } else {
                        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(cfg.host.clone())?;
                        let tls = connector.connect(name, tcp).await?;
                        client_session(tls, &cfg.host, sock.clone()).await
                    }
                }
                .await;
                match r {
                    Ok(()) => backoff = Duration::from_millis(250),
                    Err(e) => {
                        tracing::warn!(error = %e, "stealth relay disconnected; retrying");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(10));
                    }
                }
            }
        });
        Ok(ClientRelay { local_addr, task })
    }

    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for ClientRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_detection() {
        assert!(is_upgrade(&upgrade_request("gw.example")));
        assert!(!is_upgrade(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(!is_upgrade(b"GET /beyond-wg HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(!is_upgrade(b"POST /beyond-wg HTTP/1.1\r\nUpgrade: beyond-wg\r\n\r\n"));
        assert!(!is_upgrade(&[0xff, 0xfe, 0x0d, 0x0a]));
    }

    #[tokio::test]
    async fn frames_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_frame(&mut a, b"hello").await.unwrap();
        write_frame(&mut a, &[]).await.unwrap();
        drop(a);
        let mut buf = Vec::new();
        assert_eq!(read_frame(&mut b, &mut buf).await.unwrap(), Some(5));
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(read_frame(&mut b, &mut buf).await.unwrap(), Some(0));
        assert_eq!(read_frame(&mut b, &mut buf).await.unwrap(), None);
    }

    /// Full path: "WireGuard" UDP -> client relay -> TCP -> server relay -> UDP echo ("wg0") and back.
    #[tokio::test]
    async fn relays_datagrams_end_to_end() {
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wg_addr = wg.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, from) = wg.recv_from(&mut buf).await.unwrap();
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                wg.send_to(&reply, from).await.unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve(listener, None, wg_addr));
        let relay = ClientRelay::start(ClientConfig { host: "127.0.0.1".into(), port, addr: None, insecure_plaintext: true }).await.unwrap();

        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(relay.local_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        for msg in [&b"handshake-initiation"[..], &[7u8; 1400][..]] {
            app.send(msg).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), app.recv(&mut buf)).await.expect("reply").unwrap();
            assert_eq!(&buf[..5], b"echo:");
            assert_eq!(&buf[5..n], msg);
        }
        relay.stop();
    }

    #[tokio::test]
    async fn probes_get_plain_404() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, None, "127.0.0.1:9".parse().unwrap()));
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n").await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert!(out.starts_with(b"HTTP/1.1 404 Not Found"));
    }
}
