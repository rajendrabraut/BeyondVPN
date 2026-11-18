//! OS tunnel backends. We deliberately reuse the audited official WireGuard
//! implementations (WireGuard-NT on Windows, kernel/wireguard-go elsewhere)
//! instead of shipping our own packet path.

use crate::store::TUNNEL_NAME;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Default, serde::Serialize, PartialEq, Eq)]
pub struct TunnelStats {
    pub up: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub latest_handshake: u64,
}

pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    fn up(&self, conf: &Path) -> anyhow::Result<()>;
    fn down(&self, conf: &Path) -> anyhow::Result<()>;
    fn stats(&self) -> TunnelStats;
}

fn run(cmd: &mut Command) -> anyhow::Result<String> {
    let out = cmd.output().map_err(|e| anyhow::anyhow!("failed to start {:?}: {e}", cmd.get_program()))?;
    if !out.status.success() {
        anyhow::bail!("{:?} failed: {}", cmd.get_program(), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn parse_transfer(dump: &str) -> TunnelStats {
    // `wg show <if> dump`: first line interface, then peers.
    match beyond_common::wgdump::parse_dump(dump) {
        Some(d) => TunnelStats {
            up: true,
            rx_bytes: d.peers.iter().map(|p| p.rx).sum(),
            tx_bytes: d.peers.iter().map(|p| p.tx).sum(),
            latest_handshake: d.peers.iter().map(|p| p.latest_handshake).max().unwrap_or(0),
        },
        None => TunnelStats::default(),
    }
}

pub struct WindowsBackend {
    pub wireguard_exe: PathBuf,
    pub wg_exe: PathBuf,
}

impl Default for WindowsBackend {
    fn default() -> Self {
        let base = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        WindowsBackend {
            wireguard_exe: Path::new(&base).join("WireGuard").join("wireguard.exe"),
            wg_exe: Path::new(&base).join("WireGuard").join("wg.exe"),
        }
    }
}

impl Backend for WindowsBackend {
    fn name(&self) -> &'static str {
        "wireguard-nt"
    }
    fn up(&self, conf: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(self.wireguard_exe.exists(), "WireGuard for Windows not installed (expected {})", self.wireguard_exe.display());
        let _ = self.down(conf);
        // Installs service WireGuardTunnel$beyond0. With a full-tunnel AllowedIPs
        // WireGuard-NT also installs WFP rules that block untunnelled traffic (kill switch).
        run(Command::new(&self.wireguard_exe).arg("/installtunnelservice").arg(conf))?;
        Ok(())
    }
    fn down(&self, _conf: &Path) -> anyhow::Result<()> {
        run(Command::new(&self.wireguard_exe).args(["/uninstalltunnelservice", TUNNEL_NAME]))?;
        Ok(())
    }
    fn stats(&self) -> TunnelStats {
        run(Command::new(&self.wg_exe).args(["show", TUNNEL_NAME, "dump"])).map(|s| parse_transfer(&s)).unwrap_or_default()
    }
}

/// Linux and macOS: wg-quick (kernel module or wireguard-go).
pub struct WgQuickBackend;

impl Backend for WgQuickBackend {
    fn name(&self) -> &'static str {
        "wg-quick"
    }
    fn up(&self, conf: &Path) -> anyhow::Result<()> {
        let _ = self.down(conf);
        run(Command::new("wg-quick").arg("up").arg(conf))?;
        Ok(())
    }
    fn down(&self, conf: &Path) -> anyhow::Result<()> {
        run(Command::new("wg-quick").arg("down").arg(conf))?;
        Ok(())
    }
    fn stats(&self) -> TunnelStats {
        run(Command::new("wg").args(["show", TUNNEL_NAME, "dump"])).map(|s| parse_transfer(&s)).unwrap_or_default()
    }
}

/// No-op backend for tests/CI (`BEYOND_AGENT_DRY_RUN=1`).
#[derive(Default)]
pub struct DryRunBackend {
    pub up: std::sync::atomic::AtomicBool,
}

impl Backend for DryRunBackend {
    fn name(&self) -> &'static str {
        "dry-run"
    }
    fn up(&self, conf: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(conf.exists(), "config not written");
        self.up.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn down(&self, _conf: &Path) -> anyhow::Result<()> {
        self.up.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn stats(&self) -> TunnelStats {
        TunnelStats { up: self.up.load(std::sync::atomic::Ordering::SeqCst), ..Default::default() }
    }
}

pub fn platform_backend() -> Box<dyn Backend> {
    if std::env::var("BEYOND_AGENT_DRY_RUN").as_deref() == Ok("1") {
        return Box::new(DryRunBackend::default());
    }
    if cfg!(windows) {
        Box::new(WindowsBackend::default())
    } else {
        Box::new(WgQuickBackend)
    }
}

pub fn platform_name() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_parsing() {
        let s = parse_transfer("P\tPUB\t0\toff\nPEER\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t1700\t10\t20\t25\n");
        assert_eq!(s, TunnelStats { up: true, rx_bytes: 10, tx_bytes: 20, latest_handshake: 1700 });
        assert!(!parse_transfer("").up);
    }
}
