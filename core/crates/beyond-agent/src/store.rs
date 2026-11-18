//! Persistent agent state (tokens, device identity, user settings).
//!
//! Stored under the OS config dir (`%APPDATA%\BeyondVPN`, `~/.config/beyondvpn`,
//! `~/Library/Application Support/BeyondVPN`). The WireGuard private key is kept
//! in its own file with owner-only permissions on Unix.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    #[serde(default = "yes")]
    pub kill_switch: bool,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default)]
    pub exclude_routes: Vec<String>,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default)]
    pub preferred_server: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentState {
    #[serde(default)]
    pub api_url: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub device_public_key: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub connected_server: Option<String>,
    #[serde(default)]
    pub connected_at: Option<u64>,
    #[serde(default)]
    pub settings: Settings,
}

pub struct Store {
    pub dir: PathBuf,
}

pub const TUNNEL_NAME: &str = "beyond0";

impl Store {
    pub fn default_dir() -> PathBuf {
        if let Ok(d) = std::env::var("BEYOND_AGENT_DIR") {
            return PathBuf::from(d);
        }
        dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("BeyondVPN")
    }

    pub fn open(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        restrict(&dir, 0o700);
        Ok(Store { dir })
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn load(&self) -> AgentState {
        std::fs::read_to_string(self.state_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, s: &AgentState) -> anyhow::Result<()> {
        write_private(&self.state_path(), serde_json::to_string_pretty(s)?.as_bytes())
    }

    pub fn private_key(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join("device.key")).ok().map(|s| s.trim().to_string())
    }

    /// Return the device keypair, generating it on first use.
    pub fn ensure_keypair(&self) -> anyhow::Result<(String, String)> {
        if let Some(k) = self.private_key() {
            if let Ok(p) = beyond_common::keys::public_from_private(&k) {
                return Ok((k, p));
            }
        }
        let kp = beyond_common::keys::generate_keypair();
        write_private(&self.dir.join("device.key"), kp.private_key.as_bytes())?;
        Ok((kp.private_key, kp.public_key))
    }

    pub fn tunnel_conf_path(&self) -> PathBuf {
        self.dir.join(format!("{TUNNEL_NAME}.conf"))
    }

    /// Bearer token protecting the local control API (read by the desktop UI).
    pub fn api_token(&self) -> anyhow::Result<String> {
        let p = self.dir.join("agent.token");
        if let Ok(t) = std::fs::read_to_string(&p) {
            if t.trim().len() == 64 {
                return Ok(t.trim().to_string());
            }
        }
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let t = hex::encode(b);
        write_private(&p, t.as_bytes())?;
        Ok(t)
    }
}

pub fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    restrict(&tmp, 0o600);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_p: &Path, _mode: u32) {
    // On Windows the profile directory (%APPDATA%) is already ACL'd to the user;
    // the service runs as LocalSystem. DPAPI wrapping is tracked in REMAINING.md.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beyond-agent-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn state_roundtrip_and_stable_keys() {
        let s = Store::open(tmpdir("state")).unwrap();
        let mut st = s.load();
        assert!(st.settings.exclude_routes.is_empty());
        st.email = Some("a@b.c".into());
        s.save(&st).unwrap();
        assert_eq!(s.load().email.as_deref(), Some("a@b.c"));
        let (k1, p1) = s.ensure_keypair().unwrap();
        let (k2, p2) = s.ensure_keypair().unwrap();
        assert_eq!((k1, p1), (k2, p2));
        let t1 = s.api_token().unwrap();
        assert_eq!(t1, s.api_token().unwrap());
        assert_eq!(t1.len(), 64);
    }
}
