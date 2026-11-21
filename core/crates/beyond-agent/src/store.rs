//! Persistent agent state (tokens, device identity, user settings).
//!
//! Stored under the OS config dir (`%APPDATA%\BeyondVPN`, `~/.config/beyondvpn`,
//! `~/Library/Application Support/BeyondVPN`), or `%ProgramData%\BeyondVPN` for the Windows
//! service. Secrets (WireGuard private key, API refresh tokens) are DPAPI-encrypted on Windows
//! and owner-only (0600) on Unix.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Anti-blocking mode: carry WireGuard over TLS/443 (server must offer it).
    #[serde(default)]
    pub stealth: bool,
    /// Multi-hop: leave the internet through this server (entry = the connected server).
    #[serde(default)]
    pub exit_server: Option<String>,
}

fn yes() -> bool {
    true
}

impl Default for Settings {
    /// Secure by default: kill switch on, LAN blocked, no split tunnel.
    fn default() -> Self {
        Settings { kill_switch: true, allow_lan: false, exclude_routes: vec![], auto_connect: false, preferred_server: None, stealth: false, exit_server: None }
    }
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
        // With a "beyondvpn" group, members must be able to reach agent.token (0640) inside.
        restrict(&dir, if token_group().is_some() { 0o750 } else { 0o700 });
        Ok(Store { dir })
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn load(&self) -> AgentState {
        read_secret(&self.state_path()).and_then(|t| serde_json::from_slice(&t).ok()).unwrap_or_default()
    }

    /// State holds API refresh tokens: encrypted at rest on Windows (DPAPI), 0600 elsewhere.
    pub fn save(&self, s: &AgentState) -> anyhow::Result<()> {
        write_secret(&self.state_path(), serde_json::to_string_pretty(s)?.as_bytes())
    }

    pub fn private_key(&self) -> Option<String> {
        let p = self.dir.join("device.key");
        let raw = read_secret(&p)?;
        let key = String::from_utf8(raw).ok()?.trim().to_string();
        // Upgrade a plaintext key written by an older version.
        if cfg!(windows) && std::fs::read(&p).map(|b| !b.starts_with(SECRET_MAGIC)).unwrap_or(false) {
            let _ = write_secret(&p, key.as_bytes());
        }
        Some(key)
    }

    /// Return the device keypair, generating it on first use.
    pub fn ensure_keypair(&self) -> anyhow::Result<(String, String)> {
        if let Some(k) = self.private_key() {
            if let Ok(p) = beyond_common::keys::public_from_private(&k) {
                return Ok((k, p));
            }
        }
        let kp = beyond_common::keys::generate_keypair();
        write_secret(&self.dir.join("device.key"), kp.private_key.as_bytes())?;
        Ok((kp.private_key, kp.public_key))
    }

    /// Lock the state directory down for the machine-wide service (Windows): only SYSTEM and
    /// Administrators; the token file additionally readable by interactively signed-in users.
    #[cfg(windows)]
    pub fn harden_for_service(&self) -> anyhow::Result<()> {
        acl::restrict_dir(&self.dir)?;
        let t = self.dir.join("agent.token");
        if t.exists() {
            acl::token_file(&t)?;
        }
        Ok(())
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
        // The desktop UI (another user) reads this file, so no DPAPI here; access is by permissions:
        // Linux 0640 group "beyondvpn" (created by the agent itself, no startup race), else 0600.
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, t.as_bytes())?;
        match token_group() {
            Some(gid) => {
                restrict(&tmp, 0o640);
                set_group(&tmp, gid)?;
            }
            None => restrict(&tmp, 0o600),
        }
        std::fs::rename(&tmp, &p)?;
        #[cfg(windows)]
        if self.dir.starts_with(service_dir()) {
            acl::token_file(&p)?;
        }
        Ok(t)
    }
}

/// Machine-wide state directory used by the Windows service.
#[cfg(windows)]
pub fn service_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("BeyondVPN")
}

/// Plain file, owner-only permissions (used for the short-lived tunnel config).
pub fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    restrict(&tmp, 0o600);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Marker for files encrypted with DPAPI (Windows).
pub const SECRET_MAGIC: &[u8] = b"BVPN-DPAPI1\n";

/// Secret at rest: DPAPI-encrypted for the current account on Windows, 0600 elsewhere.
pub fn write_secret(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    #[cfg(windows)]
    let protected = {
        let mut blob = SECRET_MAGIC.to_vec();
        blob.extend_from_slice(&dpapi::protect(data)?);
        blob
    };
    #[cfg(windows)]
    let data = &protected[..];
    write_private(path, data)
}

/// Read a secret written by `write_secret` (or an older plaintext file).
pub fn read_secret(path: &Path) -> Option<Vec<u8>> {
    let raw = std::fs::read(path).ok()?;
    match raw.strip_prefix(SECRET_MAGIC) {
        #[cfg(windows)]
        Some(blob) => dpapi::unprotect(blob).ok(),
        #[cfg(not(windows))]
        Some(_) => None,
        None => Some(raw),
    }
}

/// gid of the "beyondvpn" group from /etc/group text.
pub fn group_gid(etc_group: &str, name: &str) -> Option<u32> {
    etc_group.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.first() == Some(&name)).then(|| f.get(2)?.parse().ok()).flatten()
    })
}

fn token_group() -> Option<u32> {
    if cfg!(unix) {
        group_gid(&std::fs::read_to_string("/etc/group").ok()?, "beyondvpn")
    } else {
        None
    }
}

#[cfg(unix)]
fn set_group(p: &Path, gid: u32) -> anyhow::Result<()> {
    std::os::unix::fs::chown(p, None, Some(gid))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_group(_p: &Path, _gid: u32) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_p: &Path, _mode: u32) {
    // Windows: per-user state lives in %APPDATA% (ACL'd to the user); the service's state is
    // locked down by `harden_for_service` and secrets are DPAPI-encrypted.
}

/// DPAPI (CryptProtectData) for the current account: only the same account on the same
/// machine can decrypt (the service runs as LocalSystem, so only SYSTEM can).
#[cfg(windows)]
pub mod dpapi {
    use std::ffi::c_void;

    #[repr(C)]
    struct Blob {
        len: u32,
        data: *mut u8,
    }
    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(input: *const Blob, desc: *const u16, entropy: *const Blob, reserved: *mut c_void, prompt: *mut c_void, flags: u32, out: *mut Blob) -> i32;
        fn CryptUnprotectData(input: *const Blob, desc: *mut *mut u16, entropy: *const Blob, reserved: *mut c_void, prompt: *mut c_void, flags: u32, out: *mut Blob) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(p: *mut c_void) -> *mut c_void;
    }
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    const ENTROPY: &[u8] = b"beyond-agent secret v1";

    fn call(data: &[u8], protect: bool) -> anyhow::Result<Vec<u8>> {
        let input = Blob { len: data.len() as u32, data: data.as_ptr() as *mut u8 };
        let entropy = Blob { len: ENTROPY.len() as u32, data: ENTROPY.as_ptr() as *mut u8 };
        let mut out = Blob { len: 0, data: std::ptr::null_mut() };
        // SAFETY: all blobs point at live buffers for the call; the output is freed with LocalFree.
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, std::ptr::null(), &entropy, std::ptr::null_mut(), std::ptr::null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), &entropy, std::ptr::null_mut(), std::ptr::null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            }
        };
        anyhow::ensure!(ok != 0, "DPAPI {}: {}", if protect { "protect" } else { "unprotect" }, std::io::Error::last_os_error());
        // SAFETY: on success `out` describes a LocalAlloc'd buffer of `len` bytes.
        let v = unsafe { std::slice::from_raw_parts(out.data, out.len as usize).to_vec() };
        unsafe {
            LocalFree(out.data as *mut c_void);
        }
        Ok(v)
    }

    pub fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        call(data, true)
    }

    pub fn unprotect(blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        call(blob, false)
    }
}

/// Windows ACLs via the built-in icacls (well-known SIDs, so it works on any display language).
#[cfg(windows)]
mod acl {
    use std::path::Path;
    use std::process::Command;

    fn icacls(args: &[&str]) -> anyhow::Result<()> {
        let exe = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join("System32").join("icacls.exe");
        let out = Command::new(exe).args(args).output()?;
        anyhow::ensure!(out.status.success(), "icacls {:?}: {}", args, String::from_utf8_lossy(&out.stdout).trim());
        Ok(())
    }

    const SYSTEM: &str = "*S-1-5-18";
    const ADMINS: &str = "*S-1-5-32-544";
    const INTERACTIVE: &str = "*S-1-5-4";

    pub fn restrict_dir(dir: &Path) -> anyhow::Result<()> {
        let d = dir.to_string_lossy();
        icacls(&[&d, "/inheritance:r", "/grant:r", &format!("{SYSTEM}:(OI)(CI)F"), &format!("{ADMINS}:(OI)(CI)F")])?;
        // Drop any explicit grants added by older installers (e.g. Users:R on everything).
        let _ = icacls(&[&d, "/remove:g", "*S-1-5-32-545", "/T"]);
        Ok(())
    }

    pub fn token_file(file: &Path) -> anyhow::Result<()> {
        let f = file.to_string_lossy();
        icacls(&[&f, "/inheritance:r", "/grant:r", &format!("{SYSTEM}:F"), &format!("{ADMINS}:F"), &format!("{INTERACTIVE}:R")])
    }
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
        assert!(st.settings.kill_switch, "kill switch must default to ON");
        let parsed: AgentState = serde_json::from_str(r#"{"settings":{}}"#).unwrap();
        assert!(parsed.settings.kill_switch);
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

    #[test]
    fn secrets_are_not_plaintext_on_windows_and_old_files_still_load() {
        let s = Store::open(tmpdir("secret")).unwrap();
        let (k, _) = s.ensure_keypair().unwrap();
        let on_disk = std::fs::read(s.dir.join("device.key")).unwrap();
        if cfg!(windows) {
            assert!(on_disk.starts_with(SECRET_MAGIC));
            assert!(!String::from_utf8_lossy(&on_disk).contains(&k), "private key must not be stored in clear");
        }
        // A plaintext key from an older version is read, then upgraded.
        let kp = beyond_common::keys::generate_keypair();
        std::fs::write(s.dir.join("device.key"), &kp.private_key).unwrap();
        assert_eq!(s.private_key().as_deref(), Some(kp.private_key.as_str()));
        if cfg!(windows) {
            assert!(std::fs::read(s.dir.join("device.key")).unwrap().starts_with(SECRET_MAGIC));
            assert_eq!(s.private_key().as_deref(), Some(kp.private_key.as_str()));
        }
    }

    #[test]
    fn group_lookup() {
        let g = "root:x:0:\nbeyondvpn:x:997:alice,bob\nusers:x:100:\n";
        assert_eq!(group_gid(g, "beyondvpn"), Some(997));
        assert_eq!(group_gid(g, "nope"), None);
    }

    #[cfg(unix)]
    #[test]
    fn unix_secret_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let s = Store::open(tmpdir("perm")).unwrap();
        s.ensure_keypair().unwrap();
        let mode = std::fs::metadata(s.dir.join("device.key")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
