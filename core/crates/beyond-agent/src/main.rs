//! beyond-agent — Beyond VPN desktop client (CLI + local daemon).
//!
//! Examples:
//!   beyond-agent login --api https://vpn.example.com --email me@example.com
//!   beyond-agent servers
//!   beyond-agent connect            # fastest server
//!   beyond-agent connect --server de-fra-1
//!   beyond-agent status
//!   beyond-agent serve              # local API for the desktop UI (run as service/admin)

mod api;
mod engine;
mod server;
mod store;
mod tunnel;

use clap::{Parser, Subcommand};
use std::io::{BufRead, Write};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "beyond-agent", version, about = "Beyond VPN desktop agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Log in and register this device (password read from stdin / BEYOND_PASSWORD).
    Login {
        #[arg(long, env = "BEYOND_API")]
        api: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        totp: Option<String>,
    },
    Logout,
    /// List VPN servers.
    Servers,
    /// Connect (fastest server unless --server given).
    Connect {
        #[arg(long)]
        server: Option<String>,
    },
    Disconnect,
    Status,
    /// Show this account's data usage (from the control plane).
    Usage,
    /// Update settings.
    Set {
        #[arg(long)]
        kill_switch: Option<bool>,
        #[arg(long)]
        allow_lan: Option<bool>,
        #[arg(long)]
        auto_connect: Option<bool>,
        /// Comma separated IPv4 CIDRs to bypass the tunnel ("" clears).
        #[arg(long)]
        exclude: Option<String>,
        /// Anti-blocking mode: carry WireGuard over TLS/443.
        #[arg(long)]
        stealth: Option<bool>,
        /// Multi-hop exit server id or name ("" turns multi-hop off).
        #[arg(long)]
        exit_server: Option<String>,
    },
    /// Run the local control API for the desktop UI.
    Serve {
        #[arg(long, default_value_t = 47800)]
        port: u16,
    },
}

fn read_password() -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("BEYOND_PASSWORD") {
        return Ok(p);
    }
    eprint!("Password: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn human(b: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let store = store::Store::open(store::Store::default_dir())?;
    let backend = tunnel::platform_backend(&store.dir);
    let engine = Arc::new(engine::Engine::new(store, backend));
    match Cli::parse().cmd {
        Cmd::Login { api, email, totp } => {
            let pw = read_password()?;
            engine.login(&api, &email, &pw, totp.as_deref()).await?;
            println!("Logged in as {email}; device registered.");
        }
        Cmd::Logout => {
            engine.logout().await?;
            println!("Logged out.");
        }
        Cmd::Servers => {
            for s in engine.servers().await? {
                println!("{:<14} {:<22} {:<3} {:<12} load {:>3.0}%  {}  [{}]", s.id, s.name, s.country, s.city, s.load * 100.0, s.status, s.features.join(","));
            }
        }
        Cmd::Connect { server } => {
            let name = engine.connect(server).await?;
            println!("Connected to {name}.");
            if engine.relay_active() {
                // The stealth relay lives in this process; the daemon (`serve`) keeps it for the desktop app.
                println!("Stealth relay running. Press Ctrl+C to disconnect.");
                tokio::signal::ctrl_c().await?;
                engine.disconnect().await?;
                println!("Disconnected.");
            }
        }
        Cmd::Disconnect => {
            engine.disconnect().await?;
            println!("Disconnected.");
        }
        Cmd::Status => {
            let s = engine.status();
            println!("logged in : {} {}", s.logged_in, s.email.unwrap_or_default());
            println!("connected : {} {}", s.connected, s.server.unwrap_or_default());
            println!("traffic   : rx {}  tx {}", human(s.rx_bytes), human(s.tx_bytes));
            println!("backend   : {}", s.backend);
            println!("settings  : {}", serde_json::to_string(&s.settings)?);
        }
        Cmd::Usage => {
            println!("{}", serde_json::to_string_pretty(&engine.usage().await?)?);
        }
        Cmd::Set { kill_switch, allow_lan, auto_connect, exclude, stealth, exit_server } => {
            let mut s = engine.status().settings;
            if let Some(v) = stealth {
                s.stealth = v;
            }
            if let Some(v) = exit_server {
                s.exit_server = Some(v.trim().to_string()).filter(|x| !x.is_empty());
            }
            if let Some(v) = kill_switch {
                s.kill_switch = v;
            }
            if let Some(v) = allow_lan {
                s.allow_lan = v;
            }
            if let Some(v) = auto_connect {
                s.auto_connect = v;
            }
            if let Some(e) = exclude {
                s.exclude_routes = e.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
            }
            println!("{}", serde_json::to_string_pretty(&engine.update_settings(s)?)?);
        }
        Cmd::Serve { port } => server::serve(engine, port).await?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn human_units() {
        assert_eq!(super::human(512), "512.0 B");
        assert_eq!(super::human(1536), "1.5 KiB");
        assert_eq!(super::human(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
