//! Beyond VPN shared primitives.
//!
//! Everything in this crate is pure (no I/O, no async) so it can be unit
//! tested exhaustively and reused by the gateway, the desktop agent and,
//! later, mobile bindings via UniFFI.

pub mod blocklist;
pub mod cidr;
pub mod dns;
pub mod keys;
pub mod telemetry;
pub mod token;
pub mod wgconf;
pub mod wgdump;

/// Seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
