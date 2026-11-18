# Beyond VPN — Things Remaining

Prioritised backlog. **P0** = required before any real users; **P1** = before public/enterprise launch; **P2** = roadmap.

## P0 — before the pilot

| # | Item | Why | Effort |
|---|---|---|---|
| 1 | Run a real deployment: control plane via `deploy/docker-compose.yml`, 2 gateways via `install-gateway.sh`, real tunnels from Windows, macOS, Linux, Android, iOS (WireGuard app) and the extension | Only dry-run/e2e verified so far; kernel WireGuard, nftables and Caddy paths are untested on real hosts | 2–3 d |
| 2 | Windows service wrapper for `beyond-agent` (Windows SCM API via `windows-service` crate, or WinSW) | `sc.exe create` on a console binary will not report status to SCM correctly | 1 d |
| 3 | Desktop installer bundling: WireGuard dependency check/installer, agent service, Electron app (`electron-builder`), code signing | Users currently install pieces manually | 3 d |
| 4 | Linux agent token permissions: `beyond-agent serve` should create the token with group ownership itself instead of `ExecStartPost` chmod | Race at first start | 0.5 d |
| 5 | Windows: protect agent state with DPAPI / ProgramData ACLs; restrict `agent.token` to the interactive users group | Any local user can read the token in the current install script | 1 d |
| 6 | Alembic migrations for the control-plane schema | `create_all` cannot evolve existing tables | 1 d |
| 7 | Redis-backed rate limiter and lockout counters | In-process limiter is per replica | 0.5 d |
| 8 | External penetration test of control plane, gateway proxy and clients | Independent assurance | vendor |

## P1 — before public / enterprise launch

| # | Item |
|---|---|
| 9 | SSO: OIDC (Azure AD, Google Workspace, Okta) and SAML 2.0 for enterprise tenants (Forti EMS parity) |
| 10 | Native macOS app (NetworkExtension + WireGuardKit) and native iOS app (currently: official WireGuard app + portal QR) |
| 11 | Stealth/obfuscated transport for censored networks (WireGuard over TCP/TLS 443, e.g. `udp2raw`/`wstunnel`, or AmneziaWG) — Proton "Stealth" parity |
| 12 | Secure Core / multi-hop (entry gateway → exit gateway chaining) |
| 13 | IPv6 inside the tunnel (ULA per gateway) — currently IPv4 tunnel addresses only (IPv6 is routed into the tunnel and dropped, preventing leaks) |
| 14 | Auto-connect on untrusted Wi-Fi (SSID trust list) on desktop and Android |
| 15 | Domain-based split tunnelling on desktop (resolve-and-route) — routes/apps exist, domains only in the extension |
| 16 | Posture: verify disk encryption, OS patch level, AV status on Windows/macOS (Forti ZTNA parity); signed posture attestation (Play Integrity / Windows Health Attestation) |
| 17 | Admin: per-group policies (currently org-wide), SIEM export (syslog/CEF, Splunk HEC), alerting webhooks |
| 18 | Gateway metrics endpoint (Prometheus) + Grafana dashboards; control-plane OpenTelemetry tracing |
| 19 | HA control plane: ≥2 replicas, managed PostgreSQL with PITR, key material in KMS/HSM |
| 20 | Per-user bandwidth shaping on gateways (tc/eBPF) |
| 21 | Browser extension store packaging, icons, i18n; Chrome Web Store / AMO / Edge submissions |
| 22 | Android: release signing, Play Store listing (VpnService declaration form), notification for foreground state, Android TV build |
| 23 | Accessibility review (WCAG 2.2 AA) of portal, desktop and Android UI |
| 24 | Load test: 5 000 peers per gateway, 200 k users on control plane (Locust/k6) |

## P2 — roadmap

- Billing/subscriptions (Stripe/Razorpay), free vs plus tiers using `servers.tier`.
- Port forwarding, dedicated IPs, P2P-optimised servers.
- Threat protection: malware URL feeds auto-updated on gateways, per-user custom blocklists.
- Tor-over-VPN servers.
- Router firmware guides (OpenWrt, pfSense) — WireGuard configs already work there.
- Merge the useful UI ideas from `legacy/forticlone/frontend/web` (country status charts) into the portal.

## Known limitations of v0.2 (be honest with users)

1. Activity logs for WireGuard clients come from **DNS** only. Apps that use their own encrypted DNS (DoH inside the app, e.g. browsers with "secure DNS" on) bypass the gateway resolver for name lookups; the traffic is still tunnelled and metered, but the domain is not logged. Mitigation: block known DoH endpoints in the blocklist (P1).
2. The browser extension protects browser traffic only, not other apps.
3. Byte counters are accurate to the WireGuard reporting interval (30 s); usage of a session that ends within 30 s of a gateway restart can be under-counted.
4. Kill switch on Windows comes from WireGuard-NT and only applies to full-tunnel configs; enabling "allow LAN"/excluded routes disables WireGuard-NT's automatic block rules.
5. Android system-level kill switch must be enabled by the user in system settings (Android does not allow apps to set it).
