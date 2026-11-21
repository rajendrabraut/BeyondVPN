# Beyond VPN — Things Remaining

Prioritised backlog. **P0** = required before any real users; **P1** = before public/enterprise launch; **P2** = roadmap.

## P0 — before the pilot

| # | Item | Why | Effort |
|---|---|---|---|
| 1 | Run a real deployment by following `docs/DEPLOY_RUNBOOK.md`: control plane via `deploy/docker-compose.yml`, 2 gateways via `install-gateway.sh`, real tunnels from Windows, macOS, Linux, Android, iOS and the extension, plus multi-hop and stealth checks | Needs Linux servers (none available yet). Verified so far (2026-11-20): CI green on GitHub; WireGuard-NT tunnels on Windows hand-shake over loopback; Android APK runs on an API 36 emulator; Electron app signs in and connects against the local demo stack (`tests/e2e/demo_stack.py`, dry-run tunnel). Kernel WireGuard, nftables, multi-hop routing, stealth over the internet and Caddy are untested on real hosts | 1 d |
| ~~2~~ | **Done in 0.0.0.1**: native Windows service (`beyond-agent service install/uninstall`, SCM status, restart on failure) | verified on Windows 11: Running/auto-start/LocalSystem, restart actions, API 200 with token / 401 without | — |
| 3 | Desktop installer bundling: WireGuard dependency check/installer, agent service, Electron app (`electron-builder`), **code signing certificate** | Users currently install pieces manually; unsigned binaries trigger SmartScreen | 3 d + certificate |
| ~~4~~ | **Done in 0.0.0.1**: agent writes `agent.token` itself as 0640 root:beyondvpn (no `ExecStartPost` race); state dir 0750 with the group | — | — |
| ~~5~~ | **Done in 0.0.0.1**: service state in `%ProgramData%\BeyondVPN` (SYSTEM + Administrators only; token also readable by INTERACTIVE); device key and refresh tokens DPAPI-encrypted | verified with icacls on Windows 11 | — |
| ~~6~~ | **Done in 0.0.0.1**: Alembic migrations (`0001_initial`, forward-only), run at start and by `beyond-cp migrate`; older `create_all` databases are stamped, not re-created | tests: models == migrations, idempotent, legacy stamp keeps data | — |
| ~~7~~ | **Done in 0.0.0.1**: `BEYOND_REDIS_URL` → rate limits shared through Redis (fixed window, atomic pipeline), per-replica fallback if Redis is down; lockout counters were already in the database | tests with a shared fake Redis | — |
| 8 | External penetration test of control plane, gateway proxy and clients | Independent assurance | vendor |
| 9b | Android release signing key (Play Store) — release APK in 0.0.0.1 is debug-signed | Needs a keystore kept outside the repo | 0.5 d |

## P1 — before public / enterprise launch

| # | Item |
|---|---|
| 9 | SSO: **OIDC done** (control plane + portal, docs/SSO.md, tested against a fake IdP). Left: real-IdP trial (Entra ID / Google / Okta), native SAML 2.0, SSO sign-in in desktop/Android/iOS apps (`beyondvpn://sso` redirect is already allowed), SCIM provisioning |
| 10 | iOS: **SwiftUI + NetworkExtension source written** (`clients/ios`), not yet compiled (needs a Mac + Xcode + Apple team). Left: first build, TestFlight, stealth + SSO in the app. Native macOS app still open |
| 11 | Stealth: **done** for desktop (`beyond-stealth` crate: WireGuard in TLS/443, nginx-like 404 to probes; gateway `[stealth]`, agent `set --stealth`). Left: Android/iOS (embed the relay via UniFFI), real-network trial behind a UDP-blocking firewall, optional domain fronting / AmneziaWG |
| 12 | Multi-hop: **done** in control plane, gateway (`bhop<N>` uplinks + policy routing) and desktop agent/app (`set --exit-server`). Left: verify on real Linux gateways (runbook §4), exit picker in Android, portal QR configs with an exit |
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
6. Stealth mode on Windows excludes the gateway's IP from AllowedIPs (so the TLS relay does not loop into the tunnel); that also turns off WireGuard-NT's built-in kill switch while stealth is on.
7. New schema columns (servers.stealth_port, servers.hop_public_key, peers.exit_server_id, hop_links, user_identities, sso_logins) are created only on a fresh database until Alembic migrations exist (P0 #6).
