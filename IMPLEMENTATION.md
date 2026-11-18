# Beyond VPN — Implementation

Technical reference for each component. Architecture diagrams and flows: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 1. Rust core (`core/`)

### 1.1 `beyond-common` (pure library, no I/O)

| Module | Responsibility | Notable safeguards |
|---|---|---|
| `keys` | Curve25519 keypairs, PSK generation, `public_from_private`, validation | OS CSPRNG; `Debug` redacts private keys; RFC 7748 test vector |
| `token` | Verify/sign EdDSA JWTs (`typ`, `aud`, `exp`, `nbf`, leeway) | Rejects `alg` ≠ `EdDSA` (no `none`/HS256 confusion); tamper tests |
| `cidr` | IPv4 CIDR parse/format, subtraction (`0.0.0.0/0 \ excludes`) | Used for split tunnelling / "allow LAN" |
| `wgconf` | Render wg-quick / WireGuard-for-Windows config; apply split-tunnel; Linux nftables kill switch | Field whitelist prevents config injection (`\n PostUp = …`) |
| `dns` | Parse query question, build sinkhole response (A→0.0.0.0, AAAA→::, else NXDOMAIN) | Rejects compression pointers / non-hostname bytes; length limits |
| `blocklist` | Suffix-match blocklist with allow-list; hosts / plain / adblock `||d^` formats | Label-boundary matching (`badads.x` ≠ `ads.x`) |
| `telemetry` | Wire types gateway ↔ control plane | Mirrors pydantic schemas |
| `wgdump` | Parse `wg show dump`; delta tracker handling counter resets | — |

### 1.2 `beyond-gateway` (binary, runs on each VPN node)

Tasks (tokio):
1. **Sync loop** (default 10 s): `GET /api/v1/gateway/peers` → update peer map, signing key, revoked users, policy blocklist, logging mode → reconcile kernel peers (`wg set … peer … allowed-ips ip/32 preshared-key /dev/stdin`, remove stale) → `POST heartbeat` (public key, port, peers, load, version).
2. **Usage loop** (30 s): `wg show wg0 dump` → per-peer deltas → `POST usage`.
3. **Log flush** (15 s): DNS + proxy log buffers → `POST dns-logs` / `proxy-logs`; re-queued on failure; buffers bounded at 50 000 entries.
4. **DNS resolver** on `10.8.0.1:53`: block → sinkhole; else forward via **DoH** (default) or UDP; logs `{client_ip, user, device, domain, qtype, blocked}`.
5. **HTTPS forward proxy** on `:8443` (rustls, TLS1.2/1.3): `CONNECT` and absolute-form HTTP; `Proxy-Authorization: Basic beyond:<token>` or `Bearer`; token must be `typ=proxy`, `aud=<gateway id>`, unexpired, user not revoked; port allow-list; blocklist; **SSRF guard** (no loopback/RFC1918/link-local/CGNAT/ULA/mapped addresses); logs bytes up/down + duration.

Config: TOML (`deploy/gateway/gateway.toml.example`); secret via `BEYOND_GATEWAY_KEY` env. `dry_run = true` skips `wg` calls (tests/CI).

### 1.3 `beyond-agent` (desktop client: CLI + daemon)

- `store`: state in `%APPDATA%\BeyondVPN` / `~/.config/BeyondVPN` / `~/Library/Application Support/BeyondVPN` (override `BEYOND_AGENT_DIR`); WireGuard private key in its own file (0600 on Unix); random 256-bit local API token.
- `api`: control-plane client (https enforced except loopback), automatic access-token refresh.
- `engine`: login → ensure device key → register device (posture: OS, arch, version) → connect (fastest server = TCP RTT × (1 + 2·load), probed concurrently) → render config with settings (kill switch, allow LAN, excluded routes; policy can force kill switch / forbid split tunnel) → bring tunnel up → report disconnect.
- `tunnel`: `WindowsBackend` (`wireguard.exe /installtunnelservice`, WFP kill switch from WireGuard-NT, config file deleted after import), `WgQuickBackend` (Linux/macOS, nftables kill switch via PostUp/PreDown), `DryRunBackend`.
- `server`: axum on `127.0.0.1:47800`; bearer token compared via SHA-256 digests; rejects any request with an `Origin` header (websites) and any `Host` other than `127.0.0.1:port`/`localhost:port` (DNS rebinding).
- CLI: `login`, `logout`, `servers`, `connect [--server]`, `disconnect`, `status`, `usage`, `set --kill-switch/--allow-lan/--auto-connect/--exclude`, `serve`.

## 2. Control plane (`control-plane/beyond_cp`)

| Module | Content |
|---|---|
| `config.py` | Env-driven settings (`BEYOND_*`), defaults safe for dev |
| `db.py`, `models.py` | SQLAlchemy 2: `users, devices, servers, peers, vpn_sessions, usage_daily, dns_logs, proxy_logs, audit_events, refresh_tokens, settings` |
| `security.py` | Argon2id, password policy, Ed25519 signing key (file/env), Fernet field encryption (PSKs, MFA secrets), JWT issue/verify, TOTP, sliding-window rate limiter |
| `audit.py` | Hash-chained audit log (`hash = sha256(prev_hash ‖ canonical_json)`), `verify_chain` |
| `policy.py` | Org policy: logging mode, blocked domains, kill-switch-required, split-tunnel-allowed, posture required, allowed platforms, max devices |
| `ipam.py` | Lowest-free tunnel IP per gateway (`.1` reserved for gateway resolver) |
| `routers/auth.py` | register (consent), login (lockout, generic errors, timing-equalised), refresh (rotation + reuse detection → family revoked), logout, MFA setup/enable/disable |
| `routers/vpn.py` | devices CRUD (WireGuard key validation, per-user limit, platform policy), servers list with live status, `sessions/connect` (posture, data cap, IPAM, PSK), disconnect, browser `proxy/token` |
| `routers/gateway.py` | gateway-authenticated `peers`, `heartbeat`, `usage`, `dns-logs` (attributed by tunnel IP server-side, never trusting gateway-supplied user ids), `proxy-logs` |
| `routers/me.py` | profile, consent, usage (daily + month + cap), sessions, **own activity**, account erase |
| `routers/admin.py` | users (role, disable → immediate revoke, data cap), gateways (create → one-time key, rotate key, maintenance), policy, sessions, DNS/web logs (every view audited), CSV export (formula-injection safe), reports (summary, top domains, usage), audit list + verify |
| `main.py` | App factory, security headers, body-size limit, CORS (no credentials), bootstrap admin, retention purge thread |
| `cli.py` | `create-admin`, `create-server`, `purge-logs`, `verify-audit` |

### 2.1 REST API summary (`/api/v1`)

| Area | Endpoints |
|---|---|
| Auth | `POST auth/register`, `auth/login`, `auth/refresh`, `auth/logout`, `auth/mfa/setup`, `auth/mfa/enable`, `auth/mfa/disable` |
| User | `GET me`, `POST me/consent`, `GET me/usage`, `GET me/sessions`, `GET me/activity`, `POST me/erase` |
| VPN | `GET/POST devices`, `DELETE devices/{id}`, `GET servers`, `POST sessions/connect`, `POST sessions/{id}/disconnect`, `POST proxy/token`, `POST proxy/disconnect` |
| Gateway | `GET gateway/peers`, `POST gateway/heartbeat`, `gateway/usage`, `gateway/dns-logs`, `gateway/proxy-logs` (headers `X-Gateway-Id`, `X-Gateway-Key`) |
| Admin | `GET admin/users`, `PATCH admin/users/{id}`, `GET admin/users/{id}/devices`, `GET/POST admin/servers`, `PATCH admin/servers/{id}`, `POST admin/servers/{id}/rotate-key`, `GET/PUT admin/policy`, `GET admin/sessions`, `GET admin/logs/dns`, `GET admin/logs/web`, `GET admin/logs/export.csv`, `GET admin/reports/summary`, `.../top-domains`, `.../usage`, `GET admin/audit`, `GET admin/audit/verify` |
| Ops | `GET /healthz`, `GET /api/v1/keys/signing`, OpenAPI at `/docs` |

Roles: `user`, `auditor` (read-only admin), `admin`.

## 3. Clients

| Client | Key implementation points |
|---|---|
| **Web portal** (`clients/web`) | React 18 + TS strict + Vite. Access token in memory, refresh token in `sessionStorage`. Devices page generates X25519 keys **in the browser** (tweetnacl), registers public key, renders config + QR for the WireGuard app (iOS/macOS/routers). Admin console: overview, users, gateways, policy, logs (+CSV), audit verify. CSP meta tag. |
| **Extension** (`clients/extension`) | MV3 service worker. `chrome.proxy` `fixed_servers` HTTPS proxy (no DIRECT fallback → fails closed), `webRequest.onAuthRequired` answers the 407 with the short-lived token (max 2 attempts per request), alarms refresh the token 5 min before expiry, `privacy.network.webRTCIPHandlingPolicy = disable_non_proxied_udp`, bypass list (LAN, control plane, user domains). Firefox: `proxy.onRequest` with `proxyAuthorizationHeader`. Messages accepted only from own extension id. |
| **Desktop** (`clients/desktop`) | Electron: `contextIsolation`, `sandbox`, no `nodeIntegration`, CSP, navigation blocked; preload exposes 7 whitelisted calls; main process reads the agent token and calls the loopback API (route whitelist, settings sanitised). Tray with quick connect. |
| **Android** (`clients/android`) | Kotlin, `com.wireguard.android:tunnel` (GoBackend). Keys + tokens in `EncryptedSharedPreferences` (Keystore-backed), backups disabled, `FLAG_SECURE`, cleartext only to emulator loopback. Per-app split tunnelling (`ExcludedApplications`), allow-LAN, Quick Settings tile, deep link to Always-on/"Block connections without VPN" (system kill switch). Posture: OS version, root heuristics. |

## 4. Data model highlights

- `peers (device_id, server_id)` unique and `(server_id, tunnel_ip)` unique → IPAM correctness enforced by DB.
- `usage_daily (user_id, day)` → cheap monthly cap checks and reports.
- `dns_logs` / `proxy_logs` indexed by `(user_id, ts)`; purged after `BEYOND_LOG_RETENTION_DAYS` (default 30).
- Gateway rx = user upload, gateway tx = user download (swapped when stored).

## 5. Configuration reference (control plane)

| Variable | Default | Meaning |
|---|---|---|
| `BEYOND_DATABASE_URL` | SQLite in data dir | `postgresql+psycopg://…` in production |
| `BEYOND_DATA_DIR` | `./data` | Keys + SQLite |
| `BEYOND_SIGNING_KEY` / `BEYOND_DATA_KEY` | generated files | Set from a secret manager in production |
| `BEYOND_ACCESS_TTL` / `REFRESH_TTL` / `PROXY_TTL` | 900 s / 7 d / 1800 s | Token lifetimes |
| `BEYOND_LOG_RETENTION_DAYS` | 30 | Activity log retention |
| `BEYOND_ALLOW_REGISTRATION` | true | Self sign-up |
| `BEYOND_REQUIRE_LOGGING_CONSENT` | true | Consent checkbox mandatory |
| `BEYOND_MAX_FAILED_LOGINS` / `LOCKOUT_SECONDS` | 5 / 900 | Brute-force protection |
| `BEYOND_AUTH_RATE_PER_MINUTE` | 30 | Per-IP auth rate limit |
| `BEYOND_CORS_ORIGINS` | `http://localhost:5173` | Portal origins |
| `BEYOND_TRUST_PROXY_HEADERS` | false | Use `X-Forwarded-For` (only behind Caddy) |
| `BEYOND_ADMIN_EMAIL` / `PASSWORD` | — | One-time bootstrap admin |
