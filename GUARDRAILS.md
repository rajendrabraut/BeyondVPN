# Beyond VPN — Guardrails

Rules that the code enforces and rules that operators must follow. Changes to anything in this file need security review.

## 1. Cryptography guardrails

1. **Never invent cryptography.** Tunnels use WireGuard only. Tokens use EdDSA (Ed25519). Passwords use Argon2id. Field encryption uses Fernet (AES-128-CBC + HMAC-SHA256). Randomness comes from the OS CSPRNG.
2. **Private keys stay on the device.** Desktop: agent state dir. Android: Keystore-backed encrypted prefs. Web: generated in the tab and shown once. The control plane stores public keys only.
3. **PresharedKey per peer** adds a symmetric layer (post-quantum hedge); stored encrypted at rest.
4. **Token rules:** access 15 min; refresh 7 days, single use, rotation with reuse detection; proxy tokens 30 min, audience-bound to one gateway; algorithm pinned to EdDSA on both sides.
5. Signing key and data key must come from a secret manager in production (`BEYOND_SIGNING_KEY`, `BEYOND_DATA_KEY`). Losing the data key makes stored PSKs and MFA secrets unreadable — back it up offline.

## 2. Application security guardrails (enforced in code)

| Threat | Control | Where |
|---|---|---|
| Credential stuffing / brute force | Per-IP rate limit, account lockout, generic errors, timing-equalised unknown-user path | `routers/auth.py`, `security.py` |
| Token forgery / alg confusion | EdDSA only, `typ` + `aud` checks, tamper tests | `security.py`, `beyond-common/token.rs` |
| Stolen refresh token | Rotation; reuse revokes the whole family | `routers/auth.py` |
| Disabled user keeps access | Disable → refresh tokens revoked, peers deactivated, sessions closed; gateway rejects proxy tokens via `revoked_subjects` within one sync | `routers/admin.py`, `gateway/proxy.rs` |
| Rogue / compromised gateway | Per-gateway secret (hashed), cannot mint tokens, cannot attribute logs to arbitrary users (server maps tunnel IP → user), clock skew capped | `routers/gateway.py` |
| Config injection into wg files | Strict character whitelist on every rendered field (Rust, TS, Kotlin) | `wgconf.rs`, `lib.ts`, `TunnelConfigBuilder.kt` |
| SSRF through browser proxy | Destination IPs resolved and rejected if private/loopback/link-local/CGNAT/ULA/mapped; port allow-list | `gateway/proxy.rs` |
| Local privilege abuse on desktop | Loopback-only API, 256-bit token, Origin header rejected, Host allow-list, route whitelist in UI | `agent/server.rs`, `desktop/src/agentClient.js` |
| Malicious web content in Electron | `contextIsolation`, `sandbox`, no Node, CSP, navigation blocked | `desktop/src/main.js` |
| CSV/Excel formula injection | Cells beginning with `= + - @` prefixed with `'` | `routers/admin.py` |
| Oversized payloads / memory exhaustion | 16 MiB request cap, bounded log buffers on gateways, pydantic max lengths | `main.py`, `gateway/state.rs`, `schemas.py` |
| Tampering with audit trail | Hash chain + verify endpoint/CLI | `audit.py` |
| Insecure transport | HTTPS enforced in agent, extension, Android (network security config), gateway → control plane; HSTS | multiple |
| Leaks outside the tunnel | Kill switch default **ON** (desktop), WFP (Windows), nftables (Linux), Android Always-on deep link, extension fails closed, WebRTC policy, DNS forced to gateway resolver | agent, extension, Android |

## 3. Activity logging — privacy and legal guardrails

Recording "where users are visiting" is personal data. The platform supports it, but **the operator is responsible for lawful use**.

1. **Consent and notice.** Registration requires `accept_logging_policy` (configurable but on by default). Enterprise deployments must also have a written acceptable-use policy that employees acknowledge.
2. **Transparency.** Every user can see exactly what was logged about them (`/me/activity`, portal "Activity" page).
3. **Least data.** Only domain/host, port, byte counts, timestamps and device are logged. No URLs paths, no page content, **no TLS interception** — never deploy MITM certificates.
4. **Logging modes.** `full` (domains), `metadata` (bytes only), `off` (usage metering only). Consumer/privacy-focused offerings should run `metadata` or `off` and must not advertise "no-logs" otherwise.
5. **Retention.** Default 30 days, automatic purge every 6 h; choose the shortest period that meets legal obligations. Note India CERT-In Direction (28 Apr 2022) requires VPN providers serving Indian users to retain certain subscriber records for 5 years — consult counsel; that applies to subscriber/KYC data, not necessarily browsing logs.
6. **Access control and accountability.** Only `admin`/`auditor` roles can read logs; **every view and export is itself audited**.
7. **Erasure.** `/me/erase` deletes the user's logs, usage, devices and account (GDPR Art. 17, India DPDP Act 2023 s.12). Admins handle requests from data principals within statutory deadlines.
8. **Cross-border.** Gateways in other countries upload logs to the control plane — document the transfer basis (SCCs etc.) for EU users.
9. **Lawful requests.** Disclose logs only on valid legal process, recorded in the audit trail; publish a transparency report if offering a public service.

## 4. Operational guardrails

1. Gateways: unattended security updates on, SSH key-only, firewall allows only UDP 51820, TCP 8443, TCP 80 (certbot). Client-to-client traffic and access to the gateway's private networks are dropped by nftables.
2. Rotate a gateway key immediately if a node is suspected compromised (`POST /admin/servers/{id}/rotate-key`); re-image the node.
3. Remove `BEYOND_ADMIN_PASSWORD` from the environment after first start; require MFA for every admin account.
4. Run the control plane only behind TLS (Caddy config provided); set `BEYOND_TRUST_PROXY_HEADERS=true` only when behind that proxy.
5. Back up PostgreSQL daily and the data/signing keys separately; test restore quarterly.
6. Run `python -m beyond_cp.cli verify-audit` from cron and alert on failure.
7. Never enable `allow_private_destinations` on a production gateway.
8. Release builds: sign Windows binaries (Authenticode), notarise macOS, sign Android with a release key kept offline.

## 5. Development guardrails

- Every change: `cargo clippy -D warnings`, all test suites, and the e2e scenario must pass (CI enforces).
- Security-relevant defaults (kill switch on, logging consent required, private destinations blocked) have regression tests — do not weaken a test to make a change pass.
- No secrets in the repo (`.gitignore` excludes keys, `.env`, local properties).
- Legacy code under `legacy/` is reference only — do not ship it (its custom crypto is not reviewed).
