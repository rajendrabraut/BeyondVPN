# Beyond VPN — Progress

*Status as of 2026-11-21, branch `beyond-v2`.*

## 1. Component status

| Component | Built | Tests | Verified how | Not yet verified |
|---|---|---|---|---|
| `beyond-common` (Rust) | ✅ | 28 ✅ | `cargo test`, clippy `-D warnings` | — |
| `beyond-stealth` (Rust, new) | ✅ | 4 ✅ | WireGuard-over-TLS relay: framing, probe 404, UDP→TCP→UDP round trip | Over the internet behind a UDP-blocking firewall |
| `beyond-gateway` (Rust) | ✅ | 14 ✅ | Unit + in-process proxy/DNS tests; multi-hop rule/link planner; e2e in dry-run | Kernel WireGuard reconcile, nftables, `bhop` uplinks + policy routing, TLS cert loading on Linux |
| `beyond-agent` (Rust) | ✅ | 6 ✅ | Unit + e2e (login, register, connect, status, disconnect) in dry-run | Real tunnel through a gateway; stealth relay with a real cert |
| WireGuard-NT on Windows | ✅ installed | manual ✅ | Two tunnel services on this PC hand-shook over 127.0.0.1 (split routes only) | Full tunnel to a real gateway |
| Control plane (Python) | ✅ | 44 ✅ | pytest (auth, MFA, **OIDC SSO vs fake IdP**, RBAC, IPAM, **multi-hop**, policy, logging modes, retention, erase, audit tamper) + e2e | PostgreSQL backend, multi-replica, real IdP |
| Web portal (React) | ✅ | 5 ✅ | vitest, `tsc` strict, Vite production build; SSO buttons + consent step | Manual UI walkthrough in a browser |
| Browser extension | ✅ | 6 ✅ | `node --test`, syntax check, packaged for Chrome + Firefox | Loaded in a real browser against a TLS gateway |
| Desktop UI (Electron) | ✅ | 4 ✅ | **Window opened** and driven over DevTools: sign-in → Connect → "Protected" against `tests/e2e/demo_stack.py` (dry-run tunnel); screenshots in `docs/screenshots/` | Real tunnel; installer |
| Android app (Kotlin) | ✅ | 7 ✅ | JUnit; `assembleDebug`; **installed and launched on an API 36 emulator** (`docs/screenshots/android-home.png`) | Physical phone; tunnel up against a gateway |
| iOS app (Swift, new) | source only | 5 written | — | Not compiled: needs a Mac with Xcode (clients/ios/README.md) |
| Cross-language e2e | ✅ | 1 scenario ✅ | `tests/e2e/run_e2e.py` (12 checks) | — |
| Deployment (Docker/installer) | ✅ written | — | Reviewed; runbook `docs/DEPLOY_RUNBOOK.md` | `docker compose up`, installer on Ubuntu (no server yet) |
| CI (GitHub Actions) | ✅ | 7 jobs ✅ | Green on PR #5 (Rust on Linux/Windows/macOS, Python, e2e, web/extension/desktop, Android) | — |
| Docs | ✅ | — | — | — |

**Totals:** 118 unit/integration tests + 1 multi-process e2e scenario, all passing locally on Windows 11 (iOS tests not run).

## 2. End-to-end scenario output (latest run)

```
[e2e] starting control plane
[e2e] starting Rust gateway (dry-run)
[e2e] gateway online
[e2e] registering user + desktop agent login/connect
[e2e] agent connected; device 4826efaa registered
[e2e] checking gateway received the peer
[e2e] browser-extension path: Python token -> Rust proxy
[e2e] proxy tunnel OK; unauthenticated request rejected (407)
[e2e] DNS sinkhole from admin policy
[e2e] waiting for activity logs to be uploaded (<=30s)
[e2e] logs present; metered 22 bytes
[e2e] disconnect removed the peer; audit chain intact
E2E PASSED
```

## 3. Defects found by testing and fixed

| # | Found by | Defect | Fix |
|---|---|---|---|
| 1 | e2e | **Desktop kill switch defaulted to OFF**: `#[derive(Default)]` on `Settings` ignored the serde default, so fresh installs had no kill switch | Manual `Default` impl (kill switch ON), regression test in `store.rs` |
| 2 | e2e | Dry-run backend kept "up" state in memory, so `status` in a new CLI process reported disconnected | Marker-file state |
| 3 | unit | Blocklist lookup failed to compile due to temporary lifetime in tail expression | Bound to local |
| 4 | unit | Blocklist would accept bare `localhost` as a blockable domain | Require a dot |
| 5 | pytest | Test e-mails on the reserved `.test` TLD rejected by email-validator | Use `example.com` |
| 6 | clippy | `repeat().take()` lint | `repeat_n` |

## 4. Repository history (this branch)

```
feat: desktop app, Android app, deployment, e2e test and CI
feat(clients): web portal (React) and MV3 browser extension (Chrome/Edge/Firefox)
feat(control-plane): FastAPI control plane with auth, MFA, devices, WireGuard provisioning, logging and admin
feat(core): Rust gateway, desktop agent and shared crypto/config library
chore: merge FortiClientVPN_Clone history into legacy/forticlone
chore: move original .NET prototype into legacy/dotnet
```

## 5. Next milestone

Pilot (P4 in PLAN.md): one control plane + two gateways on real Linux hosts, all client types connected for a 7-day soak. Entry items are P0 #1–#5 in THINGS_REMAINING.md.
