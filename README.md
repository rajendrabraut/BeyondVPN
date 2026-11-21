# Beyond VPN

A self-hostable VPN platform for **Windows, macOS, Linux, Android, iOS (via WireGuard app), any browser (extension) and a web portal**, built on open-source, audited cryptography (WireGuard, Ed25519, Argon2id) with per-user **usage metering and activity logging**, an admin console, and enterprise policy controls inspired by FortiClient and Proton VPN.

| Component | Path | Language | Status |
|---|---|---|---|
| Shared crypto/config library | `core/crates/beyond-common` | Rust | ✅ 28 tests |
| Stealth transport (WireGuard over TLS/443, anti-blocking) | `core/crates/beyond-stealth` | Rust | ✅ 4 tests |
| Gateway (peer sync, metering, filtering DNS, authenticated HTTPS proxy, multi-hop uplinks, stealth relay) | `core/crates/beyond-gateway` | Rust | ✅ 14 tests |
| Desktop agent (CLI + local daemon, WireGuard-NT / wg-quick, stealth, multi-hop) | `core/crates/beyond-agent` | Rust | ✅ 6 tests |
| Control plane (auth, MFA, OIDC SSO, devices, IPAM, multi-hop, logs, admin, audit) | `control-plane/` | Python (FastAPI) | ✅ 44 tests |
| Web portal + admin console | `clients/web/` | React + TypeScript | ✅ 5 tests, builds |
| Browser extension (Chrome, Edge, Firefox) | `clients/extension/` | JavaScript (MV3) | ✅ 6 tests |
| Desktop app UI | `clients/desktop/` | Electron | ✅ 4 tests, runs against the demo stack |
| Android app | `clients/android/` | Kotlin | ✅ 7 tests, runs on emulator |
| iOS app | `clients/ios/` | Swift (SwiftUI + NetworkExtension) | source only, not yet compiled (needs a Mac) |
| Cross-language end-to-end test | `tests/e2e/run_e2e.py` | Python | ✅ passes |
| Deployment | `deploy/`, `core/Dockerfile.gateway` | Docker / shell | written, not yet run on a real server ([runbook](docs/DEPLOY_RUNBOOK.md)) |

**Total: 118 automated tests + 1 end-to-end scenario, all passing** (see [PROGRESS.md](PROGRESS.md)).

## Project documents

| Document | Purpose |
|---|---|
| [PLAN.md](PLAN.md) | Goals, scope, architecture decisions, phased roadmap |
| [EXECUTION.md](EXECUTION.md) | How the work was carried out, step by step, and how to build/run/test everything |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Component-by-component technical detail, APIs, data model, protocols |
| [GUARDRAILS.md](GUARDRAILS.md) | Security controls, privacy/legal rules for activity logging, operating rules |
| [THINGS_REMAINING.md](THINGS_REMAINING.md) | Gaps, known limitations and prioritised backlog |
| [PROGRESS.md](PROGRESS.md) | Status per component, test evidence, bugs found and fixed |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, flows and feature comparison with Forti / Proton |
| [docs/FEASIBILITY.md](docs/FEASIBILITY.md) | Technical, operational, legal and cost feasibility |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Deployment and administration runbook |
| [docs/DEPLOY_RUNBOOK.md](docs/DEPLOY_RUNBOOK.md) | Step-by-step first real deployment with a client test checklist |
| [docs/SSO.md](docs/SSO.md) | OpenID Connect single sign-on setup (Entra ID, Google, Okta, Keycloak) |

## How it works (one paragraph)

Clients authenticate to the **control plane** (Python/FastAPI). Each device generates its own WireGuard key locally and registers only the public key. When a user connects, the control plane allocates a tunnel IP on the chosen **gateway** and returns the WireGuard config. Each gateway runs kernel WireGuard plus the Rust `beyond-gateway` service, which pulls its peer list every 10 s, meters traffic per peer, resolves DNS for tunnelled clients (blocking ads/malware and logging the domains visited), and offers an authenticated HTTPS proxy for the browser extension. Gateways upload usage and activity logs, which users can see about themselves and admins can search, export and audit.

## Quick start (developer machine)

```bash
# 1. Rust core
cd core && cargo test --workspace && cargo build --workspace && cd ..
```

```bash
# 2. Control plane (http://127.0.0.1:8000/docs)
cd control-plane && python -m venv .venv && .venv/Scripts/pip install -e ".[test]" && .venv/Scripts/pytest -q
```

```bash
# 3. End-to-end: control plane + Rust gateway + Rust agent talking to each other
control-plane/.venv/Scripts/python tests/e2e/run_e2e.py
```

```bash
# 4. Web portal (proxies /api to 127.0.0.1:8000)
cd clients/web && npm install && npm run dev
```

On Linux/macOS use `.venv/bin/` instead of `.venv/Scripts/`. Production deployment is described in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Repository layout

```
core/                 Rust workspace (beyond-common, beyond-gateway, beyond-agent) + gateway Dockerfile
control-plane/        FastAPI control plane, tests, Dockerfile
clients/web/          React portal + admin console
clients/extension/    MV3 browser extension (Chrome/Edge/Firefox manifests)
clients/desktop/      Electron desktop UI
clients/android/      Native Android app (Kotlin, WireGuard tunnel library)
deploy/               docker-compose, Caddy, gateway installer, agent services, blocklists
tests/e2e/            Cross-language end-to-end test
legacy/dotnet/        Original BeyondVPN .NET prototype (history preserved)
legacy/forticlone/    FortiClientVPN_Clone repository (history preserved via subtree merge)
```

## Licence

AGPL-3.0-or-later for new code (network-service copyleft suits a hosted VPN). The WireGuard tunnel library used on Android is Apache-2.0; WireGuard for Windows is MIT/GPL-2.0 (installed separately).
