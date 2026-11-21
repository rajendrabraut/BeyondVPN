# Beyond VPN — Plan

*Owner: platform architecture. Last updated: 2026-11-18.*

## 1. Requirements (as given) and how the plan answers them

| # | Requirement | Plan response |
|---|---|---|
| 1 | Must work on every device | Native apps for Windows/macOS/Linux (Rust agent + Electron UI) and Android (Kotlin). iOS, routers and any other device use the **official WireGuard app** with a config/QR generated in the web portal. Any browser gets the extension. |
| 2 | Proper logs of data usage and where users go | Per-peer byte counters from WireGuard (all traffic), per-domain DNS logs from the gateway resolver (all apps), per-host logs from the browser proxy. Usage rolled up per user/day. Admin search, CSV export, reports; users see their own logs. |
| 3 | Maintain security properly | WireGuard (Noise IK, ChaCha20-Poly1305) + preshared key; Argon2id; EdDSA tokens; MFA; lockout; refresh-token rotation; per-gateway secrets; encrypted fields; hash-chained audit log; SSRF and injection guards. See GUARDRAILS.md. |
| 4 | Own VPN from open-source tools | Own control plane, gateway, agent, apps and protocol glue; the cryptographic data plane is WireGuard (GPL-2.0 kernel, MIT/Apache user-space) — deliberately **not** a home-made cipher. |
| 5 | Features from Forti / Proton | Kill switch, split tunnelling (routes, apps, domains), NetShield-style blocking, quick-connect/fastest server, server load, MFA, always-on, device posture checks, admin policy, audit, data caps, WebRTC leak protection. Matrix in docs/ARCHITECTURE.md. |
| 6 | Test properly | Unit tests in every component (96), adversarial security tests, cross-language e2e test, CI on 3 OSes. |
| 7 | Name it Beyond VPN | Product, package IDs (`app.beyondvpn.*`), UI, docs. |
| 8 | Clone & merge the two repos | `BeyondVPN` cloned, work on branch `beyond-v2`; `FortiClientVPN_Clone` merged with full history under `legacy/forticlone`; original .NET code under `legacy/dotnet`. |
| 9 | Language freedom (Rust/Python) | **Rust** where memory safety + performance matter (gateway packet-adjacent services, desktop agent, crypto helpers). **Python** where productivity and ecosystem matter (control plane, admin APIs, reporting). TypeScript/Kotlin for UIs. |
| 10 | Documentation & feasibility as senior architect/admin | This file set + docs/ARCHITECTURE.md, docs/FEASIBILITY.md, docs/OPERATIONS.md. |
| 11 | Six .md files | PLAN, EXECUTION, IMPLEMENTATION, GUARDRAILS, THINGS_REMAINING, PROGRESS. |
| 12 | Fully automated, no prompts | Executed end-to-end without user interaction; all decisions recorded below. |

## 2. Key architecture decisions (ADRs)

| ID | Decision | Alternatives rejected | Reason |
|---|---|---|---|
| ADR-1 | **WireGuard** as data plane | Custom protocol over WebSocket (legacy .NET prototype), OpenVPN, IPsec | Formally analysed protocol, ~4k LoC kernel code, fastest on mobile, available on every OS. Writing our own cipher/handshake is an unacceptable security risk. |
| ADR-2 | Split **control plane** (Python) / **data plane** (Rust + kernel WG) | Monolith | Gateways keep running if the control plane is down (cached peers); scale independently; smaller attack surface on gateways. |
| ADR-3 | Device-generated keys; server never sees private keys | Server-generated configs | Compromise of the control plane does not reveal tunnel keys. Web portal generates keys in the browser (tweetnacl X25519). |
| ADR-4 | **Ed25519 (EdDSA) JWTs** for access and proxy tokens | HS256 shared secret | Gateways verify offline with a public key and can never mint tokens. |
| ADR-5 | Activity logging at **DNS resolver + browser proxy**, metering from **WireGuard counters** | TLS interception / DPI | Gives "where users visit" (domains/hosts) without breaking TLS, installing root CAs, or seeing page contents. |
| ADR-6 | Browser extension = authenticated **HTTPS forward proxy** | WireGuard in WASM | Extensions cannot create tunnels; proxy approach is what Proton/others ship. |
| ADR-7 | Desktop: **privileged Rust agent + unprivileged UI** | UI elevated | Least privilege; UI cannot be abused to run commands; API bound to loopback with token + Origin/Host checks. |
| ADR-8 | Reuse **WireGuard-NT** (Windows) / **wg-quick** (Linux/macOS) / **wireguard-android** tunnel lib | Own TUN driver | Signed drivers, audited, kill-switch support built in. |
| ADR-9 | SQLite for dev, PostgreSQL for production (SQLAlchemy) | NoSQL | Relational data, transactions for IPAM, easy reporting. |
| ADR-10 | Logging mode is a **policy** (`full` / `metadata` / `off`) + retention | Always log everything | Legal requirements differ by jurisdiction and customer; consent captured at registration. |
| ADR-11 | Legacy code preserved, not extended | Extend .NET prototype | Prototype used custom crypto framing; the requirement allowed language choice; history is kept for reference. |

## 3. Scope

**In scope (delivered in v0.2):** control plane, gateway, desktop agent + UI, Android app, browser extension, web portal + admin console, deployment artefacts, tests, docs.

**Out of scope for v0.2 (tracked in THINGS_REMAINING.md):** native iOS/macOS apps (iOS uses WireGuard app), SSO (OIDC/SAML), Secure-Core multi-hop, obfuscation/stealth transport, billing, app-store signing/publishing, HA/multi-region control plane, load testing at scale.

## 4. Phased roadmap

| Phase | Content | Exit criteria | Status |
|---|---|---|---|
| P0 Foundations | Repo merge, architecture, shared library | Tests for keys/tokens/config | ✅ |
| P1 Core VPN | Control plane, gateway, desktop agent | Cross-language e2e passes | ✅ |
| P2 Clients | Web portal, extension, desktop UI, Android | All build + unit tests | ✅ |
| P3 Ops | Docker, installer, CI | Compose/CI files | ✅ written (not yet run on real infra) |
| P4 Pilot | Deploy 1 control plane + 2 gateways, 20 users | Real tunnels on all OSes, 7-day soak | ⏳ next |
| P5 Hardening | Pen-test, SSO, Redis rate-limit, HA DB, signed builds | External audit report | ⏳ |
| P6 Scale & features | Multi-hop, stealth transport, iOS native, billing | — | ⏳ |

## 5. Success metrics

- Connect time p95 < 2 s on broadband; reconnect after network change < 5 s (WireGuard roaming).
- Gateway: ≥ 1 Gbit/s per vCPU-pair with kernel WireGuard; ≤ 250 peers default capacity per small node.
- Zero private keys stored server-side; zero plaintext secrets in DB (PSK & MFA secrets encrypted).
- Activity log ingestion lag < 30 s; retention purge daily; audit chain verifies.
