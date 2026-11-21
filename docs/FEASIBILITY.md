# Beyond VPN — Feasibility Study

## 1. Technical feasibility — **High**

| Question | Assessment |
|---|---|
| Can we build our "own VPN" safely? | Yes, by owning everything *except* the cryptographic tunnel. WireGuard is open source, formally verified (Tamarin/CryptoVerif analyses), in the Linux kernel since 5.6 and available on every OS. A bespoke cipher/handshake (as in the legacy .NET prototype) would need a multi-month external audit and would still be riskier. |
| Every device? | Windows/macOS/Linux via WireGuard-NT/wg-quick driven by our Rust agent; Android via the WireGuard tunnel library (Apache-2.0) inside our app; iOS/routers/smart TVs via standard WireGuard configs from our portal; any browser via our extension + HTTPS proxy. A native iOS app needs an Apple developer account and NetworkExtension entitlement (P1). |
| Logging "where users go" without breaking TLS? | Yes: DNS resolver logs (all apps) + proxy CONNECT host logs (browser). Limitation: apps with built-in DoH hide lookups (mitigation: block DoH endpoints). Full URL logging would require TLS interception, which we reject on security and legal grounds. |
| Performance | Kernel WireGuard reaches multi-Gbit/s per node; our gateway service is not in the packet path except for DNS and the browser proxy (Rust/tokio, zero-copy `copy_bidirectional`). |
| Language choice | Rust for long-running network daemons on hostile networks (memory safety, small static binaries, cross-compiles to all desktop OSes). Python/FastAPI for the control plane (fast iteration, rich auth/crypto libraries, easy admin reporting). Both proven in this repo with 96 tests + e2e. |

## 2. Operational feasibility — **Medium-High**

- Small team can operate: gateways are cattle (installer script / Docker image), control plane is a standard 3-tier app.
- Required skills: Linux networking (nftables, WireGuard), PostgreSQL, TLS/PKI, mobile/desktop release engineering (code signing, store review).
- Monitoring: health endpoint + heartbeat staleness today; Prometheus/OTel is P1.
- App-store risk: Google Play requires a VpnService declaration; Apple requires an organisation account for VPN apps. Plan 2–4 weeks for reviews.

## 3. Legal & compliance feasibility — **Medium (needs counsel)**

| Area | Note |
|---|---|
| India (IT Act 2000, CERT-In Directions 28-Apr-2022, DPDP Act 2023) | VPN providers serving Indian users must keep certain subscriber/KYC records (name, validity, IPs, purpose) for 5 years and report incidents within 6 h. Activity logs are personal data under DPDP → notice, consent, purpose limitation, erasure. |
| EU/UK (GDPR) | Browsing-domain logs are personal data; lawful basis (consent or legitimate interest for employer-managed devices with DPIA), retention limits, data-subject rights (implemented: view + erase), cross-border transfer basis. |
| Employer monitoring | Allowed in many jurisdictions with clear policy and proportionality; must be disclosed (built-in consent + transparency page). |
| Marketing | Do **not** advertise "no-logs" unless deployed with `logging_mode=off` and short retention, and independently audited. |
| Export control | WireGuard/strong crypto is generally mass-market (EAR 5A992 / 5D992) — confirm for target countries. |
| Licensing | New code AGPL-3.0-or-later; dependencies MIT/Apache/BSD/ISC; WireGuard-NT and wireguard-android redistribution terms respected (installed separately on Windows; Apache-2.0 library on Android). |

## 4. Economic feasibility (indicative, cloud list prices 2026)

| Scale | Infra | Monthly cost |
|---|---|---|
| Pilot: 50 users | 1 small VM control plane + managed PG starter, 2 gateways (2 vCPU) | ≈ US$ 60–120 |
| SMB: 1 000 users | 2 CP replicas, PG 2 vCPU, 6 gateways in 3 regions | ≈ US$ 400–800 + bandwidth |
| Consumer: 50 000 users | 4 CP replicas, PG HA 8 vCPU + log store, 150–250 gateways (bandwidth-dominated) | ≈ US$ 15–40 k (bandwidth is 60–80 %) |

One-off: code signing certs (~US$ 300–600/yr), Apple developer (US$ 99/yr), Google Play (US$ 25), external pen-test (US$ 8–25 k).

## 5. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Logging misuse / privacy breach | Medium | High | RBAC, audited log access, retention, encryption at rest (DB volume), consent/transparency |
| Gateway compromise | Low-Med | High | Hardened systemd unit, per-gateway secret + rotation, no token minting, isolation rules, re-image on suspicion |
| Control-plane outage | Medium | Medium | Gateways keep last peer set; HA replicas + managed DB (P1) |
| VPN blocking by networks/censors | Medium | Medium | Stealth transport (P1), port 443 options |
| App-store rejection | Medium | Medium | Follow VPN policies, privacy policy, declarations |
| Key loss (data key) | Low | High | Secret manager + offline backup; documented in GUARDRAILS |

## 6. Verdict

**Feasible.** v0.2 already demonstrates the full control-plane ↔ gateway ↔ client loop with automated tests. The remaining risk is concentrated in real-infrastructure validation (P0 items) and legal configuration of activity logging, not in core technology.
