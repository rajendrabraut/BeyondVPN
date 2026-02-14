# BeyondVPN Production Technical Specification (.NET 8)

## 0) Design Targets and Operating Envelope

This specification targets a dual-market VPN platform (enterprise + consumer) implemented primarily in C#/.NET 8 with Linux/Windows data-plane nodes and a centralized ASP.NET Core control plane.

**Assumed baseline SLO/SLA targets (replace with final product numbers):**
- Concurrent active clients: **X = 200,000** (burst 300,000)
- Tunnel setup latency (p95): **Y = < 250 ms** regional, < 600 ms cross-region
- Availability: **99.9%+** monthly for authenticated tunnel service
- Deployment budget model: **Hybrid cloud-first** (managed control plane + optional self-hosted enterprise gateways)

---

## 1) High-Level Architecture

## 1.1 Control Plane vs Data Plane

### Control Plane (ASP.NET Core Web API)
Responsibilities:
- Identity, authN/authZ, device registration/binding
- VPN server discovery and dynamic assignment
- Session/token issuance, revocation, policy distribution
- Fleet telemetry ingestion and audit log orchestration

Core services:
- `AuthService` (OIDC/SAML/passwordless integrations)
- `DeviceService` (device fingerprint + attestation + trust score)
- `SessionService` (short-lived connection grants)
- `PlacementService` (least-latency + least-load routing)
- `PolicyService` (ACL, split/full tunnel, traffic quota)
- `AuditService` (immutable event stream)

State stores:
- PostgreSQL: source of truth
- Redis: hot session/device/server state

### Data Plane (VPN Gateways)
Responsibilities:
- Tunnel termination (UDP primary, TCP fallback)
- Packet encryption/decryption and forwarding
- NAT traversal assist, keepalives, anti-replay windows
- Per-session enforcement (bandwidth caps, ACL, idle timeout)

Runtime profile:
- Linux preferred for high-throughput kernel networking
- Windows Server supported for enterprise deployments
- Gateway agent written in C# with native interop for TUN/TAP + optional eBPF/iptables integration on Linux

## 1.2 Component Layout (described diagram)

**Diagram (text):**
`VPN Client (Win UI + Service)` -> `Control Plane API + Redis/Postgres` -> `Gateway Pool (regional)` -> `Internet / Private resources`

Out-of-band links:
- Gateways push heartbeat/load metrics to Control Plane.
- Control Plane pushes CRL/revocations and policy snapshots to gateways (via gRPC stream).

## 1.3 Client ↔ Server Communication

1. Client authenticates with control plane over TLS 1.3.
2. Client requests connection grant with device proof.
3. Control plane returns signed tunnel config (gateway endpoint list, ephemeral key material envelope, policy TTL).
4. Client establishes data-plane tunnel to assigned gateway via UDP; if blocked, fallback TCP.
5. Gateway validates token offline using JWKS cache + optional introspection fallback.

## 1.4 Key Exchange & Tunnel Lifecycle

Lifecycle:
- `INIT` -> `AUTHENTICATED` -> `KEY_EXCHANGED` -> `ESTABLISHED` -> `ROTATING` -> `TERMINATED`.
- Ephemeral session keys derived via ECDH (X25519) + HKDF.
- Re-key every 15 minutes or 2 GB traffic, whichever comes first.

---

## 2) VPN Protocol Design

## 2.1 Handshake Flow (WireGuard/OpenVPN-inspired, custom control semantics)

1. **ClientHello**
   - Version, cipher suite preference, client ephemeral public key, nonce, token, device ID hash.
2. **GatewayHello**
   - Chosen cipher suite, gateway ephemeral key, nonce, anti-replay cookie challenge (stateless DoS defense).
3. **ClientAuthProof**
   - HMAC over transcript with derived temporary key + cookie echo.
4. **ServerFinish**
   - Session ID, assigned virtual IP, route set, key epoch, limits.
5. **Data Transfer**
   - Encrypted packets with monotonically increasing sequence numbers.
6. **Rekey**
   - Lightweight rekey frame with new ephemeral key and key epoch.

All handshake frames carry:
- protocol version
- timestamp (+/- 30 seconds skew window)
- replay protection window id

## 2.2 Cryptography Choices

Primary profile:
- Key exchange: **X25519**
- AEAD cipher: **ChaCha20-Poly1305** (mobile/CPU-efficient default)
- Alternate AEAD: **AES-256-GCM** when AES-NI available
- Hash/KDF: **BLAKE2s** (protocol hashing) + **HKDF-SHA256** for key expansion
- Auth token signing: **Ed25519** (control plane issued grants)

C# implementation notes:
- Use `libsodium` bindings for X25519/ChaCha where possible.
- Use `.NET Cryptography APIs` (`AesGcm`, `HMACSHA256`, `ECDiffieHellman`) as compliant fallback.
- Zero sensitive buffers using `CryptographicOperations.ZeroMemory`.

## 2.3 Key Rotation Strategy

- Soft rekey trigger: 15 min / 2 GB / route-policy change.
- Hard rekey trigger: suspicion event (IP change anomaly, replay threshold breach).
- Overlap window: accept key epoch N and N+1 for 30 seconds.
- Failed rekey -> terminate after grace retries (3 attempts, exponential backoff).

## 2.4 NAT Traversal Handling

- UDP hole punching for peer-to-gateway path continuity.
- Keepalive every 20 seconds (adaptive based on NAT type).
- NAT type inference using STUN-like probes.
- Fallback matrix:
  - UDP direct
  - UDP encapsulated over 443
  - TCP 443 TLS camouflage tunnel

---

## 3) Database Schema

## 3.1 Core Entities

- `users`: identity and lifecycle state
- `devices`: user-bound device identity and trust posture
- `vpn_servers`: regional gateway inventory and health
- `sessions`: active/closed tunnel sessions
- `audit_events`: immutable security/compliance events
- `traffic_usage_rollups`: hourly/day aggregates for billing and limits

## 3.2 Example SQL (PostgreSQL)

```sql
CREATE TABLE users (
  id                UUID PRIMARY KEY,
  email             CITEXT UNIQUE NOT NULL,
  password_hash     TEXT,
  auth_provider     TEXT NOT NULL DEFAULT 'local',
  mfa_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
  status            TEXT NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE devices (
  id                UUID PRIMARY KEY,
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_public_key BYTEA NOT NULL,
  fingerprint_hash  BYTEA NOT NULL,
  platform          TEXT NOT NULL,
  display_name      TEXT,
  trust_state       TEXT NOT NULL,
  last_seen_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_devices_user_last_seen ON devices(user_id, last_seen_at DESC);

CREATE TABLE vpn_servers (
  id                UUID PRIMARY KEY,
  region            TEXT NOT NULL,
  public_ip         INET NOT NULL,
  udp_port          INT NOT NULL,
  tcp_port          INT NOT NULL,
  capacity_clients  INT NOT NULL,
  active_clients    INT NOT NULL DEFAULT 0,
  health_status     TEXT NOT NULL,
  load_score        NUMERIC(5,2) NOT NULL DEFAULT 0,
  last_heartbeat_at TIMESTAMPTZ NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_vpn_servers_region_health ON vpn_servers(region, health_status, load_score);

CREATE TABLE sessions (
  id                UUID PRIMARY KEY,
  user_id           UUID NOT NULL REFERENCES users(id),
  device_id         UUID NOT NULL REFERENCES devices(id),
  server_id         UUID NOT NULL REFERENCES vpn_servers(id),
  grant_jti         UUID NOT NULL,
  status            TEXT NOT NULL,
  assigned_ip       INET,
  bytes_in          BIGINT NOT NULL DEFAULT 0,
  bytes_out         BIGINT NOT NULL DEFAULT 0,
  started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at          TIMESTAMPTZ,
  rekey_epoch       INT NOT NULL DEFAULT 1
);
CREATE INDEX idx_sessions_device_status_started ON sessions(device_id, status, started_at DESC);
CREATE INDEX idx_sessions_server_status ON sessions(server_id, status);

CREATE TABLE audit_events (
  id                BIGSERIAL PRIMARY KEY,
  event_time        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor_type        TEXT NOT NULL,
  actor_id          UUID,
  action            TEXT NOT NULL,
  object_type       TEXT,
  object_id         TEXT,
  result            TEXT NOT NULL,
  source_ip         INET,
  correlation_id    UUID,
  metadata          JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_audit_events_time_action ON audit_events(event_time DESC, action);
CREATE INDEX idx_audit_events_metadata_gin ON audit_events USING GIN(metadata);
```

## 3.3 Scale Indexing and Partitioning

- Partition `sessions` and `audit_events` by month for retention and query locality.
- Use partial index for active sessions: `WHERE status = 'active'`.
- Keep OLTP tables narrow; move heavy analytics into rollup tables.

---

## 4) API Design (C#/.NET)

## 4.1 Endpoint Surface (ASP.NET Core)

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/devices/register`
- `POST /api/v1/devices/{id}/attest`
- `POST /api/v1/vpn/sessions/start`
- `POST /api/v1/vpn/sessions/{id}/heartbeat`
- `POST /api/v1/vpn/sessions/{id}/stop`
- `GET /api/v1/vpn/servers/recommendations`

## 4.2 C# Contract Examples

```csharp
public sealed record StartSessionRequest(
    Guid DeviceId,
    string ClientRegion,
    string ClientPublicKey,
    string[] SupportedCipherSuites,
    string AppVersion);

public sealed record StartSessionResponse(
    Guid SessionId,
    string AssignedGatewayHost,
    int UdpPort,
    int TcpPort,
    string GrantToken,
    DateTimeOffset ExpiresAt,
    string[] Routes,
    int RekeyIntervalSeconds);
```

Implementation notes:
- Use `Minimal APIs` or controllers with explicit request validation (`FluentValidation` or data annotations).
- All endpoints require correlation IDs and structured logging scopes.
- JWKS endpoint for gateway-side token verification.

## 4.3 Abuse Prevention

- Rate limit by IP + user + device tuple via Redis sliding window.
- Login endpoint with adaptive throttling and CAPTCHA escalation.
- Token replay detection via JTI cache (`SETNX` + TTL).
- Geo-velocity checks (impossible travel) for high-risk auth attempts.

---

## 5) Caching Strategy

## 5.1 Redis Keyspaces

- `sess:{sessionId}` -> active session blob (TTL aligned to grant expiry)
- `dev:{deviceId}:state` -> trust score, revocation flag
- `srv:{serverId}:load` -> active clients, egress Mbps, health
- `jti:{tokenId}` -> replay protection marker
- `route:{region}` -> precomputed gateway recommendations

## 5.2 Patterns

- Read-through cache for server recommendations.
- Write-behind for traffic counters (flush every 10-30s in batches).
- Pub/Sub channel for revocation broadcast to gateways.
- Use Redis Cluster with key hash tags for co-locating hot keys.

---

## 6) Client Architecture (Windows First, C#)

## 6.1 Process Split

1. **UI App (WinForms/WPF)**
   - User login, server preference, status visualization.
2. **Windows Service (`LocalSystem` with hardened ACL)**
   - Tunnel creation, key management, policy enforcement.
   - Exposes local named pipe API to UI with strict ACLs.

## 6.2 Tunnel Lifecycle Manager

State machine in service:
- `Disconnected`
- `Authenticating`
- `Connecting`
- `Connected`
- `Reconnecting`
- `Blocked` (policy/compliance failure)

Service responsibilities:
- Manage TUN adapter routes/DNS safely.
- Persist only non-secret session metadata.
- Keep keys in-memory only; optional DPAPI-protected short cache.

## 6.3 Auto-Reconnect Logic

- Exponential backoff: 1s, 2s, 4s, 8s, capped at 60s.
- Fast failover when heartbeat missed >2 intervals.
- Region failover strategy: primary -> nearest 2 alternates.
- Preserve kill-switch behavior during reconnect for full tunnel profiles.

---

## 7) Deployment & CI/CD

## 7.1 Containerization

Images:
- `beyondvpn-control-plane` (.NET 8 ASP.NET image)
- `beyondvpn-gateway` (.NET 8 runtime + CAP_NET_ADMIN on Linux)
- `beyondvpn-worker` (rollups, audit export, async tasks)

Use multi-stage Docker builds and signed images (cosign).

## 7.2 Kubernetes Topology

Namespaces:
- `vpn-control`
- `vpn-data-plane`
- `vpn-observability`

Deployment pattern:
- Control plane: HPA on CPU/RPS.
- Gateway: DaemonSet or regional Deployment with host networking.
- Redis/PostgreSQL: managed services recommended (RDS/Cloud SQL/ElastiCache).

## 7.3 Release Strategy

- Blue/green for control plane API.
- Canary (5% -> 25% -> 100%) for gateway software.
- Automatic rollback on SLO breach (setup latency p95, auth error rate, packet loss).

CI/CD pipeline gates:
- Unit tests, integration tests, protocol compatibility tests, container vulnerability scan, IaC policy checks.

---

## 8) Security by Layer

## 8.1 Client Security

- Code signing and anti-tamper checks.
- Secure update channel (signed manifests + pinned cert chain).
- Local secrets in Windows DPAPI or OS keychain equivalents.

## 8.2 Server Hardening

- Minimal OS baseline, CIS hardening profiles.
- mTLS between control services and gateways.
- Strict egress/ingress NetworkPolicy in Kubernetes.
- Runtime seccomp/AppArmor and read-only root filesystem where possible.

## 8.3 Key Storage

- Root signing keys in cloud KMS/HSM.
- Data encryption keys rotated automatically (90-day max age).
- No long-lived private keys on gateways; bootstrap via short-lived certs.

## 8.4 MITM/Replay Defenses

- TLS 1.3 with certificate pinning (client control-plane channel).
- Handshake transcript binding.
- Nonce + sequence anti-replay sliding window.
- Token audience + expiry + one-time JTI semantics.

---

## 9) Monitoring & Observability

## 9.1 Metrics

Control plane:
- Auth success/failure rate
- Session issuance latency (p50/p95/p99)
- API 4xx/5xx and rate-limit hits

Data plane:
- Tunnel setup latency
- Active sessions per gateway
- Packet loss/jitter/RTT
- Throughput in/out per gateway and per tenant
- Rekey failures and reconnect rates

## 9.2 Logging Strategy

- Structured JSON logs with correlation IDs and session IDs.
- Security events to immutable audit store (WORM-capable bucket export).
- PII minimization + field-level redaction.

## 9.3 Alerting Thresholds (initial)

- Setup latency p95 > 500 ms (5 min) -> warning
- Auth failure rate > 5% (10 min) -> critical
- Gateway packet loss > 2% sustained -> warning
- Redis unavailable > 30s -> critical

---

## 10) Cost Estimation Model

Costs should be modeled by three dimensions:

1. **Bandwidth cost per user**
   - `avg GB/user/month * egress $/GB`
2. **Gateway compute cost**
   - `required gateway instances per region * instance hourly price`
3. **Control plane cost**
   - API nodes + DB + Redis + observability stack

Example monthly model:
- 100k users, 50 GB/user, $0.05/GB egress -> $250k egress
- 120 gateway instances at $120/mo -> $14.4k
- Control plane managed services -> $25k-$60k

Optimization levers:
- Regional egress blending
- Smart routing to avoid premium inter-AZ paths
- Compression for TCP fallback control channels only

---

## 11) Risk Assessment

## 11.1 DDoS

Risks:
- Handshake flood on UDP ports
- Token validation abuse

Mitigations:
- Stateless cookie challenge pre-auth.
- Anycast + upstream DDoS scrubbing.
- Per-source IP token bucket at edge.

## 11.2 Key Leakage

Risks:
- Signing key exfiltration, endpoint memory scraping

Mitigations:
- HSM-backed signing, split-key operations, emergency rotation runbook.
- Frequent ephemeral keys and forward secrecy.

## 11.3 Server Compromise

Risks:
- Gateway host takeover, lateral movement

Mitigations:
- Immutable images, rapid node rotation, least privilege IAM.
- Strong control/data plane isolation; no direct DB access from gateway.

## 11.4 Regulatory Risks

- GDPR data minimization, right-to-erasure workflows
- Region pinning for data residency
- ISO 27001 controls mapped to operational procedures and evidence collection

---

## 12) MVP vs Future Roadmap

## Phase 1 (Core VPN, 3-4 months)

- Windows client + service
- Control plane auth/device/session APIs
- UDP tunnel + TCP fallback
- Basic gateway placement + quotas + audit logs
- Regional HA (2 regions)

## Phase 2 (6-9 months)

- Mobile clients (iOS/Android)
- Split tunneling and app-based routing
- SSO/SAML enterprise integrations
- Advanced policy engine and tenant isolation

## Phase 3 (9-15 months)

- Dedicated enterprise gateways / private PoPs
- CASB/SSE integration hooks
- ZTNA posture checks and conditional access
- BYOK and advanced compliance reporting

---

## .NET 8 Reference Implementation Notes

- Control plane: ASP.NET Core + gRPC for gateway streaming channels.
- Shared contracts: `VpnCore` project with DTOs + protocol primitives.
- Gateway runtime: `BackgroundService` workers for tunnel IO loops.
- Performance:
  - `SocketAsyncEventArgs` pools
  - `System.IO.Pipelines` for packet framing
  - Array pools to minimize GC pressure
- Security coding:
  - Constant-time comparisons via `CryptographicOperations.FixedTimeEquals`
  - Avoid secret material in logs/exceptions

This architecture is production-oriented: it separates trust domains, supports multi-region scaling, and aligns with operational controls required for enterprise-grade VPN services.

---

## 13) How This System Works in Practice (End-to-End Runtime)

This section describes the concrete runtime flow from user login to packet forwarding.

1. **User sign-in and device trust check**
   - Windows client UI sends credentials/SSO token to control plane.
   - Control plane verifies identity, checks device binding/trust posture, and evaluates policy.

2. **Session grant issuance**
   - Client asks `POST /api/v1/vpn/sessions/start` with device ID + client ephemeral key.
   - Control plane selects the best gateway (latency + load + policy constraints).
   - Control plane returns short-lived signed grant, gateway endpoints, allowed routes, and rekey interval.

3. **Data-plane handshake and tunnel establishment**
   - Client opens UDP tunnel to gateway (fallback TCP if blocked).
   - Handshake performs ephemeral X25519 key agreement + transcript validation + anti-replay cookie.
   - Gateway returns assigned virtual IP and policy envelope; tunnel transitions to `ESTABLISHED`.

4. **Encrypted packet processing**
   - Client service reads packets from local TUN adapter.
   - Payloads are encrypted with current key epoch and forwarded to gateway.
   - Gateway decrypts, enforces policy/quota, NATs/routes traffic to destination.
   - Return traffic is encrypted and sent back to client for local injection to TUN.

5. **Steady-state control and enforcement**
   - Heartbeats update session liveness.
   - Redis-backed counters track per-session traffic and abuse/rate limits.
   - Policy or revocation updates are pushed to gateways; non-compliant sessions are terminated.

6. **Rekey, failover, and termination**
   - Rekey occurs periodically or when byte threshold is exceeded.
   - If gateway health degrades, client reconnects to next recommended server.
   - On disconnect/logout/revocation, session is closed and audit events are persisted.

---

## 14) Current Repository Production Readiness Assessment

### 14.1 Verdict

**Current repository state is NOT production-ready for real VPN service operation.**

The codebase contains useful prototype building blocks (crypto primitives, TUN wrappers, simple relay), but it lacks critical production capabilities required to run a secure, scalable VPN in enterprise/consumer environments.

### 14.2 Evidence from current codebase

- Linux server app currently performs a relay hello over WebSocket and does not implement full packet tunnel loop, authZ enforcement, session lifecycle, or policy engine integration.
- Relay component is a basic WebSocket bridge keyed by query-string session ID, with no strong control-plane authorization model.
- WinForms controller methods are mostly logging stubs and do not orchestrate full handshake/session/recovery logic.
- No complete ASP.NET Core control plane (auth APIs, device registration, session issuance, token revocation, placement) exists yet.
- No PostgreSQL/Redis integration for production session/control state in runtime code.
- No Kubernetes manifests/Helm, autoscaling policies, or release automation artifacts are present in repo for the architecture described above.

### 14.3 Production gap matrix

1. **Protocol hardening gap**
   - Need full handshake transcript binding, replay windows, key epoch tracking, authenticated control frames, and robust parser fuzzing.

2. **Control-plane gap**
   - Need real authN/authZ, tenant-aware policy engine, device attestation, revocation APIs, and signed short-lived grants.

3. **Data-plane gap**
   - Need high-performance UDP packet engine, TCP fallback framing, route management, QoS/limits, and full observability hooks.

4. **Reliability gap**
   - Need multi-region placement, health probes, failover orchestration, rolling/canary deployment support.

5. **Security/compliance gap**
   - Need KMS/HSM key workflows, secret rotation, secure bootstrapping, immutable audit chain, GDPR workflows.

6. **Testing/verification gap**
   - Need unit/integration/perf/chaos tests, interoperability tests, and formal release gates.

### 14.4 What would make it production-capable

Minimum acceptance before production launch:
- End-to-end encrypted tunnel with verified throughput/latency SLOs.
- Complete control plane with device/session/token lifecycle.
- Replay/MITM resistance validated through security testing.
- Multi-region HA with automated failover and on-call alerting.
- Compliance-ready audit, data retention, and deletion workflows.

Until these are implemented and validated, this repository should be treated as **prototype / pre-production foundation**, not a deployable production VPN product.
