# Beyond VPN — Operations Runbook

## 1. Deploy the control plane (Docker)

Prerequisites: Linux VM with Docker, DNS `A` record `vpn.example.com` → VM, ports 80/443 open.

1. Build the portal: `cd clients/web && npm ci && npm run build`.
2. `cp deploy/.env.example deploy/.env` and set `BEYOND_DOMAIN`, `POSTGRES_PASSWORD`, admin e-mail/password, and generate `BEYOND_SIGNING_KEY` / `BEYOND_DATA_KEY` (commands in the file). Store the two keys in your secret manager too.
3. `docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build`
4. Open `https://vpn.example.com`, sign in as admin, **enable 2FA**, then remove `BEYOND_ADMIN_PASSWORD` from `.env` and `docker compose up -d` again.
5. Policy page: choose logging mode and retention per GUARDRAILS.md §3.

## 2. Add a gateway

1. Admin console → Gateways → Add (id e.g. `in-mum-1`, hostname `mum1.vpn.example.com`, country, tunnel CIDR unique per gateway is **not** required — each gateway has its own address space, default `10.8.0.0/22`). Copy the one-time gateway key.
   CLI alternative: `docker compose exec control-plane python -m beyond_cp.cli create-server --id in-mum-1 --name "Mumbai 1" --country IN --hostname mum1.vpn.example.com`.
2. On a fresh Ubuntu 22.04+/Debian 12 host with DNS pointing at it:
   ```bash
   cd core && cargo build --release -p beyond-gateway
   ```
   ```bash
   sudo BEYOND_GATEWAY_KEY=<key> BEYOND_GATEWAY_BIN=core/target/release/beyond-gateway deploy/gateway/install-gateway.sh in-mum-1 https://vpn.example.com mum1.vpn.example.com
   ```
   or with Docker: copy/edit `deploy/gateway/gateway.toml`, then `BEYOND_GATEWAY_KEY=<key> docker compose -f deploy/gateway/docker-compose.yml up -d --build`.
3. Firewall: allow UDP 51820, TCP 8443, TCP 80 (certificate renewal).
4. The gateway shows **online** in the console within ~10 s.

## 3. Install clients

| Platform | Steps |
|---|---|
| Windows | Install WireGuard for Windows → run `deploy/agent/install-windows.ps1` (admin) with `beyond-agent.exe` → install the Beyond VPN desktop app → sign in. |
| Linux | Install `wireguard-tools` + `nftables`; copy `beyond-agent` to `/usr/local/bin`; install `deploy/agent/beyond-agent.service`; add user to group `beyondvpn`; run the desktop app or use the CLI (`beyond-agent login …`, `connect`). |
| macOS | `brew install wireguard-tools`; run `sudo beyond-agent serve` (launchd plist: P0 backlog) and the desktop app, or use the WireGuard app with a portal config. |
| Android | Install the APK (or Play build) → sign in → Connect → optionally enable Always-on + Block connections without VPN. |
| iOS / iPadOS / routers | Portal → Devices → Add device → scan QR with the WireGuard app / import `.conf`. |
| Browsers | Install the extension → enter `https://vpn.example.com` → sign in → Connect. |

## 4. Routine tasks

| Task | How |
|---|---|
| Disable a user | Admin → Users → Disable (sessions end, gateways drop peers within one sync) |
| Set a data cap | Admin → Users → Data cap |
| Block a domain for everyone | Admin → Policy → Blocked domains → Save |
| Investigate activity | Admin → Logs (filters, CSV export); every access is audited |
| Verify audit integrity | Admin → Audit → Verify, or `python -m beyond_cp.cli verify-audit` (cron + alert) |
| Purge logs now | `python -m beyond_cp.cli purge-logs` |
| Rotate a gateway key | Admin API `POST /api/v1/admin/servers/{id}/rotate-key`, update `/etc/beyondvpn/gateway.env`, restart service |
| Maintenance mode | Admin → Gateways → Maintenance (clients stop selecting it) |

## 5. Backup & restore

- PostgreSQL: daily `pg_dump` (or managed PITR); keep 30 days.
- Keys: `BEYOND_SIGNING_KEY`, `BEYOND_DATA_KEY` in secret manager + offline copy. Without the data key, PSKs and MFA secrets cannot be decrypted (users must re-enrol MFA; peers get new PSKs after deleting `peers` rows).
- Gateways are stateless apart from `/etc/beyondvpn/wg.key` (re-generating it is fine; clients get the new public key on next connect).

## 6. Incident response (summary)

1. Suspected gateway compromise → set Maintenance, rotate key, destroy VM, re-provision; review audit + logs for the window.
2. Suspected account takeover → disable user, force MFA, review `auth.*` audit events (`auth.refresh_reuse_detected` is a strong signal).
3. Report to CERT-In within 6 hours where applicable (India) and to data-protection authorities per GDPR/DPDP timelines.

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| Server shows offline | Gateway logs (`journalctl -u beyond-gateway`), outbound HTTPS to control plane, gateway key |
| Connected but no internet | `sysctl net.ipv4.ip_forward`, `nft list ruleset` (masquerade on WAN iface), MTU (try 1380) |
| DNS not resolving | Gateway listening on `10.8.0.1:53`, upstream DoH reachable |
| Extension says 407 loop | Token audience mismatch (wrong gateway id) or user disabled/over cap |
| Desktop app "service not running" | `beyond-agent serve` running elevated? token file present in agent dir? |
