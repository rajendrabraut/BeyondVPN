# First real deployment — runbook

Goal: control plane + 2 gateways on real Linux hosts, then real tunnels from every client.
Nothing here has been run on real servers yet; tick each box as you go and note anything that
differs. Time: about half a day.

## 0. What you need

| Item | Example | Notes |
|---|---|---|
| Control-plane VM | 2 vCPU / 4 GB, Ubuntu 24.04 | Docker + Compose plugin |
| 2 gateway VMs | 1–2 vCPU / 1–2 GB, Ubuntu 24.04, **different countries** | kernel ≥ 5.6 (WireGuard built in) |
| DNS | `vpn.example.com` → control plane; `in1.vpn.example.com`, `de1.vpn.example.com` → gateways | A records, before step 1 (Let's Encrypt) |
| Firewall | CP: TCP 80, 443. Gateways: UDP 51820, TCP 80, 8443, (443 if stealth) | cloud security groups too |
| Legal | GUARDRAILS.md §3 | **before real users**: consent text, retention, CERT-In/DPDP |

## 1. Control plane

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git nodejs npm
git clone https://github.com/rajendrabraut/BeyondVPN.git && cd BeyondVPN
cp deploy/.env.example deploy/.env
python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"   # -> BEYOND_SIGNING_KEY
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())" # -> BEYOND_DATA_KEY
nano deploy/.env        # domain, Postgres password, admin email/password, both keys
(cd clients/web && npm ci && npm run build)
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
curl -fsS https://vpn.example.com/healthz
```

- [ ] `healthz` returns OK over HTTPS (Caddy got a certificate).
- [ ] Sign in to `https://vpn.example.com` as the admin; **change the admin password**; remove
      `BEYOND_ADMIN_PASSWORD` from `deploy/.env` and `docker compose up -d` again.
- [ ] Back up `BEYOND_SIGNING_KEY` / `BEYOND_DATA_KEY` in a password manager. Losing the data
      key makes stored WireGuard pre-shared keys and MFA secrets unreadable.
- [ ] Admin → Servers → add `in-mum-1` (hostname `in1.vpn.example.com`) and `de-fra-1`
      (`de1.vpn.example.com`). Copy each **gateway key** (shown once).
- [ ] Optional: SSO — see docs/SSO.md.

## 2. Gateways (repeat per node)

Build the binary once on any Linux x86_64 box (or use `core/Dockerfile.gateway`):

```bash
sudo apt-get install -y build-essential curl && curl https://sh.rustup.rs -sSf | sh -s -- -y
cd BeyondVPN/core && ~/.cargo/bin/cargo build --release -p beyond-gateway
```

On each gateway:

```bash
git clone https://github.com/rajendrabraut/BeyondVPN.git && cd BeyondVPN/deploy/gateway
scp builder:BeyondVPN/core/target/release/beyond-gateway .        # or copy it however you like
sudo BEYOND_GATEWAY_KEY='<key from step 1>' BEYOND_GATEWAY_BIN=./beyond-gateway \
     ./install-gateway.sh in-mum-1 https://vpn.example.com in1.vpn.example.com
sudo journalctl -u beyond-gateway -f
```

- [ ] Log shows `starting` then no `sync failed` lines.
- [ ] Admin → Servers shows the node **online** within 30 s.
- [ ] `sudo wg show wg0` lists the interface; `sudo nft list ruleset` shows `table inet beyond`.
- [ ] Each gateway has its own `tunnel_cidr` only if you plan to route between them; the
      default `10.8.0.0/22` everywhere is fine (multi-hop NATs on the entry).

## 3. Real tunnels — client matrix

Create a normal user account (not the admin) in the portal and accept the logging notice.

| Client | How | Pass when |
|---|---|---|
| Windows | Install WireGuard for Windows, then `beyond-agent login --api https://vpn.example.com --email you@…` and `beyond-agent connect` from an **elevated** prompt (or the desktop app + `beyond-agent serve` service) | `beyond-agent status` shows a handshake; https://ifconfig.me shows the gateway IP |
| macOS / Linux | `brew install wireguard-tools` / `apt install wireguard-tools`, same agent commands with `sudo` | same |
| Android | Install the APK from the CI artifact (`beyondvpn-android-debug`), sign in, Connect | key icon in status bar; ifconfig.me = gateway IP |
| iOS | Until the native app is built (clients/ios/README.md): portal → Devices → *Add device* → scan the QR with the WireGuard app | same |
| Browser extension | Load `clients/extension` unpacked, sign in, Connect | browser shows gateway IP; other apps do not |

For each: [ ] DNS goes through the gateway (`nslookup example.com` → server 10.8.0.1),
[ ] a domain from the admin blocklist does not resolve, [ ] the portal Activity page shows the
domains and data usage within ~1 minute, [ ] Disconnect restores normal traffic,
[ ] kill switch: stop the gateway service while connected — traffic must stop, not leak.

## 4. Multi-hop

```bash
beyond-agent set --exit-server de-fra-1
beyond-agent connect --server in-mum-1
curl https://ifconfig.me          # must print the de-fra-1 public IP
```

- [ ] On in-mum-1: `ip rule | grep 51001` shows the client's tunnel IP; `wg show bhop1` has a handshake.
- [ ] On de-fra-1: `wg show wg0` lists in-mum-1's hop key as a peer.
- [ ] `beyond-agent set --exit-server ""` + reconnect removes the rule.

## 5. Stealth (anti-blocking) mode

On one gateway set `[stealth] enabled = true` in `/etc/beyondvpn/gateway.toml`, open TCP 443,
`sudo systemctl restart beyond-gateway`. Admin → Servers should show the stealth port.

```bash
curl -sk https://in1.vpn.example.com/            # must look like a plain nginx 404
beyond-agent set --stealth true && beyond-agent connect --server in-mum-1
```

- [ ] Works on a network that blocks UDP (e.g. phone hotspot with a UDP-blocking firewall rule,
      or `sudo iptables -A OUTPUT -p udp --dport 51820 -j DROP` on the client).
- [ ] Windows note: with stealth on, WireGuard-NT's built-in kill switch does not apply
      (AllowedIPs no longer contains 0.0.0.0/0). Known limitation.

## 6. Sign-off

- [ ] All boxes above ticked on at least Windows + Android + one browser.
- [ ] Load: 50 concurrent test peers on one gateway for 1 hour without sync errors.
- [ ] Update `THINGS_REMAINING.md` item 1 with the date and anything that broke.
