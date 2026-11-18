#!/usr/bin/env bash
# Bare-metal / VM gateway installer for Ubuntu 22.04+/Debian 12.
#   sudo BEYOND_GATEWAY_KEY=... ./install-gateway.sh in-mum-1 https://vpn.example.com mum1.vpn.example.com
set -euo pipefail

GW_ID="${1:?gateway id}"
CP_URL="${2:?control plane url (https://...)}"
HOSTNAME_FQDN="${3:?public hostname of this gateway}"
: "${BEYOND_GATEWAY_KEY:?export BEYOND_GATEWAY_KEY first (shown once when the gateway was created)}"
BIN_SRC="${BEYOND_GATEWAY_BIN:-./beyond-gateway}"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
[[ "$CP_URL" == https://* ]] || { echo "control plane URL must be https://"; exit 1; }

apt-get update -y
apt-get install -y wireguard-tools nftables iproute2 certbot unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

install -m 0755 "$BIN_SRC" /usr/local/bin/beyond-gateway
id beyond >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin beyond
install -d -m 0750 /etc/beyondvpn /etc/beyondvpn/blocklists /etc/beyondvpn/tls
[[ -s /etc/beyondvpn/wg.key ]] || (umask 077; wg genkey > /etc/beyondvpn/wg.key)

# TLS for the browser-extension proxy (HTTP-01 on port 80).
certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "$HOSTNAME_FQDN" || echo "WARN: certbot failed; proxy will refuse to start with missing cert"
ln -sf "/etc/letsencrypt/live/$HOSTNAME_FQDN/fullchain.pem" /etc/beyondvpn/tls/fullchain.pem
ln -sf "/etc/letsencrypt/live/$HOSTNAME_FQDN/privkey.pem" /etc/beyondvpn/tls/privkey.pem

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
sed -e "s#^gateway_id = .*#gateway_id = \"$GW_ID\"#" -e "s#^control_plane_url = .*#control_plane_url = \"$CP_URL\"#" \
  "$SCRIPT_DIR/gateway.toml.example" > /etc/beyondvpn/gateway.toml
cp -n "$SCRIPT_DIR/../blocklists/default.txt" /etc/beyondvpn/blocklists/default.txt || true

umask 077
printf 'BEYOND_GATEWAY_KEY=%s\n' "$BEYOND_GATEWAY_KEY" > /etc/beyondvpn/gateway.env
install -m 0755 "$SCRIPT_DIR/../../core/docker/gateway-entrypoint.sh" /usr/local/sbin/beyond-gateway-up

cat > /etc/systemd/system/beyond-gateway.service <<'UNIT'
[Unit]
Description=Beyond VPN gateway
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/beyondvpn/gateway.env
ExecStart=/usr/local/sbin/beyond-gateway-up
Restart=always
RestartSec=3
# Needs CAP_NET_ADMIN for wg/nft; everything else is locked down.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/beyondvpn
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now beyond-gateway
echo "Gateway $GW_ID installed. Open UDP 51820 and TCP 8443 (+80 for certbot renewals) in the firewall."
