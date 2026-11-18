#!/bin/sh
# Brings up wg0 + NAT, then runs beyond-gateway. Needs NET_ADMIN and host networking.
set -eu

: "${BEYOND_GATEWAY_KEY:?BEYOND_GATEWAY_KEY is required}"
CONF="${BEYOND_GATEWAY_CONFIG:-/etc/beyondvpn/gateway.toml}"
KEYFILE="${BEYOND_WG_KEY_FILE:-/etc/beyondvpn/wg.key}"
CIDR="${BEYOND_TUNNEL_CIDR:-10.8.0.0/22}"
GW_IP="${BEYOND_TUNNEL_GW:-10.8.0.1}"
PORT="${BEYOND_WG_PORT:-51820}"
WAN="${BEYOND_WAN_IF:-$(ip route show default | awk '{print $5; exit}')}"

umask 077
mkdir -p "$(dirname "$KEYFILE")"
[ -s "$KEYFILE" ] || wg genkey > "$KEYFILE"

ip link show wg0 >/dev/null 2>&1 || ip link add wg0 type wireguard
wg set wg0 private-key "$KEYFILE" listen-port "$PORT"
ip address replace "$GW_IP/${CIDR#*/}" dev wg0
ip link set wg0 up mtu 1420

sysctl -qw net.ipv4.ip_forward=1 || true

# NAT + isolation: clients may reach the internet and the gateway resolver,
# but not each other (client isolation) nor the gateway's private networks.
nft -f - <<EOF
table inet beyond
delete table inet beyond
table inet beyond {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" oifname "wg0" drop
    iifname "wg0" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } drop
    iifname "wg0" oifname "$WAN" accept
  }
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "wg0" udp dport 53 accept
    iifname "wg0" tcp dport 53 accept
    iifname "wg0" ip daddr $GW_IP drop
  }
}
table ip beyond_nat
delete table ip beyond_nat
table ip beyond_nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr $CIDR oifname "$WAN" masquerade
  }
}
EOF

exec beyond-gateway run --config "$CONF"
