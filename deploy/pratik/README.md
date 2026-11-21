# Running the gateway on Pratik

[Pratik](../../../../Pratik) is our own lightweight container engine (Rust, tiny Alpine-based VM).
This folder runs `beyond-gateway` in a Pratik container with **real kernel WireGuard**, so a
gateway can be tested on a Windows PC without a Linux server.

```
Windows: WireGuard client ──UDP 127.0.0.1:51820──▶ QEMU ──▶ VM nft DNAT ──▶ container wg0 (beyond-gateway)
                                                                              │
Windows: control plane 127.0.0.1:8000 ◀──── http://control-plane:8000 (10.0.2.2) ┘
```

## 1. Build the gateway for Linux (static musl)

```powershell
winget install zig.zig
cargo install cargo-zigbuild --locked
cd core
cargo zigbuild --release -p beyond-gateway --target x86_64-unknown-linux-musl
```

## 2. Control plane on Windows

```powershell
control-plane\.venv\Scripts\python.exe tests\e2e\pratik_tunnel.py control-plane   # keep running
```

It creates server `pratik-1` and writes its gateway key to `%TEMP%\beyond-pratik-demo\gateway.key`.

## 3. Gateway image + container

```powershell
pratik vm start
pratik mkimage beyond-gateway:0.2 --packages wireguard-tools-wg,nftables,iproute2 `
  --add core\target\x86_64-unknown-linux-musl\release\beyond-gateway:/usr/local/bin/beyond-gateway:755 `
  --add core\docker\gateway-entrypoint.sh:/usr/local/bin/gateway-up:755 `
  --add deploy\pratik\gateway.toml:/etc/beyondvpn/gateway.toml `
  --add deploy\blocklists\default.txt:/etc/beyondvpn/blocklists/default.txt `
  --cmd /usr/local/bin/gateway-up
pratik run -d --name gw --restart --cap-add NET_ADMIN -p 51820:51820/udp `
  --add-host control-plane:10.0.2.2 -e BEYOND_GATEWAY_KEY=<key> beyond-gateway:0.2
pratik logs gw
```

## 4. Client tunnel (split: only 10.8.0.1 goes through it)

```powershell
control-plane\.venv\Scripts\python.exe tests\e2e\pratik_tunnel.py client
# elevated: & 'C:\Program Files\WireGuard\wireguard.exe' /installtunnelservice $env:TEMP\beyond-pratik-demo\bvpnpratik.conf
nslookup example.com 10.8.0.1        # DNS answered by the gateway through the tunnel
control-plane\.venv\Scripts\python.exe tests\e2e\pratik_tunnel.py activity   # the lookup is logged
# elevated: & 'C:\Program Files\WireGuard\wireguard.exe' /uninstalltunnelservice bvpnpratik
```
