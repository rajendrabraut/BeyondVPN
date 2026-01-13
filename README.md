# BeyondVPN

This repository contains the BeyondVPN multi-platform codebase. The solution is intentionally small and split into four projects:

- `VpnApp.WinForms`: single WinForms UI that can run in Client or Server mode.
- `VpnCore`: shared protocol, crypto, and common utilities.
- `VpnServer.Linux`: Linux daemon that reverse-connects to a relay.
- `VpnRelay`: public relay component for CGNAT-safe connectivity.

> Note: WSS termination is expected via a reverse proxy (nginx, Caddy, or Traefik) in front of `VpnRelay`. The relay only bridges encrypted payloads.

## Design intent
- The tunnel transports raw IP packets (Layer-3) over encrypted WSS.
- Clients (desktop, web, or mobile) can reach server-side resources once routed through the VPN.
- The relay never decrypts payloads; end-to-end encryption is handled by client and server.

## Where to start
- Build and run `VpnRelay` on a public VPS (443 via reverse proxy).
- Run `VpnServer.Linux` behind CGNAT; it connects out to the relay.
- Run `VpnApp.WinForms` in Client mode to connect to the same relay session.

## Publish & run
### Relay (public VPS)
```bash
dotnet publish VpnRelay/VpnRelay.csproj -c Release -o out/relay
./out/relay/VpnRelay --urls http://0.0.0.0:8080
```
Terminate TLS/WSS at your reverse proxy on port 443 and forward to `http://127.0.0.1:8080/relay`.

### Linux server (behind CGNAT)
```bash
dotnet publish VpnServer.Linux/VpnServer.Linux.csproj -c Release -o out/server
VPN_RELAY="wss://relay.example.com/relay?role=server&session=myvpn" ./out/server/VpnServer.Linux
```

### Windows app (Client or Server mode)
Open `VpnSuite.sln` in Visual Studio 2022 and publish `VpnApp.WinForms` for `net48`.

At runtime:
- Set **Mode = Client** and connect to `wss://relay.example.com/relay?role=client&session=myvpn`
- Or set **Mode = Server** and connect to the relay as a server session
