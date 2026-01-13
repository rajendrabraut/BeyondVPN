# BeyondVPN

This repository contains the BeyondVPN multi-platform codebase:

- `VpnApp.WinForms`: single WinForms UI that can run in Client or Server mode.
- `VpnCore`: shared protocol, crypto, and common utilities.
- `VpnServer.Linux`: Linux daemon that reverse-connects to a relay.
- `VpnRelay`: public relay component for CGNAT-safe connectivity.
- `VpnCli`: small diagnostics CLI.

> Note: WSS termination is expected via a reverse proxy (nginx, Caddy, or Traefik) in front of `VpnRelay`. The relay only bridges encrypted payloads.
