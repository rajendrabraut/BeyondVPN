# FortiClient-Clone VPN - Open Source

Free, open-source server-client VPN platform inspired by FortiClient.

**Architecture:**
- **Backend**: .NET 8 gRPC (dotnet rpc) – manages auth, profiles, free VPN servers
- **Frontend Web**: React + Vite + TypeScript + Tailwind
- **Desktop**: Electron + React (Windows/macOS/Linux)
- **Mobile**: React Native (Expo) for Android

Uses only free OSS tools: WireGuard, OpenVPN, gRPC, .NET, Node.js

## Quick Start

### 1. Backend (.NET 8)
```bash
cd backend/VpnServer
dotnet restore
dotnet run
# gRPC on https://localhost:5001, REST gateway on http://localhost:5000
```

### 2. Web Frontend
```bash
cd frontend/web
npm install
npm run dev
```

### 3. Desktop (Electron)
```bash
cd frontend/desktop
npm install
npm run dev
```

### 4. Android
```bash
cd frontend/mobile
npm install
npx expo start
```

## How it works like FortiClient
1. User logs in to central server
2. Server returns curated free VPN profiles (WireGuard + OpenVPN)
3. Client downloads config and starts local tunnel
4. Desktop uses native wg-quick/openvpn; Android uses VpnService intent; Web shows status only

**Free VPN sources integrated:**
- WireGuard configs (self-hosted or public like VPN Gate, ProtonVPN Free manual)
- OpenVPN community servers
- You can add your own .conf/.ovpn in backend/Data/ServerRepository.cs

> Legal: Only use free servers you have permission for. This is a management client, not a VPN provider.
