# Beyond VPN — Execution

How the work was carried out and how to reproduce every build and test.

## 1. Execution log (2026-11-18)

| Step | Action | Result |
|---|---|---|
| 1 | Checked toolchain: Rust 1.100 (GNU), Python 3.13, Node 24, JDK 17, Android SDK 35–37, Gradle 8.14.3 cache, Docker (daemon not running), no WireGuard installed | Environment suitable for all builds except live tunnels |
| 2 | Cloned `rajendrabraut/BeyondVPN` and `rajendrabraut/FortiClientVPN_Clone`; reviewed both | BeyondVPN = .NET 8 prototype with custom crypto over WebSocket; Forti clone = React web + Electron + Expo Android delegating to external VPN apps |
| 3 | Created branch `beyond-v2`; moved .NET code to `legacy/dotnet`; subtree-merged Forti clone into `legacy/forticlone` keeping history | Single monorepo, nothing lost |
| 4 | Built `beyond-common` (keys, tokens, CIDR, wg config, DNS, blocklist, telemetry, wg dump) | 27 tests pass |
| 5 | Built `beyond-gateway` (config, state, control-plane client, wg reconcile, DNS server, proxy) | 11 tests incl. full proxy e2e (auth, block, SSRF, tunnel, revocation) |
| 6 | Built `beyond-agent` (store, API client, engine, backends, local API, CLI) | 6 tests |
| 7 | Built control plane (models, security, audit, policy, IPAM, 5 routers, CLI) | 30 tests |
| 8 | Built web portal (React/TS) and MV3 extension | 5 + 6 tests; `tsc` strict + Vite build OK |
| 9 | Built Electron desktop UI and Android app | 4 tests; Android 7 tests + debug APK (18.1 MB) |
| 10 | Wrote cross-language e2e (`tests/e2e/run_e2e.py`) | **Found 2 bugs** (see PROGRESS.md §3), fixed, e2e passes |
| 11 | Deployment artefacts, CI workflow, clippy `-D warnings` clean | Done |
| 12 | Documentation set | This file and siblings |

## 2. Build & test commands

All commands from the repository root. Windows paths shown; on Linux/macOS replace `.venv\Scripts\` with `.venv/bin/`.

### Rust core
```bash
cd core && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo build --workspace
```

### Control plane
```bash
cd control-plane && python -m venv .venv && .venv\Scripts\pip install -e ".[test]" && .venv\Scripts\pytest -q
```
Run locally: `.venv\Scripts\uvicorn beyond_cp.main:create_app --factory --port 8000` → API docs at `http://127.0.0.1:8000/docs`.

### End-to-end (needs the two steps above)
```bash
control-plane\.venv\Scripts\python tests\e2e\run_e2e.py
```
Starts the control plane, a dry-run Rust gateway (real DNS + proxy, no kernel WireGuard) and the Rust agent in dry-run mode, then verifies login → device registration → connect → peer sync → Python-issued token accepted by Rust proxy → DNS sinkhole from admin policy → log upload → disconnect → audit chain.

### Web portal
```bash
cd clients/web && npm install && npm test && npm run build
```

### Browser extension
```bash
cd clients/extension && npm test && npm run check && npm run package:chrome && npm run package:firefox
```
Load `clients/extension/dist/chrome` via `chrome://extensions` → Developer mode → Load unpacked.

### Desktop UI
```bash
cd clients/desktop && npm test && npm install && npm start
```
Requires `beyond-agent serve` running (as Administrator/root because it manages tunnels).

### Android
```bash
cd clients/android && gradlew.bat --no-daemon testDebugUnitTest assembleDebug
```
APK: `clients/android/app/build/outputs/apk/debug/app-debug.apk`. Requires `local.properties` with `sdk.dir` (created automatically by Android Studio).

## 3. Automation

`.github/workflows/ci.yml` runs on every push/PR: clippy + tests on Linux/Windows/macOS, control-plane tests, the e2e scenario, web/extension/desktop tests and build, Android unit tests + APK artefact.

## 4. What was *not* executed and why

| Item | Reason | How to execute |
|---|---|---|
| Real WireGuard tunnel on this machine | WireGuard for Windows not installed; would require admin rights and changes network settings | Install WireGuard, run `beyond-agent serve` elevated, connect to a real gateway |
| Gateway on a Linux host with kernel WG | No Linux server available; Docker daemon not running | `deploy/gateway/install-gateway.sh` on Ubuntu 22.04+ |
| `docker compose up` | Docker daemon not running | See docs/OPERATIONS.md |
| Electron runtime launch | Electron binary (~100 MB) not downloaded; UI logic tested via agent-client tests | `npm install && npm start` |
| Android on device/emulator | No device attached | `adb install app-debug.apk` |
