# Beyond VPN for iOS / iPadOS

SwiftUI app + Network Extension (packet tunnel) using the official
[WireGuardKit](https://git.zx2c4.com/wireguard-apple) for the data plane.
Same control-plane API as the Android and desktop clients.

> **Status: source only.** This code was written on Windows and has **not been compiled or
> run**. Expect a short round of Xcode fixes on first build. The config builder is covered
> by `Tests/TunnelConfigTests.swift`.

## What it does

- Sign in (email/password + TOTP), register the device's WireGuard key (Curve25519 from CryptoKit,
  stored in the Keychain, this-device-only).
- Server list with load, "fastest" pick, **multi-hop exit** picker.
- Connect/disconnect via `NETunnelProviderManager`; **kill switch** = `includeAllNetworks`.
- Allow-LAN split tunnel (same CIDR subtraction as `beyond-common/src/wgconf.rs`).
- Live byte counters from the extension.

Not yet on iOS: stealth (TLS/443) mode — that needs the `beyond-stealth` relay inside the
extension (planned via UniFFI bindings to the Rust crate). SSO sign-in (open
`/api/v1/auth/sso/{provider}/start?return_to=beyondvpn://sso` in `ASWebAuthenticationSession`,
then POST the `sso_code` to `/api/v1/auth/sso/exchange`) is also still to wire up.

## Build (on a Mac)

1. Xcode 16+, an Apple Developer account (Network Extension entitlement is granted to all
   paid accounts), Go 1.22+ (`brew install go`) — WireGuardKit compiles wireguard-go.
2. `brew install xcodegen && cd clients/ios && xcodegen generate`
3. Open `BeyondVPN.xcodeproj`, set your Team on both targets, and make sure the App Group
   `group.app.beyondvpn.ios` exists in your account (or rename it in `Shared/TunnelConfig.swift`
   and both `.entitlements` files).
4. WireGuardKit needs its Go bridge built once: add an **External Build System** target
   named `WireGuardGoBridgeiOS` that runs `make` in
   `$(BUILD_DIR)/../../SourcePackages/checkouts/wireguard-apple/Sources/WireGuardKitGo`, and make
   the `PacketTunnel` target depend on it (this is the documented WireGuardKit setup).
5. Run on a real device (Network Extensions do not run in the Simulator).

## App Store notes

- Declare encryption use (`ITSAppUsesNonExemptEncryption = YES`) and file the annual
  self-classification report (WireGuard uses standard algorithms).
- The privacy label must list "Browsing History" (DNS domains) as collected and linked to the
  user when the control plane runs in `full` logging mode.
