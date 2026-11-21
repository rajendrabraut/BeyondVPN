import Foundation
import NetworkExtension

/// Installs/starts the PacketTunnel extension through NETunnelProviderManager.
@MainActor
final class TunnelManager: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var rx = 0
    @Published private(set) var tx = 0
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    func load() async {
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = all.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Shared.tunnelBundleId }
        status = manager?.connection.status ?? .invalid
        if let m = manager { watch(m) }
    }

    private func watch(_ m: NETunnelProviderManager) {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: m.connection, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.status = m.connection.status }
        }
    }

    /// Save the config (iOS asks the user once to allow adding a VPN) and start it.
    func start(wgQuick: String, serverName: String, killSwitch: Bool) async throws {
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Shared.tunnelBundleId
        proto.serverAddress = serverName
        proto.providerConfiguration = [Shared.wgQuickKey: wgQuick]
        // Kill switch: keep all traffic inside the tunnel, including while it reconnects.
        proto.includeAllNetworks = killSwitch
        proto.excludeLocalNetworks = !killSwitch
        m.protocolConfiguration = proto
        m.localizedDescription = "Beyond VPN"
        m.isEnabled = true
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
        manager = m
        watch(m)
        try m.connection.startVPNTunnel()
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    func refreshCounters() {
        guard let session = manager?.connection as? NETunnelProviderSession, status == .connected else { return }
        try? session.sendProviderMessage(Data()) { [weak self] data in
            guard let data, let o = try? JSONSerialization.jsonObject(with: data) as? [String: Int] else { return }
            Task { @MainActor in
                self?.rx = o["rx"] ?? 0
                self?.tx = o["tx"] ?? 0
            }
        }
    }
}
