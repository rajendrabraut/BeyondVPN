import NetworkExtension
import WireGuardKit
import os

/// Runs inside the Network Extension process. All crypto and packet handling is the
/// official WireGuardKit (wireguard-go); we only hand it the config written by the app.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "app.beyondvpn.ios.tunnel", category: "tunnel")

    private lazy var adapter = WireGuardAdapter(with: self) { [weak self] level, message in
        self?.log.log(level: level == .error ? .error : .debug, "\(message, privacy: .public)")
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let text = proto.providerConfiguration?[Shared.wgQuickKey] as? String,
              let config = try? TunnelConfiguration(fromWgQuickConfig: text, called: "beyond0")
        else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        adapter.start(tunnelConfiguration: config) { [weak self] error in
            if let error {
                self?.log.error("start failed: \(String(describing: error), privacy: .public)")
            }
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        adapter.stop { _ in completionHandler() }
    }

    /// The app asks for byte counters with an empty message.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        adapter.getRuntimeConfiguration { settings in
            var rx = 0, tx = 0
            for line in (settings ?? "").split(separator: "\n") {
                if line.hasPrefix("rx_bytes=") { rx += Int(line.dropFirst(9)) ?? 0 }
                if line.hasPrefix("tx_bytes=") { tx += Int(line.dropFirst(9)) ?? 0 }
            }
            completionHandler?(try? JSONSerialization.data(withJSONObject: ["rx": rx, "tx": tx]))
        }
    }
}
