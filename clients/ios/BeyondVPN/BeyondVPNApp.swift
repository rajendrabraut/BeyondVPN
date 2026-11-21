import NetworkExtension
import SwiftUI
import UIKit

@main
struct BeyondVPNApp: App {
    @StateObject private var model = AppModel()
    var body: some Scene {
        WindowGroup { ContentView().environmentObject(model) }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @AppStorage("apiUrl") var apiUrl = ""
    @AppStorage("deviceId") var deviceId = ""
    @AppStorage("email") var email = ""
    @AppStorage("killSwitch") var killSwitch = true
    @AppStorage("allowLan") var allowLan = false
    @AppStorage("exitServer") var exitServer = ""
    @AppStorage("sessionId") private var sessionId = ""

    @Published var servers: [Server] = []
    @Published var selected: String = ""
    @Published var error: String?
    @Published var busy = false
    let tunnel = TunnelManager()
    private var api: ApiClient?

    var loggedIn: Bool { api != nil && !deviceId.isEmpty }

    init() {
        if let url = URL(string: apiUrl), let t = KeyStore.loadTokens(), !deviceId.isEmpty {
            api = ApiClient(base: url, tokens: t)
        }
        Task { await tunnel.load(); await reloadServers() }
    }

    private func run(_ f: @escaping () async throws -> Void) {
        busy = true
        error = nil
        Task {
            do { try await f() } catch { self.error = error.localizedDescription }
            busy = false
        }
    }

    func login(password: String, totp: String) {
        run {
            guard let url = URL(string: self.apiUrl.trimmingCharacters(in: .whitespaces)), url.scheme == "https" || url.host == "127.0.0.1" || url.host == "localhost" else {
                throw ApiError(status: 0, detail: "Server URL must start with https://")
            }
            let api = ApiClient(base: url, tokens: nil)
            try await api.login(email: self.email, password: password, totp: totp.isEmpty ? nil : totp)
            let (_, pub) = try KeyStore.keypair()
            self.deviceId = try await api.registerDevice(name: UIDevice.current.name, publicKey: pub)
            self.api = api
            await self.reloadServers()
        }
    }

    func reloadServers() async {
        guard let api else { return }
        do {
            servers = try await api.servers()
        } catch { self.error = error.localizedDescription }
    }

    func toggle() {
        if tunnel.status == .connected || tunnel.status == .connecting {
            run {
                self.tunnel.stop()
                if let api = self.api, !self.sessionId.isEmpty { try? await api.disconnect(sessionId: self.sessionId) }
                self.sessionId = ""
            }
            return
        }
        run {
            guard let api = self.api else { return }
            let candidates = self.servers.filter(\.online)
            guard let target = candidates.first(where: { $0.id == self.selected }) ?? candidates.min(by: { $0.load < $1.load }) else {
                throw ApiError(status: 503, detail: "No server available")
            }
            let exit = self.exitServer.isEmpty || self.exitServer == target.id ? nil : self.exitServer
            let resp = try await api.connect(deviceId: self.deviceId, serverId: target.id, exitServerId: exit)
            let (priv, _) = try KeyStore.keypair()
            let conf = try TunnelConfigBuilder.render(privateKey: priv, response: resp, allowLan: self.allowLan, excludeRoutes: [])
            self.sessionId = resp.sessionId
            try await self.tunnel.start(wgQuick: conf, serverName: target.name, killSwitch: self.killSwitch || resp.policy.killSwitchRequired)
        }
    }

    func logout() {
        run {
            self.tunnel.stop()
            await self.api?.logout()
            self.api = nil
            self.deviceId = ""
            self.servers = []
        }
    }
}
