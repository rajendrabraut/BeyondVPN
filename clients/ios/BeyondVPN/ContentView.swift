import NetworkExtension
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        NavigationStack {
            Group {
                if model.loggedIn { MainView(tunnel: model.tunnel) } else { LoginView() }
            }
            .navigationTitle("Beyond VPN")
        }
    }
}

struct LoginView: View {
    @EnvironmentObject var model: AppModel
    @State private var password = ""
    @State private var totp = ""
    var body: some View {
        Form {
            Section("Account") {
                TextField("Server URL (https://…)", text: $model.apiUrl).textInputAutocapitalization(.never).keyboardType(.URL)
                TextField("Email", text: $model.email).textInputAutocapitalization(.never).keyboardType(.emailAddress).textContentType(.username)
                SecureField("Password", text: $password).textContentType(.password)
                TextField("Authenticator code (if enabled)", text: $totp).keyboardType(.numberPad).textContentType(.oneTimeCode)
            }
            if let e = model.error { Text(e).foregroundStyle(.red) }
            Button(model.busy ? "Signing in…" : "Sign in") { model.login(password: password, totp: totp) }
                .disabled(model.busy || model.apiUrl.isEmpty || model.email.isEmpty || password.isEmpty)
            Text("While connected, this service records your data usage and the domains you visit, as described in the privacy policy you accepted when you created your account.")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }
}

struct MainView: View {
    @EnvironmentObject var model: AppModel
    /// Observed directly so status/counter changes re-render this view.
    @ObservedObject var tunnel: TunnelManager
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        let t = tunnel
        Form {
            Section {
                VStack(spacing: 8) {
                    Image(systemName: t.status == .connected ? "lock.shield.fill" : "shield.slash")
                        .font(.system(size: 56)).foregroundStyle(t.status == .connected ? .green : .secondary)
                    Text(label(t.status)).font(.headline)
                    if t.status == .connected {
                        Text("↓ \(bytes(t.rx))   ↑ \(bytes(t.tx))").font(.footnote).foregroundStyle(.secondary)
                    }
                }.frame(maxWidth: .infinity).padding(.vertical, 8)
                Button(t.status == .connected || t.status == .connecting ? "Disconnect" : "Connect") { model.toggle() }
                    .buttonStyle(.borderedProminent).frame(maxWidth: .infinity).disabled(model.busy)
            }
            Section("Location") {
                Picker("Server", selection: $model.selected) {
                    Text("⚡ Fastest").tag("")
                    ForEach(model.servers) { s in Text("\(s.flag) \(s.name) · \(Int(s.load * 100))%").tag(s.id).disabled(!s.online) }
                }
                Picker("Multi-hop exit", selection: $model.exitServer) {
                    Text("Off").tag("")
                    ForEach(model.servers.filter(\.online)) { s in Text("\(s.flag) \(s.name)").tag(s.id) }
                }
            }
            Section("Protection") {
                Toggle("Kill switch", isOn: $model.killSwitch)
                Toggle("Allow local network", isOn: $model.allowLan)
            }
            if let e = model.error { Text(e).foregroundStyle(.red) }
            Button("Sign out \(model.email)", role: .destructive) { model.logout() }
        }
        .refreshable { await model.reloadServers() }
        .onReceive(timer) { _ in t.refreshCounters() }
    }

    private func label(_ s: NEVPNStatus) -> String {
        switch s {
        case .connected: return "Protected"
        case .connecting, .reasserting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        default: return "Not protected"
        }
    }

    private func bytes(_ n: Int) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .binary) }
}
