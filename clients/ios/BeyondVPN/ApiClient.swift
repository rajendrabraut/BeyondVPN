import Foundation

struct Server: Codable, Identifiable, Hashable {
    var id: String
    var name: String
    var country: String
    var city: String
    var load: Double
    var status: String
    var features: [String]
    var stealthPort: Int?
    var multihopEntry: Bool?

    var online: Bool { status == "online" }
    var flag: String {
        country.uppercased().unicodeScalars.compactMap { UnicodeScalar(127_397 + $0.value) }.map(String.init).joined()
    }

    enum CodingKeys: String, CodingKey {
        case id, name, country, city, load, status, features
        case stealthPort = "stealth_port", multihopEntry = "multihop_entry"
    }
}

struct Tokens: Codable {
    var accessToken: String
    var refreshToken: String
    enum CodingKeys: String, CodingKey { case accessToken = "access_token", refreshToken = "refresh_token" }
}

struct ApiError: LocalizedError {
    var status: Int
    var detail: String
    var errorDescription: String? { detail }
}

/// Control-plane client. Tokens live in the Keychain (see KeyStore); never in UserDefaults.
actor ApiClient {
    let base: URL
    private let session: URLSession
    private var tokens: Tokens?

    init(base: URL, tokens: Tokens?) {
        self.base = base
        self.tokens = tokens
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 20
        cfg.httpCookieStorage = nil
        session = URLSession(configuration: cfg)
    }

    var currentTokens: Tokens? { tokens }

    private func request(_ method: String, _ path: String, body: [String: Any?]? = nil, auth: Bool = true) async throws -> Data {
        func build() throws -> URLRequest {
            var r = URLRequest(url: base.appendingPathComponent("api/v1").appendingPathComponent(path))
            r.httpMethod = method
            if let body {
                r.setValue("application/json", forHTTPHeaderField: "Content-Type")
                r.httpBody = try JSONSerialization.data(withJSONObject: body.mapValues { $0 ?? NSNull() })
            }
            if auth, let t = tokens?.accessToken { r.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
            return r
        }
        var (data, resp) = try await session.data(for: build())
        var code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if code == 401, auth, try await refresh() {
            (data, resp) = try await session.data(for: build())
            code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        }
        guard (200..<300).contains(code) else {
            let detail = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["detail"] as? String
            throw ApiError(status: code, detail: detail ?? HTTPURLResponse.localizedString(forStatusCode: code))
        }
        return data
    }

    private func refresh() async throws -> Bool {
        guard let rt = tokens?.refreshToken else { return false }
        var r = URLRequest(url: base.appendingPathComponent("api/v1/auth/refresh"))
        r.httpMethod = "POST"
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = try JSONSerialization.data(withJSONObject: ["refresh_token": rt])
        let (data, resp) = try await session.data(for: r)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            tokens = nil
            return false
        }
        tokens = try JSONDecoder().decode(Tokens.self, from: data)
        try KeyStore.saveTokens(tokens)
        return true
    }

    func login(email: String, password: String, totp: String?) async throws {
        let data = try await request("POST", "auth/login", body: ["email": email, "password": password, "totp_code": totp], auth: false)
        tokens = try JSONDecoder().decode(Tokens.self, from: data)
        try KeyStore.saveTokens(tokens)
    }

    func registerDevice(name: String, publicKey: String) async throws -> String {
        let posture: [String: Any] = ["os": "ios", "app_version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"]
        let data = try await request("POST", "devices", body: ["name": name, "platform": "ios", "public_key": publicKey, "posture": posture])
        return (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["id"] as? String ?? ""
    }

    func servers() async throws -> [Server] {
        try JSONDecoder().decode([Server].self, from: try await request("GET", "servers"))
    }

    func connect(deviceId: String, serverId: String, exitServerId: String?) async throws -> ConnectResponse {
        let data = try await request("POST", "sessions/connect", body: ["device_id": deviceId, "server_id": serverId, "exit_server_id": exitServerId])
        return try JSONDecoder().decode(ConnectResponse.self, from: data)
    }

    func disconnect(sessionId: String) async throws {
        _ = try await request("POST", "sessions/\(sessionId)/disconnect")
    }

    func logout() async {
        if let rt = tokens?.refreshToken {
            _ = try? await request("POST", "auth/logout", body: ["refresh_token": rt], auth: false)
        }
        tokens = nil
        try? KeyStore.saveTokens(nil)
    }
}
