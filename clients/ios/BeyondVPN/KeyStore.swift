import CryptoKit
import Foundation
import Security

/// Keychain storage (this-device-only, after first unlock) for the WireGuard key and API tokens.
enum KeyStore {
    private static let service = "app.beyondvpn.ios"

    private static func set(_ account: String, _ data: Data?) throws {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        SecItemDelete(q as CFDictionary)
        guard let data else { return }
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(st)) }
    }

    private static func get(_ account: String) -> Data? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account, kSecReturnData as String: true]
        var out: AnyObject?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    /// WireGuard keypair (Curve25519), created once per install. Returns (private, public) base64.
    static func keypair() throws -> (String, String) {
        if let raw = get("wg.private"), let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw) {
            return (raw.base64EncodedString(), k.publicKey.rawRepresentation.base64EncodedString())
        }
        let k = Curve25519.KeyAgreement.PrivateKey()
        try set("wg.private", k.rawRepresentation)
        return (k.rawRepresentation.base64EncodedString(), k.publicKey.rawRepresentation.base64EncodedString())
    }

    static func saveTokens(_ t: Tokens?) throws { try set("tokens", t.map { try JSONEncoder().encode($0) }) }
    static func loadTokens() -> Tokens? { get("tokens").flatMap { try? JSONDecoder().decode(Tokens.self, from: $0) } }
}
