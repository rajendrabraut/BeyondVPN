import Foundation

/// Shared between the app and the PacketTunnel extension (both targets compile this file).
public enum Shared {
    public static let appGroup = "group.app.beyondvpn.ios"
    public static let tunnelBundleId = "app.beyondvpn.ios.tunnel"
    /// Key under NETunnelProviderProtocol.providerConfiguration holding the wg-quick text.
    public static let wgQuickKey = "wgQuickConfig"
}

/// Response of POST /api/v1/sessions/connect (control-plane/beyond_cp/schemas.py ConnectOut).
public struct ConnectResponse: Codable, Equatable {
    public struct Policy: Codable, Equatable {
        public var killSwitchRequired: Bool
        public var splitTunnelAllowed: Bool
        enum CodingKeys: String, CodingKey {
            case killSwitchRequired = "kill_switch_required"
            case splitTunnelAllowed = "split_tunnel_allowed"
        }
    }

    public var sessionId: String
    public var address: String
    public var dns: [String]
    public var mtu: Int
    public var peerPublicKey: String
    public var presharedKey: String
    public var endpoint: String
    public var allowedIps: [String]
    public var persistentKeepalive: Int
    public var policy: Policy
    public var exitServerId: String?

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id", address, dns, mtu
        case peerPublicKey = "peer_public_key", presharedKey = "preshared_key", endpoint
        case allowedIps = "allowed_ips", persistentKeepalive = "persistent_keepalive", policy
        case exitServerId = "exit_server_id"
    }
}

/// Renders a wg-quick config. Mirrors core/crates/beyond-common/src/wgconf.rs and the Android builder.
public enum TunnelConfigBuilder {
    /// RFC1918 + link-local + multicast: excluded when "allow LAN" is on.
    public static let lanRanges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"]

    public static func render(privateKey: String, response c: ConnectResponse, allowLan: Bool, excludeRoutes: [String]) throws -> String {
        for v in [privateKey, c.peerPublicKey, c.presharedKey, c.endpoint, c.address] + c.dns + c.allowedIps where !safe(v) {
            throw ConfigError.unsafeValue
        }
        let split = c.policy.splitTunnelAllowed
        var excludes = split ? excludeRoutes : []
        if split && allowLan { excludes += lanRanges }
        let allowed = try excludes.isEmpty ? c.allowedIps : Cidr.subtract(c.allowedIps, excludes)
        var s = "[Interface]\nPrivateKey = \(privateKey)\nAddress = \(c.address)\n"
        if !c.dns.isEmpty { s += "DNS = \(c.dns.joined(separator: ", "))\n" }
        s += "MTU = \(c.mtu)\n\n[Peer]\nPublicKey = \(c.peerPublicKey)\nPresharedKey = \(c.presharedKey)\n"
        s += "AllowedIPs = \(allowed.joined(separator: ", "))\nEndpoint = \(c.endpoint)\nPersistentKeepalive = \(c.persistentKeepalive)\n"
        return s
    }

    /// Reject anything that could inject extra config lines.
    static func safe(_ v: String) -> Bool {
        !v.isEmpty && v.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || "+/=.:-[]_".unicodeScalars.contains($0) }
    }

    public enum ConfigError: Error { case unsafeValue, badCidr(String) }
}

/// IPv4 CIDR subtraction (AllowedIPs minus excluded routes). IPv6 entries pass through.
public enum Cidr {
    struct Net: Equatable {
        var addr: UInt32
        var prefix: Int
        var mask: UInt32 { prefix == 0 ? 0 : ~UInt32(0) << UInt32(32 - prefix) }
        func contains(_ o: Net) -> Bool { o.prefix >= prefix && (o.addr & mask) == addr }
        func overlaps(_ o: Net) -> Bool { contains(o) || o.contains(self) }
        var halves: (Net, Net) {
            let p = prefix + 1
            return (Net(addr: addr, prefix: p), Net(addr: addr | (UInt32(1) << UInt32(32 - p)), prefix: p))
        }
        var description: String {
            "\(addr >> 24 & 255).\(addr >> 16 & 255).\(addr >> 8 & 255).\(addr & 255)/\(prefix)"
        }
    }

    static func parse(_ s: String) throws -> Net {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        let prefix = parts.count == 2 ? Int(parts[1]) : 32
        let octets = parts[0].split(separator: ".").compactMap { UInt32($0) }
        guard let p = prefix, (0...32).contains(p), octets.count == 4, octets.allSatisfy({ $0 <= 255 }) else {
            throw TunnelConfigBuilder.ConfigError.badCidr(s)
        }
        let a = octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]
        let n = Net(addr: 0, prefix: p)
        return Net(addr: a & n.mask, prefix: p)
    }

    public static func subtract(_ allowed: [String], _ excludes: [String]) throws -> [String] {
        let ex = try excludes.map(parse)
        var out: [String] = []
        for a in allowed {
            if a.contains(":") { out.append(a); continue }
            var work = [try parse(a)]
            var keep: [Net] = []
            while let n = work.popLast() {
                if ex.contains(where: { $0.contains(n) }) { continue }
                if !ex.contains(where: { $0.overlaps(n) }) { keep.append(n); continue }
                let (l, r) = n.halves
                work.append(r)
                work.append(l)
            }
            out += keep.sorted { $0.addr < $1.addr }.map(\.description)
        }
        return out
    }
}
