import XCTest
@testable import BeyondVPN

final class TunnelConfigTests: XCTestCase {
    private func response(split: Bool = true) -> ConnectResponse {
        ConnectResponse(
            sessionId: "s1", address: "10.8.0.2/32", dns: ["10.8.0.1"], mtu: 1420,
            peerPublicKey: "PUBKEY+/=", presharedKey: "PSK+/=", endpoint: "gw.example.com:51820",
            allowedIps: ["0.0.0.0/0", "::/0"], persistentKeepalive: 25,
            policy: .init(killSwitchRequired: false, splitTunnelAllowed: split), exitServerId: nil
        )
    }

    func testFullTunnelConfig() throws {
        let s = try TunnelConfigBuilder.render(privateKey: "PRIV=", response: response(), allowLan: false, excludeRoutes: [])
        XCTAssertTrue(s.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
        XCTAssertTrue(s.contains("DNS = 10.8.0.1"))
        XCTAssertTrue(s.contains("Endpoint = gw.example.com:51820"))
    }

    func testExcludeRouteSplitsAllowedIps() throws {
        let out = try Cidr.subtract(["0.0.0.0/0"], ["0.0.0.0/1"])
        XCTAssertEqual(out, ["128.0.0.0/1"])
        let lan = try Cidr.subtract(["0.0.0.0/0"], TunnelConfigBuilder.lanRanges)
        XCTAssertFalse(lan.contains("0.0.0.0/0"))
        XCTAssertFalse(lan.contains { $0.hasPrefix("192.168.") })
    }

    func testPolicyCanForbidSplitTunnel() throws {
        let s = try TunnelConfigBuilder.render(privateKey: "PRIV=", response: response(split: false), allowLan: true, excludeRoutes: ["1.2.3.0/24"])
        XCTAssertTrue(s.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
    }

    func testRejectsInjection() {
        var r = response()
        r.endpoint = "gw:51820\nPostUp = rm -rf /"
        XCTAssertThrowsError(try TunnelConfigBuilder.render(privateKey: "PRIV=", response: r, allowLan: false, excludeRoutes: []))
    }

    func testDecodesControlPlaneJson() throws {
        let json = #"{"session_id":"s","address":"10.8.0.2/32","dns":["10.8.0.1"],"mtu":1420,"peer_public_key":"k","preshared_key":"p","endpoint":"h:1","allowed_ips":["0.0.0.0/0"],"persistent_keepalive":25,"policy":{"kill_switch_required":true,"split_tunnel_allowed":false},"stealth_port":null,"exit_server_id":"ch-zrh-1"}"#
        let r = try JSONDecoder().decode(ConnectResponse.self, from: Data(json.utf8))
        XCTAssertEqual(r.exitServerId, "ch-zrh-1")
        XCTAssertTrue(r.policy.killSwitchRequired)
    }
}
