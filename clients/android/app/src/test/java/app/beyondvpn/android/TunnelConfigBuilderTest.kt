package app.beyondvpn.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelConfigBuilderTest {
    private val key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
    private fun conn(split: Boolean = true, endpoint: String = "gw.example.com:51820") = ConnectResponse(
        sessionId = "s", address = "10.8.0.2/32", dns = listOf("10.8.0.1"), mtu = 1420,
        peerPublicKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", presharedKey = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=",
        endpoint = endpoint, allowedIps = listOf("0.0.0.0/0", "::/0"), keepalive = 25,
        killSwitchRequired = false, splitTunnelAllowed = split,
    )

    @Test fun fullTunnel() {
        val c = TunnelConfigBuilder.build(key, conn())
        assertTrue(c.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
        assertTrue(c.contains("DNS = 10.8.0.1"))
        assertFalse(c.contains("ExcludedApplications"))
    }

    @Test fun allowLanAndExcludedApps() {
        val c = TunnelConfigBuilder.build(key, conn(), allowLan = true, excludedApps = setOf("com.bank.app", "bad;pkg"))
        assertFalse(c.contains("AllowedIPs = 0.0.0.0/0"))
        assertTrue(c.contains("8.0.0.0/7"))
        assertTrue(c.contains("ExcludedApplications = com.bank.app\n"))
    }

    @Test fun policyDisablesSplitTunnel() {
        val c = TunnelConfigBuilder.build(key, conn(split = false), allowLan = true, excludedApps = setOf("com.bank.app"))
        assertTrue(c.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
        assertFalse(c.contains("ExcludedApplications"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsInjection() {
        TunnelConfigBuilder.build(key, conn(endpoint = "x:1\nPostUp = evil"))
    }

    @Test fun cidrSubtract() {
        val r = Cidr.subtract(listOf("0.0.0.0/0"), listOf("1.2.3.4/32"))
        assertEquals(32, r.size)
        assertEquals(listOf("10.0.0.0/8"), Cidr.subtract(listOf("10.0.0.0/8"), listOf("11.0.0.0/8")))
        assertTrue(Cidr.subtract(listOf("10.0.0.0/8"), listOf("0.0.0.0/0")).isEmpty())
    }

    @Test fun jsonParsing() {
        val s = Json.servers("""[{"id":"in-mum-1","name":"Mumbai","country":"IN","city":"Mumbai","load":0.25,"status":"online","features":["p2p"]}]""")
        assertEquals("in-mum-1", s[0].id)
        assertTrue(s[0].online)
        val c = Json.connect("""{"session_id":"x","address":"10.8.0.2/32","dns":["10.8.0.1"],"mtu":1420,"peer_public_key":"k","preshared_key":"p","endpoint":"h:1","allowed_ips":["0.0.0.0/0"],"persistent_keepalive":25,"policy":{"kill_switch_required":true,"split_tunnel_allowed":false}}""")
        assertTrue(c.killSwitchRequired)
        assertFalse(c.splitTunnelAllowed)
        val u = Json.usage("""{"month_total_bytes":2048,"data_cap_bytes":null,"days":[]}""")
        assertNull(u.cap)
        assertEquals("mfa_required", Json.error("""{"detail":"mfa_required"}"""))
        assertEquals("request failed", Json.error("<html>"))
    }

    @Test fun formatting() {
        assertEquals("🇮🇳", flag("IN"))
        assertEquals("512 B", formatBytes(512))
        assertEquals("1.5 KB", formatBytes(1536))
    }
}
