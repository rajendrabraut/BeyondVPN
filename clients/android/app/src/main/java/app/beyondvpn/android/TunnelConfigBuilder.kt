package app.beyondvpn.android

/**
 * Builds a wg-quick style config understood by com.wireguard.config.Config.parse().
 * Pure Kotlin so it is unit-testable on the JVM. Mirrors core/crates/beyond-common/src/wgconf.rs.
 */
object TunnelConfigBuilder {
    private val SAFE = Regex("^[A-Za-z0-9.:\\-_\\[\\]/+=]+$")
    private val PKG = Regex("^[A-Za-z0-9_.]+$")
    private val LAN = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4")

    fun build(
        privateKey: String,
        c: ConnectResponse,
        allowLan: Boolean = false,
        excludedApps: Set<String> = emptySet(),
    ): String {
        val fields = listOf(privateKey, c.address, c.peerPublicKey, c.presharedKey, c.endpoint) + c.dns + c.allowedIps
        require(fields.all { SAFE.matches(it) }) { "server returned an unsafe config value" }
        val split = c.splitTunnelAllowed
        val allowed = if (split && allowLan) Cidr.subtract(c.allowedIps, LAN) else c.allowedIps
        val apps = if (split) excludedApps.filter { PKG.matches(it) }.sorted() else emptyList()
        return buildString {
            appendLine("[Interface]")
            appendLine("PrivateKey = $privateKey")
            appendLine("Address = ${c.address}")
            if (c.dns.isNotEmpty()) appendLine("DNS = ${c.dns.joinToString(", ")}")
            appendLine("MTU = ${c.mtu}")
            // Per-app split tunnelling (Proton/Forti feature) via VpnService.Builder.addDisallowedApplication.
            if (apps.isNotEmpty()) appendLine("ExcludedApplications = ${apps.joinToString(", ")}")
            appendLine()
            appendLine("[Peer]")
            appendLine("PublicKey = ${c.peerPublicKey}")
            appendLine("PresharedKey = ${c.presharedKey}")
            appendLine("AllowedIPs = ${allowed.joinToString(", ")}")
            appendLine("Endpoint = ${c.endpoint}")
            appendLine("PersistentKeepalive = ${c.keepalive}")
        }
    }
}

/** IPv4 CIDR subtraction (complement inside AllowedIPs). IPv6 entries pass through. */
object Cidr {
    private data class Net(val addr: Long, val prefix: Int) {
        val mask: Long get() = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        fun contains(o: Net) = o.prefix >= prefix && (o.addr and mask) == addr
        fun halves(): Pair<Net, Net> {
            val p = prefix + 1
            val bit = 1L shl (32 - p)
            return Net(addr, p) to Net(addr or bit, p)
        }
        override fun toString(): String =
            "${(addr shr 24) and 255}.${(addr shr 16) and 255}.${(addr shr 8) and 255}.${addr and 255}/$prefix"
    }

    private fun parse(s: String): Net {
        val (ip, p) = if ('/' in s) s.split('/').let { it[0] to it[1].toInt() } else s to 32
        require(p in 0..32)
        val parts = ip.split('.').map { it.toInt() }
        require(parts.size == 4 && parts.all { it in 0..255 })
        val a = parts.fold(0L) { acc, x -> (acc shl 8) or x.toLong() }
        val m = if (p == 0) 0L else (0xFFFFFFFFL shl (32 - p)) and 0xFFFFFFFFL
        return Net(a and m, p)
    }

    private fun sub(net: Net, ex: Net, out: MutableList<Net>) {
        when {
            ex.contains(net) -> Unit
            !net.contains(ex) -> out += net
            else -> net.halves().let { (a, b) -> sub(a, ex, out); sub(b, ex, out) }
        }
    }

    fun subtract(include: List<String>, exclude: List<String>): List<String> {
        val v6 = include.filter { ':' in it }
        var cur = include.filter { ':' !in it }.map(::parse)
        for (e in exclude.map(::parse)) {
            val next = mutableListOf<Net>()
            cur.forEach { sub(it, e, next) }
            cur = next
        }
        return cur.sortedWith(compareBy({ it.addr }, { it.prefix })).map { it.toString() } + v6
    }
}
