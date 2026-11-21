package app.beyondvpn.android

import org.json.JSONArray
import org.json.JSONObject

data class Server(
    val id: String,
    val name: String,
    val country: String,
    val city: String,
    val load: Double,
    val status: String,
    val features: List<String>,
) {
    val online get() = status == "online"
    fun label(): String = "${flag(country)} $name · ${(load * 100).toInt()}%" + if (online) "" else " (offline)"
}

data class ConnectResponse(
    val sessionId: String,
    val address: String,
    val dns: List<String>,
    val mtu: Int,
    val peerPublicKey: String,
    val presharedKey: String,
    val endpoint: String,
    val allowedIps: List<String>,
    val keepalive: Int,
    val killSwitchRequired: Boolean,
    val splitTunnelAllowed: Boolean,
)

data class Tokens(val access: String, val refresh: String)

data class Usage(val monthTotal: Long, val cap: Long?)

private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }

object Json {
    fun servers(body: String): List<Server> {
        val a = JSONArray(body)
        return (0 until a.length()).map { i ->
            val o = a.getJSONObject(i)
            Server(
                id = o.getString("id"),
                name = o.getString("name"),
                country = o.getString("country"),
                city = o.optString("city"),
                load = o.optDouble("load", 0.0),
                status = o.optString("status", "offline"),
                features = o.optJSONArray("features")?.strings() ?: emptyList(),
            )
        }
    }

    fun connect(body: String): ConnectResponse {
        val o = JSONObject(body)
        val p = o.optJSONObject("policy") ?: JSONObject()
        return ConnectResponse(
            sessionId = o.getString("session_id"),
            address = o.getString("address"),
            dns = o.getJSONArray("dns").strings(),
            mtu = o.optInt("mtu", 1420),
            peerPublicKey = o.getString("peer_public_key"),
            presharedKey = o.getString("preshared_key"),
            endpoint = o.getString("endpoint"),
            allowedIps = o.getJSONArray("allowed_ips").strings(),
            keepalive = o.optInt("persistent_keepalive", 25),
            killSwitchRequired = p.optBoolean("kill_switch_required", false),
            splitTunnelAllowed = p.optBoolean("split_tunnel_allowed", true),
        )
    }

    fun tokens(body: String): Tokens {
        val o = JSONObject(body)
        return Tokens(o.getString("access_token"), o.getString("refresh_token"))
    }

    fun usage(body: String): Usage {
        val o = JSONObject(body)
        return Usage(o.optLong("month_total_bytes", 0), if (o.isNull("data_cap_bytes")) null else o.getLong("data_cap_bytes"))
    }

    fun error(body: String?): String =
        try {
            val d = JSONObject(body ?: "").opt("detail")
            if (d is String) d else d?.toString() ?: "request failed"
        } catch (_: Exception) {
            "request failed"
        }
}

fun flag(country: String): String {
    if (!Regex("^[A-Z]{2}$").matches(country)) return "🌐"
    val sb = StringBuilder()
    country.forEach { sb.appendCodePoint(0x1F1E6 + (it - 'A')) }
    return sb.toString()
}

fun formatBytes(n: Long): String {
    val units = listOf("B", "KB", "MB", "GB", "TB")
    var v = n.toDouble()
    var i = 0
    while (v >= 1024 && i < units.size - 1) {
        v /= 1024; i++
    }
    return if (i == 0) "${n} B" else String.format(java.util.Locale.US, "%.1f %s", v, units[i])
}
