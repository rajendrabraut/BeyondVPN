package app.beyondvpn.android

import android.content.Context
import android.os.Build
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.crypto.KeyPair
import org.json.JSONObject
import java.io.File

/** Orchestrates login -> device registration -> WireGuard tunnel via the official GoBackend. */
class VpnManager(private val context: Context, val store: Store) {
    val api = ApiClient(store)
    private val backend by lazy { GoBackend(context.applicationContext) }

    @Volatile
    var state: Tunnel.State = Tunnel.State.DOWN
        private set

    private val tunnel = object : Tunnel {
        override fun getName() = "beyond0"
        override fun onStateChange(newState: Tunnel.State) {
            state = newState
        }
    }

    private fun posture(): JSONObject = JSONObject()
        .put("os", "android")
        .put("os_version", Build.VERSION.RELEASE)
        .put("sdk", Build.VERSION.SDK_INT)
        .put("model", Build.MODEL)
        .put("rooted", isProbablyRooted())
        .put("app_version", BuildConfigCompat.VERSION)

    private fun isProbablyRooted(): Boolean =
        listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk").any { File(it).exists() } ||
            (Build.TAGS?.contains("test-keys") == true)

    fun login(apiUrl: String, email: String, password: String, totp: String?) {
        api.login(apiUrl, email, password, totp)
        // Device key is generated on the phone; only the public half is sent.
        val priv = store.privateKey ?: KeyPair().privateKey.toBase64().also { store.privateKey = it }
        val pub = KeyPair(com.wireguard.crypto.Key.fromBase64(priv)).publicKey.toBase64()
        store.deviceId = api.registerDevice("${Build.MANUFACTURER} ${Build.MODEL}".take(80), pub, posture())
    }

    fun connect(serverId: String?): String {
        val deviceId = store.deviceId ?: throw IllegalStateException("Device not registered, sign in again")
        val servers = api.servers()
        val target = servers.firstOrNull { it.id == serverId && it.online }
            ?: servers.filter { it.online }.minByOrNull { it.load }
            ?: throw IllegalStateException("No servers available")
        val resp = api.connect(deviceId, target.id)
        val text = TunnelConfigBuilder.build(store.privateKey!!, resp, store.allowLan, store.excludedApps)
        val config = Config.parse(text.byteInputStream())
        backend.setState(tunnel, Tunnel.State.UP, config)
        state = Tunnel.State.UP
        store.sessionId = resp.sessionId
        store.connectedServer = target.name
        store.lastServer = target.id
        return target.name
    }

    fun disconnect() {
        runCatching { backend.setState(tunnel, Tunnel.State.DOWN, null) }
        state = Tunnel.State.DOWN
        store.sessionId?.let { api.disconnect(it) }
        store.sessionId = null
        store.connectedServer = null
    }

    fun stats(): Pair<Long, Long> = runCatching {
        val s = backend.getStatistics(tunnel)
        s.totalRx() to s.totalTx()
    }.getOrDefault(0L to 0L)

    fun logout() {
        disconnect()
        api.logout()
    }
}

object BuildConfigCompat {
    const val VERSION = "0.2.0"
}
