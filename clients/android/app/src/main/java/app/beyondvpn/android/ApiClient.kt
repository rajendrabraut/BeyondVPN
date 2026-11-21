package app.beyondvpn.android

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class ApiException(val code: Int, message: String) : Exception(message)

/** Blocking client; always call from Dispatchers.IO. */
class ApiClient(private val store: Store) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()
    private val json = "application/json".toMediaType()

    companion object {
        fun normalize(url: String): String {
            val u = url.trim().trimEnd('/')
            val local = u.startsWith("http://10.0.2.2") || u.startsWith("http://127.0.0.1") || u.startsWith("http://localhost")
            require(u.startsWith("https://") || local) { "Server URL must start with https://" }
            return u
        }
    }

    private fun exec(method: String, path: String, body: JSONObject?, auth: Boolean): String {
        val base = store.apiUrl ?: throw ApiException(0, "Not signed in")
        val b = Request.Builder().url("$base/api/v1$path")
        if (auth) store.accessToken?.let { b.header("Authorization", "Bearer $it") }
        b.method(method, body?.toString()?.toRequestBody(json) ?: if (method == "POST") "".toRequestBody(json) else null)
        http.newCall(b.build()).execute().use { r ->
            val text = r.body?.string() ?: ""
            if (!r.isSuccessful) throw ApiException(r.code, Json.error(text))
            return text
        }
    }

    private fun call(method: String, path: String, body: JSONObject? = null): String =
        try {
            exec(method, path, body, true)
        } catch (e: ApiException) {
            if (e.code != 401 || !refresh()) throw e
            exec(method, path, body, true)
        }

    private fun refresh(): Boolean {
        val rt = store.refreshToken ?: return false
        return try {
            val t = Json.tokens(exec("POST", "/auth/refresh", JSONObject().put("refresh_token", rt), false))
            store.accessToken = t.access
            store.refreshToken = t.refresh
            true
        } catch (_: ApiException) {
            store.clearSession()
            false
        }
    }

    fun login(apiUrl: String, email: String, password: String, totp: String?) {
        store.apiUrl = normalize(apiUrl)
        val body = JSONObject().put("email", email).put("password", password).put("totp_code", totp?.takeIf { it.isNotBlank() } ?: JSONObject.NULL)
        val t = Json.tokens(exec("POST", "/auth/login", body, false))
        store.email = email
        store.accessToken = t.access
        store.refreshToken = t.refresh
    }

    fun logout() {
        store.refreshToken?.let { runCatching { exec("POST", "/auth/logout", JSONObject().put("refresh_token", it), false) } }
        store.clearSession()
    }

    fun registerDevice(name: String, publicKey: String, posture: JSONObject): String =
        JSONObject(call("POST", "/devices", JSONObject().put("name", name).put("platform", "android").put("public_key", publicKey).put("posture", posture))).getString("id")

    fun servers(): List<Server> = Json.servers(call("GET", "/servers"))

    fun connect(deviceId: String, serverId: String): ConnectResponse =
        Json.connect(call("POST", "/sessions/connect", JSONObject().put("device_id", deviceId).put("server_id", serverId)))

    fun disconnect(sessionId: String) {
        runCatching { call("POST", "/sessions/$sessionId/disconnect") }
    }

    fun usage(): Usage = Json.usage(call("GET", "/me/usage?days=30"))
}
