package app.beyondvpn.android

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

/**
 * All secrets (tokens, WireGuard private key) live in EncryptedSharedPreferences,
 * whose master key is held in the Android Keystore. Backups are disabled in the manifest.
 */
class Store(context: Context) {
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        "beyond_secure",
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    var apiUrl: String? by str("api_url")
    var email: String? by str("email")
    var accessToken: String? by str("access")
    var refreshToken: String? by str("refresh")
    var deviceId: String? by str("device_id")
    var privateKey: String? by str("wg_private")
    var sessionId: String? by str("session_id")
    var connectedServer: String? by str("connected_server")
    var lastServer: String? by str("last_server")

    var allowLan: Boolean
        get() = prefs.getBoolean("allow_lan", false)
        set(v) = prefs.edit().putBoolean("allow_lan", v).apply()

    var excludedApps: Set<String>
        get() = prefs.getStringSet("excluded_apps", emptySet()) ?: emptySet()
        set(v) = prefs.edit().putStringSet("excluded_apps", v).apply()

    val loggedIn get() = refreshToken != null

    fun clearSession() {
        prefs.edit().remove("access").remove("refresh").remove("session_id").remove("connected_server").apply()
    }

    private fun str(key: String) = object : kotlin.properties.ReadWriteProperty<Any?, String?> {
        override fun getValue(thisRef: Any?, property: kotlin.reflect.KProperty<*>): String? = prefs.getString(key, null)
        override fun setValue(thisRef: Any?, property: kotlin.reflect.KProperty<*>, value: String?) {
            prefs.edit().apply { if (value == null) remove(key) else putString(key, value) }.apply()
        }
    }
}
