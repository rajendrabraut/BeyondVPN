package app.beyondvpn.android

import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.WindowManager
import android.widget.ArrayAdapter
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import app.beyondvpn.android.databinding.ActivityMainBinding
import com.wireguard.android.backend.Tunnel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    private lateinit var b: ActivityMainBinding
    private val vpn get() = (application as BeyondApp).vpn
    private var servers: List<Server> = emptyList()
    private var pendingConnect = false

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK && pendingConnect) doConnect() else showError(getString(R.string.vpn_permission_denied))
        pendingConnect = false
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keep tokens/config out of screenshots and the recents switcher.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.signIn.setOnClickListener { signIn() }
        b.toggle.setOnClickListener { toggle() }
        b.signOut.setOnClickListener { io({ vpn.logout() }) { render() } }
        b.allowLan.setOnCheckedChangeListener { _, v -> vpn.store.allowLan = v }
        b.splitApps.setOnClickListener { pickExcludedApps() }
        b.killSwitch.setOnClickListener { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
        render()
        lifecycleScope.launch {
            while (isActive) {
                updateStats()
                delay(2000)
            }
        }
    }

    private fun io(work: () -> Unit, after: () -> Unit = {}) {
        showError(null)
        setBusy(true)
        lifecycleScope.launch {
            val err = withContext(Dispatchers.IO) { runCatching(work).exceptionOrNull() }
            setBusy(false)
            if (err != null) {
                if (err.message == "mfa_required") {
                    b.totpLayout.visibility = View.VISIBLE
                    b.totp.requestFocus()
                } else showError(err.message ?: err.toString())
            }
            after()
        }
    }

    private fun setBusy(busy: Boolean) {
        b.progress.visibility = if (busy) View.VISIBLE else View.GONE
        b.toggle.isEnabled = !busy
        b.signIn.isEnabled = !busy
    }

    private fun showError(msg: String?) {
        b.error.text = msg ?: ""
        b.error.visibility = if (msg.isNullOrBlank()) View.GONE else View.VISIBLE
    }

    private fun signIn() {
        val url = b.apiUrl.text.toString()
        val email = b.email.text.toString().trim()
        val pw = b.password.text.toString()
        val totp = b.totp.text.toString()
        io({ vpn.login(url, email, pw, totp) }) {
            b.password.setText("")
            render()
        }
    }

    private fun render() {
        val logged = vpn.store.loggedIn
        b.loginGroup.visibility = if (logged) View.GONE else View.VISIBLE
        b.mainGroup.visibility = if (logged) View.VISIBLE else View.GONE
        if (!logged) {
            b.apiUrl.setText(vpn.store.apiUrl ?: "")
            b.email.setText(vpn.store.email ?: "")
            return
        }
        b.who.text = vpn.store.email
        b.allowLan.isChecked = vpn.store.allowLan
        renderState()
        lifecycleScope.launch {
            val list = withContext(Dispatchers.IO) { runCatching { vpn.api.servers() } }
            list.onSuccess { s ->
                servers = s
                val labels = listOf(getString(R.string.fastest)) + s.map { it.label() }
                b.server.adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, labels)
                val idx = s.indexOfFirst { it.id == vpn.store.lastServer }
                if (idx >= 0) b.server.setSelection(idx + 1)
            }.onFailure { showError(it.message) }
            val usage = withContext(Dispatchers.IO) { runCatching { vpn.api.usage() }.getOrNull() }
            usage?.let { b.usage.text = getString(R.string.usage_fmt, formatBytes(it.monthTotal), it.cap?.let(::formatBytes) ?: "∞") }
        }
    }

    private fun renderState() {
        val up = vpn.state == Tunnel.State.UP
        b.state.text = getString(if (up) R.string.protected_state else R.string.unprotected_state)
        b.state.setTextColor(getColor(if (up) R.color.ok else R.color.bad))
        b.where.text = vpn.store.connectedServer ?: ""
        b.toggle.text = getString(if (up) R.string.disconnect else R.string.connect)
    }

    private fun updateStats() {
        if (!::b.isInitialized || vpn.state != Tunnel.State.UP) return
        lifecycleScope.launch {
            val (rx, tx) = withContext(Dispatchers.IO) { vpn.stats() }
            b.stats.text = getString(R.string.stats_fmt, formatBytes(rx), formatBytes(tx))
        }
    }

    private fun toggle() {
        if (vpn.state == Tunnel.State.UP) {
            io({ vpn.disconnect() }) { renderState() }
            return
        }
        val intent = VpnService.prepare(this)
        if (intent != null) {
            pendingConnect = true
            vpnPermission.launch(intent)
        } else doConnect()
    }

    private fun doConnect() {
        val pos = b.server.selectedItemPosition
        val id = if (pos <= 0) null else servers.getOrNull(pos - 1)?.id
        io({ vpn.connect(id) }) { renderState() }
    }

    private fun pickExcludedApps() {
        val pm = packageManager
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { pm.getLaunchIntentForPackage(it.packageName) != null && it.packageName != packageName }
            .map { it.packageName to pm.getApplicationLabel(it).toString() }
            .sortedBy { it.second.lowercase() }
        val current = vpn.store.excludedApps.toMutableSet()
        val checked = apps.map { it.first in current }.toBooleanArray()
        AlertDialog.Builder(this)
            .setTitle(R.string.split_title)
            .setMultiChoiceItems(apps.map { it.second }.toTypedArray(), checked) { _, i, on ->
                if (on) current += apps[i].first else current -= apps[i].first
            }
            .setPositiveButton(android.R.string.ok) { _, _ -> vpn.store.excludedApps = current }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
