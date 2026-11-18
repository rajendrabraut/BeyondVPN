package app.beyondvpn.android

import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.wireguard.android.backend.Tunnel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class VpnTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val vpn get() = (application as BeyondApp).vpn

    override fun onStartListening() = render()

    override fun onClick() {
        // Permission must be granted from the app UI first.
        if (VpnService.prepare(this) != null || !vpn.store.loggedIn) return
        scope.launch {
            withContext(Dispatchers.IO) {
                runCatching { if (vpn.state == Tunnel.State.UP) vpn.disconnect() else vpn.connect(vpn.store.lastServer) }
            }
            render()
        }
    }

    private fun render() {
        val t = qsTile ?: return
        val up = vpn.state == Tunnel.State.UP
        t.state = if (up) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        t.label = if (up) getString(R.string.protected_state) else getString(R.string.app_name)
        t.updateTile()
    }
}
