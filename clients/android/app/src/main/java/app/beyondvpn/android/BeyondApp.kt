package app.beyondvpn.android

import android.app.Application

class BeyondApp : Application() {
    lateinit var vpn: VpnManager
        private set

    override fun onCreate() {
        super.onCreate()
        vpn = VpnManager(this, Store(this))
    }
}
