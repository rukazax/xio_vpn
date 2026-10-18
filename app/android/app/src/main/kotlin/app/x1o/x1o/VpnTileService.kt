package app.x1o.x1o

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.amnezia.awg.backend.Tunnel

class VpnTileService : TileService() {
    companion object {
        private var live: VpnTileService? = null
        fun refresh(context: android.content.Context) {
            Handler(android.os.Looper.getMainLooper()).post { live?.refreshState() }
        }
    }
    override fun onCreate() { super.onCreate(); live = this }
    override fun onDestroy() { if (live === this) live = null; super.onDestroy() }

    override fun onStartListening() {
        super.onStartListening()
        refreshState()
    }
    private fun refreshState() {
        Engine.initialize(this)
        Engine.worker.execute {
            val up = Engine.isUp()
            Handler(mainLooper).post {
                if (live !== this) return@post
                qsTile?.apply {
                    label = "XIO VPN"
                    state = if (up) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
                    if (Build.VERSION.SDK_INT >= 29) subtitle = L10n.text(this@VpnTileService, if (up) "Интерфейс активен" else "Отключено")
                    updateTile()
                }
            }
        }
    }
    override fun onClick() {
        super.onClick()
        if (isLocked) unlockAndRun { toggle() } else toggle()
    }
    private fun toggle() {
        qsTile?.apply { state=Tile.STATE_UNAVAILABLE; if(Build.VERSION.SDK_INT>=29) subtitle=L10n.text(this@VpnTileService,"Запуск VPN…");updateTile() }
        startForegroundService(Intent(this,VpnControlService::class.java))
    }
}
