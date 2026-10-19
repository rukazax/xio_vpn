package app.x1o.x1o

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import org.amnezia.awg.backend.GoBackend

/** The foreground notification lives with the actual VPN service, not the UI. */
class X1oVpnService : GoBackend.VpnService() {
    companion object {
        @Volatile private var instance: X1oVpnService? = null
        private val lifecycle = Object()
        // Engine.worker waits for stopSelf completion before another activation.
        fun awaitStopped() {
            val deadline = android.os.SystemClock.elapsedRealtime() + 5000
            synchronized(lifecycle) {
                while (instance != null) {
                    val remaining = deadline - android.os.SystemClock.elapsedRealtime()
                    check(remaining > 0) { "VPN service is still stopping" }
                    lifecycle.wait(remaining)
                }
            }
        }
        fun awaitCreated(): X1oVpnService {
            val deadline=android.os.SystemClock.elapsedRealtime()+5000
            synchronized(lifecycle) { while(instance==null){val left=deadline-android.os.SystemClock.elapsedRealtime();check(left>0);lifecycle.wait(left)};return instance!! }
        }
        private const val CHANNEL = "x1o.vpn"
        private const val ID = 101
        const val DISCONNECT = "app.x1o.DISCONNECT"
        fun languageChanged() {
            Handler(Looper.getMainLooper()).post {
                instance?.let { service ->
                    service.createChannel()
                    service.getSystemService(NotificationManager::class.java).notify(ID, service.notification(service.isUp))
                }
            }
        }
        fun stateChanged(up: Boolean) {
            Handler(Looper.getMainLooper()).post {
                instance?.let { service ->
                    service.isUp = up
                    if (up) service.getSystemService(NotificationManager::class.java).notify(ID, service.notification(true))
                    else service.stopForeground(STOP_FOREGROUND_REMOVE)
                }
            }
        }
    }
    fun rivetBuilder(): Builder = Builder()
    private val phaseHandler=Handler(Looper.getMainLooper())
    private var lastRivetPhase=""
    private val phaseWatch=object:Runnable {
        override fun run(){
            if(instance!==this@X1oVpnService)return
            VpnSharing.schedule(this@X1oVpnService)
            if(RivetBackend.established){
                val value=RivetBackend.status();val key=value.optString("phase")+value.optString("protocol")
                if(key!=lastRivetPhase){lastRivetPhase=key;Engine.worker.execute{
                    val status=Engine.status()
                    phaseHandler.post {if(instance===this@X1oVpnService)getSystemService(NotificationManager::class.java).notify(ID,notification(true,if(status["phase"]=="reconnecting")"Повторное подключение…" else null))}
                }}
            }
            phaseHandler.postDelayed(this,if(RivetBackend.established)2000L else 15000L)
        }
    }
    private var isUp = false
    private fun createChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, L10n.text(this, "VPN-подключение"), NotificationManager.IMPORTANCE_LOW).apply {
                description = L10n.text(this@X1oVpnService, "Состояние VPN и кнопка отключения")
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
        )
    }
    override fun onCreate() {
        super.onCreate()
        synchronized(lifecycle){instance = this;lifecycle.notifyAll()}
        createChannel()
        phaseHandler.post(phaseWatch)
        if (Build.VERSION.SDK_INT >= 34) startForeground(ID, notification(false), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(ID, notification(false))
    }
    private fun notification(up: Boolean, overrideText:String?=null): Notification {
        val open = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, X1oVpnService::class.java).setAction(DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_vpn).setContentTitle("XIO VPN")
            .setContentText(if(overrideText!=null)L10n.text(this,overrideText) else if (up) L10n.text(this, "VPN-интерфейс активен · {0}", when(Engine.kind){"rivet-h3"->"RIVET / H3";"rivet-s1"->"RIVET / S1";"awg"->"AmneziaWG";"cloak"->"OpenVPN / Cloak";"xray"->"Xray";else->"AmneziaWG"}) else L10n.text(this, "Запуск VPN…"))
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_SERVICE).setVisibility(Notification.VISIBILITY_PRIVATE)
            .addAction(Notification.Action.Builder(null, L10n.text(this, "Отключить"), stop).build())
        if (Build.VERSION.SDK_INT >= 31) builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        return builder.build()
    }
    override fun onConfigurationChanged(config: android.content.res.Configuration) {
        super.onConfigurationChanged(config)
        languageChanged()
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        if (intent?.action == DISCONNECT) {
            Engine.initialize(this)
            Engine.worker.execute {
                try { Engine.disconnect() } catch (_: Exception) { Handler(mainLooper).post { stopSelf() } }
            }
        }
        if((intent==null || intent.action=="android.net.VpnService") && getSharedPreferences("x1o",0).getString("connectionPlan",null)!=null) {
            startForegroundService(Intent(this,VpnControlService::class.java).setAction("app.xio.RECONNECT"))
        }
        return START_STICKY
    }
    override fun onTaskRemoved(rootIntent: Intent?) {
        // Removing the Activity task must not tear down the TUN or foreground service.
        super.onTaskRemoved(rootIntent)
    }
    override fun onRevoke() {
        getSharedPreferences("x1o",0).edit().putBoolean("vpnWanted",false).commit()
        Engine.worker.execute { try {Engine.disconnect()} catch(_:Exception) {} }
        super.onRevoke()
    }
    override fun onDestroy() {
        phaseHandler.removeCallbacks(phaseWatch)
        OpenVpnBackend.stop()
        XrayBackend.stop()
        if(Engine.kind.startsWith("rivet-")) RivetBackend.stop()
        // The base service releases the TUN and invokes the tunnel DOWN callback.
        super.onDestroy()
        synchronized(lifecycle) {
            if (instance === this) instance = null
            lifecycle.notifyAll()
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
    }
}
