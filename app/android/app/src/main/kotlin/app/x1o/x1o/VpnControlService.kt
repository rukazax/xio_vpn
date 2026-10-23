package app.x1o.x1o
import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import android.os.Handler
import org.amnezia.awg.backend.Tunnel
import org.json.JSONObject
import java.net.URL
/** Owns tile requests while Flutter and its Activity are absent. */
class VpnControlService : Service() {
 override fun onBind(intent: Intent?): IBinder? = null
 override fun onCreate() {
  super.onCreate()
  android.util.Log.i("XIO/Tile","controller created")
  getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel("xio.control","XIO VPN",NotificationManager.IMPORTANCE_LOW))
  startForeground(102,Notification.Builder(this,"xio.control").setSmallIcon(R.drawable.ic_vpn).setContentTitle("XIO VPN").setContentText(L10n.text(this,"Запуск VPN…")).setOngoing(true).build())
  Engine.initialize(this)
 }
 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
  android.util.Log.i("XIO/Tile","start busy="+Engine.backgroundBusy)
  if(Engine.backgroundBusy) return START_NOT_STICKY
  Engine.backgroundBusy=true
  Engine.worker.execute {
   try {
    android.util.Log.i("XIO/Tile","worker active="+Engine.isUp())
    if(Engine.isUp() && intent?.action!="app.xio.RECONNECT") Engine.disconnect()
    else if(Engine.isUp()) { /* already restored */ }
    else {
     check(getSharedPreferences("x1o",0).getString("consentRevision",null)=="2026-10-18")
     val plan=JSONObject(getSharedPreferences("x1o",0).getString("connectionPlan","{}")!!)
     val ids=plan.optJSONArray("ids") ?: error("No profile")
     android.util.Log.i("XIO/Tile","plan count="+ids.length())
     require(ids.length() in 1..16)
     val site=URL(plan.getString("site"));require(site.protocol=="https" && site.host.isNotEmpty() && site.userInfo==null)
     val timeoutMillis=plan.optInt("timeoutSeconds",15).coerceIn(5,60)*1000L
     var connected=false
     for(i in 0 until ids.length()) {
      val id=ids.getString(i);require(Regex("^(wg|awg|rvh|rvs|xr|ss|ov|ik|ck|ts)[0-9]{1,24}$").matches(id))
      try {
       if(!id.startsWith("ik"))check(VpnService.prepare(this)==null)
       android.util.Log.i("XIO/Tile","candidate="+id.takeWhile{!it.isDigit()})
       val started=System.currentTimeMillis();Engine.connect(id,true)
       ConnectionProbe.verify(site,started,(timeoutMillis-Engine.lastConnectMillis).coerceAtLeast(1));connected=true;android.util.Log.i("XIO/Tile","verification complete");break
      } catch(e:Exception) {android.util.Log.w("XIO/Connect",Engine.kind+" attempt failed: "+e.javaClass.simpleName);Engine.disconnect()}
     }
     check(connected)
    }
   } catch(e:Exception) {
    android.util.Log.w("XIO/Tile","controller failed: "+e.javaClass.simpleName)
    try {Engine.disconnect()} catch(_:Exception) {}
    Handler(mainLooper).post {android.widget.Toast.makeText(this,L10n.text(this,"Не удалось подключиться. Проверьте сервер и разрешение VPN в XIO."),android.widget.Toast.LENGTH_LONG).show()}
   } finally {
    android.util.Log.i("XIO/Tile","controller complete")
    Engine.backgroundBusy=false
    VpnTileService.refresh(this)
    Handler(mainLooper).post {stopForeground(STOP_FOREGROUND_REMOVE);stopSelf()}
   }
  }
  return START_NOT_STICKY
 }
}
