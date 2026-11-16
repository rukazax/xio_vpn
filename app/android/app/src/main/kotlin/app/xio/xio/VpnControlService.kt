package app.xio.xio
import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import android.os.Handler
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
  // A tile DOWN fences pending/live work before this same worker queue.
  if(intent?.action!="app.xio.RECONNECT" && (Engine.backgroundBusy || Engine.hasPublicationOwner())) {
   Engine.revokePublication()
   Engine.revokeLogicalPolicy()
   Engine.worker.execute {
    try { Engine.disconnect() } catch(_:Exception) { /* Owner stays incomplete. */ }
    Handler(mainLooper).post { stopForeground(STOP_FOREGROUND_REMOVE);stopSelf() }
   }
   return START_NOT_STICKY
  }
  if(Engine.backgroundBusy) return START_NOT_STICKY
  Engine.backgroundBusy=true
  // Starts before the worker queue, not afresh for every candidate.
  val round=ConnectionBudget(30000,android.os.SystemClock::elapsedRealtime)
  // A policy publication or a settings write owns admission; refuse without effects.
  try { Engine.registerConnect(round) } catch(e:Exception) {
   Engine.backgroundBusy=false
   android.util.Log.w("XIO/Tile","tile admission refused: "+e.message)
   stopForeground(STOP_FOREGROUND_REMOVE);stopSelf()
   return START_NOT_STICKY
  }
  val roundId="tile-${android.os.SystemClock.elapsedRealtime()}-$startId"
  val complete=java.util.concurrent.atomic.AtomicBoolean()
  val handler=Handler(mainLooper)
  val expired=Runnable {
   if(!complete.get()) {
    round.cancel()
    Engine.cancelConnect(roundId)?.let {XioVpnService.stateChanged(false,it)}
    android.util.Log.w("XIO/Tile","round expired; cleanup incomplete until worker joins")
    android.widget.Toast.makeText(this,L10n.text(this,"Не удалось подключиться. Проверьте сервер и разрешение VPN в XIO."),android.widget.Toast.LENGTH_LONG).show()
   }
  }
  handler.postDelayed(expired,round.remainingMillis())
  Engine.worker.execute {
   var attemptOwner:ConnectionBudget?=null
   try {
    round.remainingMillis()
    if(Engine.isUp() && intent?.action!="app.xio.RECONNECT") Engine.disconnect(round)
    else if(Engine.isUp()) { /* already restored */ }
    else {
     check(getSharedPreferences("xio",0).getString("consentRevision",null)=="2026-10-18")
     // Copy the committed envelope receipt and the candidate list together, once.
     // Boot/Tile validation reads the real durable document, with no Flutter and
     // no fresh default sampling later in this round.
     val captured=PolicyBridge.capture(this@VpnControlService)
     val ids=captured.candidates
     require(ids.size in 1..16)
     val verification=BackgroundVerificationOptions.fromPlanValue(captured.siteCheckEnabled)
     val site=if(verification.siteCheckEnabled) {
      URL(captured.site).also { site -> require(site.protocol=="https" && site.host.isNotEmpty() && site.userInfo==null) }
     } else null
     val budget=round.cap(ConnectionPolicy.ROUND_MILLIS)
     val count=if(captured.mode=="selectedOnly")1 else ids.size
     budget.runCandidates(count,captured.timeoutSeconds*1000L,object:ConnectionBudget.Attempts {
      override fun connect(index:Int,attempt:ConnectionBudget) {
        attemptOwner=attempt
       val id=ids[index];require(Regex("^(wg|awg|rvh|rvs|xr|ss|ov|ik|ck|ts)[0-9]{1,24}$").matches(id))
       if(!id.startsWith("ik"))check(VpnService.prepare(this@VpnControlService)==null)
       val started=System.currentTimeMillis() // Epoch handshake freshness only.
       // The SAME captured generation/receipt is passed to every candidate.
       Engine.connect(id,true,attempt,captured.policyJson(),roundId,policyReceipt=captured.receipt)
       verification.verify(started,attempt,
         { remaining -> ConnectionProbe.verify(checkNotNull(site),started,remaining) },
         { Engine.handshake() }, { millis -> Thread.sleep(millis) })
       attempt.remainingMillis()
      }
      override fun cleanup(owner:ConnectionBudget) { attemptOwner?.let { Engine.disconnectOwned(roundId,it,owner) } }
     })
    }
   } catch(e:Exception) {
    android.util.Log.w("XIO/Tile","controller failed: "+(e as? PolicyFailure)?.code.orEmpty()+" "+e.javaClass.simpleName)
    attemptOwner?.let {Engine.cancelConnect(roundId,it)}
    // No new five-second allowance after the original round has expired.
    try {attemptOwner?.let {Engine.disconnectOwned(roundId,it,round)}} catch(_:Exception) {}
    handler.post {android.widget.Toast.makeText(this,L10n.text(this,"Не удалось подключиться. Проверьте сервер и разрешение VPN в XIO."),android.widget.Toast.LENGTH_LONG).show()}
   } finally {
    Engine.releaseConnect(round)
    complete.set(true)
    handler.removeCallbacks(expired)
    Engine.backgroundBusy=false
    VpnTileService.refresh(this)
    handler.post {stopForeground(STOP_FOREGROUND_REMOVE);stopSelf()}
   }
  }
  return START_NOT_STICKY
 }
}

