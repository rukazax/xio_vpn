package app.xio.xio

// Compile-only signatures for unchanged collaborators. Never executed; this is
// not an Engine/Service/device test. Actual controller and ConnectionProbe compile.
@Suppress("UNUSED_PARAMETER")
object Engine {
 var backgroundBusy=false
 val worker:java.util.concurrent.Executor=java.util.concurrent.Executor { error("Compile only") }
 fun initialize(context:android.content.Context) {}
 fun hasPublicationOwner()=false
 fun revokePublication() {}
 fun registerConnect(round:ConnectionBudget) {}
 fun releaseConnect(round:ConnectionBudget) {}
 fun cancelConnect(roundId:String?=null) {}
 fun isUp(known:org.json.JSONObject?=null)=false
 fun disconnect(budget:ConnectionBudget?=null) {}
 fun connect(id:String,allowExistingService:Boolean=false,
  budget:ConnectionBudget=ConnectionBudget(15000,android.os.SystemClock::elapsedRealtime),
  policyJSON:String="{\"mode\":\"automatic\",\"roundMillis\":30000}",
  roundId:String="compile-only",publicationToken:Long=0L) {}
 fun handshake(known:org.json.JSONObject?=null)=0L
}
@Suppress("UNUSED_PARAMETER")
object XioVpnService { fun stateChanged(up:Boolean) {} }
@Suppress("UNUSED_PARAMETER")
object VpnTileService { fun refresh(context:android.content.Context) {} }
@Suppress("UNUSED_PARAMETER")
object L10n { fun text(context:android.content.Context,value:String)=value }
object R { object drawable { const val ic_vpn=1 } }
