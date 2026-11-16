package app.xio.xio

import android.os.ParcelFileDescriptor
import app.xio.mobile.Mobile
import app.xio.mobile.Protector
import org.json.JSONObject

/** Owns the TUN, not an Internet-readiness assertion while native recovery runs. */
object RivetBackend {
 @Volatile var established=false
 fun status():JSONObject {
  val value=JSONObject(Mobile.status())
  if(!value.optBoolean("interfaceUp") && !value.optBoolean("recoveryPending") && value.optString("phase") in listOf("failed","disconnected"))established=false
  return value
 }
 fun stop(timeoutMillis:Long=5000){established=false;Mobile.stopWithTimeout(timeoutMillis.coerceIn(1,30000))}
 fun connect(service:XioVpnService,id:String,raw:String,timeoutMillis:Long,policyJSON:String="{\"mode\":\"automatic\",\"roundMillis\":30000}"){
  val budget=ConnectionBudget(timeoutMillis.coerceIn(1,30000),android.os.SystemClock::elapsedRealtime)
  val token=Engine.publicationToken()
  Engine.requireActivation(token)
  go.Seq.setContext(service.applicationContext)
  val protector=object:Protector {
   override fun protect(fd:Long):Boolean=fd>=0&&fd<=Int.MAX_VALUE&&service.protect(fd.toInt())
   override fun resolve(host:String):String = PhysicalNetwork.resolve(service,host)
  }
  try {
   val cfg=JSONObject(raw)
   // Deliberately requires regenerated JNI bindings: never fall back to a legacy
   // auto-switching API when the caller explicitly selected a transport.
   val result=JSONObject(Mobile.connectPolicyTimeout(raw,protector,budget.remainingMillis(),policyJSON))
   check(result.optBoolean("secure") && result.optString("policyMode")==JSONObject(policyJSON).getString("mode"))
   budget.remainingMillis()
   val builder=service.rivetBuilder().setSession("XIO VPN").setMtu(1280).addAddress(cfg.getString("ip"),32).addDnsServer("9.9.9.9").setBlocking(false)
   if(cfg.optString("ip6").isNotEmpty()){builder.addAddress(cfg.getString("ip6"),128).addDnsServer("2620:fe::fe")}
   SplitRouting(service).applyNative(builder)
   budget.remainingMillis()
   Engine.requireActivation(token)
   val tun=builder.establish()?:error("VPN permission missing")
   try {
    budget.remainingMillis()
    val fd=tun.detachFd()
    try {Engine.requireActivation(token);Mobile.attachTun(fd.toLong())}catch(e:Exception){ParcelFileDescriptor.adoptFd(fd).close();throw e}
   }finally{tun.close()}
   budget.remainingMillis()
   Engine.requireActivation(token)
   established=true
   service.getSharedPreferences("xio",0).edit().putString("activeId",id).putBoolean("vpnWanted",true).commit()
   XioVpnService.stateChanged(true,token)
  }catch(e:Exception){Mobile.cancelConnect();established=false;throw e}
 }
}
