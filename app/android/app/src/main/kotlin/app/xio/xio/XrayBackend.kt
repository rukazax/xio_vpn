package app.xio.xio

import android.os.ParcelFileDescriptor
import app.xio.mobile.Mobile
import app.xio.mobile.Protector
import org.json.JSONObject

/** Xray shares XIO's one system VpnService; its TUN remains while reconnecting. */
object XrayBackend {
 @Volatile var established=false
 fun status():JSONObject=JSONObject(Mobile.xrayStatus())
 fun stop(){Mobile.xrayStop();established=false}
 fun connect(service:XioVpnService,id:String,raw:String,timeoutMillis:Long){
  val token=Engine.publicationToken()
  Engine.requireActivation(token)
  go.Seq.setContext(service.applicationContext)
  val protector=object:Protector {
   override fun protect(fd:Long):Boolean=fd>=0&&fd<=Int.MAX_VALUE&&service.protect(fd.toInt())
   override fun resolve(host:String):String = PhysicalNetwork.resolve(service,host)
  }
  try {
   val started=android.os.SystemClock.elapsedRealtime()
   Mobile.xrayStart(raw,protector,timeoutMillis)
   // The admitted plan's site; the old raw plan is no longer an authority and
   // there is no silent "youtube.com" default here.
   val site=Engine.capturedSite()
   val roots=service.assets.open("flutter_assets/assets/security/probe-roots.pem").bufferedReader().use{it.readText()}
   require(timeoutMillis>(android.os.SystemClock.elapsedRealtime()-started)){"Connection deadline"}
   // A single probe must not declare a healthy tunnel dead: the admitted site
   // can be filtered (DNS) or blocked from the exit host while the tunnel works.
   // Probe the admitted site first, then a small fixed set, and require one pass.
   val probes=(listOf(site)+listOf("https://www.google.com/","https://api.ipify.org/","https://www.cloudflare.com/")).filter{it.isNotBlank()}.distinct()
   var failure:Exception?=null
   var passed=false
   for((index,probe) in probes.withIndex()){
    val left=timeoutMillis-(android.os.SystemClock.elapsedRealtime()-started)
    if(left<=1500)break
    // Share the remaining budget: a filtered or censored probe must not eat the
    // whole deadline and leave the tunnel unverified.
    val rest=probes.size-index-1
    val cap=if(rest==0)left else (left/(rest+1)).coerceIn(1500L,6500L)
    try{
     Mobile.xrayCheckHttps(probe,roots,cap);passed=true
     Diag.append("xray","probe ok: "+probe+" ("+(android.os.SystemClock.elapsedRealtime()-started)+" ms)")
     break
    }catch(e:Exception){
     failure=e
     Diag.append("xray","probe failed: "+probe+": "+e.message)
    }
   }
   if(!passed)throw failure?:IllegalStateException("Connection deadline")
   val builder=service.rivetBuilder().setSession("XIO VPN").setMtu(1280).addAddress("198.18.0.1",32).addAddress("fd00:7869:6f::1",128).addDnsServer("9.9.9.9").addDnsServer("2620:fe::fe").setBlocking(false)
   SplitRouting(service).applyNative(builder)
   Engine.requireActivation(token)
   val tun=builder.establish()?:error("VPN permission missing");val fd=tun.detachFd()
   try {Engine.requireActivation(token);Mobile.xrayAttachTun(fd.toLong())}catch(e:Exception){ParcelFileDescriptor.adoptFd(fd).close();throw e}
   Engine.requireActivation(token)
   established=true
   service.getSharedPreferences("xio",0).edit().putString("activeId",id).putBoolean("vpnWanted",true).commit()
   XioVpnService.stateChanged(true,token)
  }catch(e:Exception){stop();throw e}
 }
}
