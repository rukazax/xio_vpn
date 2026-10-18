package app.x1o.x1o

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import app.xio.mobile.Mobile
import app.xio.mobile.Protector
import org.json.JSONObject
import java.net.Inet4Address

/** RIVET shares XIO's one system VpnService; its TUN remains while reconnecting. */
object RivetBackend {
 @Volatile var established=false
 fun status():JSONObject=JSONObject(Mobile.status())
 fun stop(){Mobile.stop();established=false}
 fun connect(service:X1oVpnService,id:String,raw:String,timeoutMillis:Long){
  go.Seq.setContext(service.applicationContext)
  val protector=object:Protector {
   override fun protect(fd:Long):Boolean=fd>=0&&fd<=Int.MAX_VALUE&&service.protect(fd.toInt())
   override fun resolve(host:String):String {
    val cm=service.getSystemService(ConnectivityManager::class.java)
    val networks=try{cm.allNetworks}catch(_:Exception){return ""}
    for(network in networks){val caps=try{cm.getNetworkCapabilities(network)}catch(_:Exception){null}?:continue
     if(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)||!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))continue
     try {return network.getAllByName(host).firstOrNull {it is Inet4Address}?.hostAddress?:continue}catch(_:Exception){}
    };return ""
   }
  }
  try {
   val cfg=JSONObject(raw);val result=JSONObject(Mobile.connectTimeout(raw,protector,timeoutMillis));check(result.optBoolean("secure"))
   val builder=service.rivetBuilder().setSession("XIO VPN").setMtu(1280).addAddress(cfg.getString("ip"),32).addDnsServer("9.9.9.9").setBlocking(false)
   SplitRouting(service).applyNative(builder)
   val tun=builder.establish()?:error("VPN permission missing");val fd=tun.detachFd()
   try {Mobile.attachTun(fd.toLong())}catch(e:Exception){ParcelFileDescriptor.adoptFd(fd).close();throw e}
   established=true
   service.getSharedPreferences("x1o",0).edit().putString("activeId",id).putBoolean("vpnWanted",true).commit()
   X1oVpnService.stateChanged(true)
  }catch(e:Exception){stop();throw e}
 }
}
