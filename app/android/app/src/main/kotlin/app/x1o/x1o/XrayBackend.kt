package app.x1o.x1o

import android.os.ParcelFileDescriptor
import app.xio.mobile.Mobile
import app.xio.mobile.Protector
import org.json.JSONObject

/** Xray shares XIO's one system VpnService; its TUN remains while reconnecting. */
object XrayBackend {
 @Volatile var established=false
 fun status():JSONObject=JSONObject(Mobile.xrayStatus())
 fun stop(){Mobile.xrayStop();established=false}
 fun connect(service:X1oVpnService,id:String,raw:String,timeoutMillis:Long){
  go.Seq.setContext(service.applicationContext)
  val protector=object:Protector {
   override fun protect(fd:Long):Boolean=fd>=0&&fd<=Int.MAX_VALUE&&service.protect(fd.toInt())
   override fun resolve(host:String):String = PhysicalNetwork.resolve(service,host)
  }
  try {
   Mobile.xrayStart(raw,protector,timeoutMillis)
   val builder=service.rivetBuilder().setSession("XIO VPN").setMtu(1280).addAddress("198.18.0.1",32).addAddress("fd00:7869:6f::1",128).addDnsServer("9.9.9.9").addDnsServer("2620:fe::fe").setBlocking(false)
   SplitRouting(service).applyNative(builder)
   val tun=builder.establish()?:error("VPN permission missing");val fd=tun.detachFd()
   try {Mobile.xrayAttachTun(fd.toLong())}catch(e:Exception){ParcelFileDescriptor.adoptFd(fd).close();throw e}
   established=true
   service.getSharedPreferences("x1o",0).edit().putString("activeId",id).putBoolean("vpnWanted",true).commit()
   X1oVpnService.stateChanged(true)
  }catch(e:Exception){stop();throw e}
 }
}
