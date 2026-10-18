package app.x1o.x1o
import app.xio.mobile.Mobile
import app.xio.mobile.Protector
import app.xio.mobile.SecureStore
import app.xio.mobile.NetworkInfo
import android.net.ConnectivityManager
import android.net.NetworkRequest
import android.net.NetworkCapabilities
import android.net.Network
import android.net.LinkProperties
import android.os.ParcelFileDescriptor
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

object TailscaleBackend {
 private var networkCallback:ConnectivityManager.NetworkCallback?=null
 private var connectivity:ConnectivityManager?=null
 @Volatile var established=false
 fun status()=JSONObject(Mobile.tailscaleStatus())
 fun stop(){networkCallback?.let{try{connectivity?.unregisterNetworkCallback(it)}catch(_:Exception){}};networkCallback=null;connectivity=null;Mobile.tailscaleStop();established=false}
 fun deleteState(context:android.content.Context,id:String){
  val prefs=context.getSharedPreferences("x1o",0);val index="tailState:"+id;for(key in prefs.getStringSet(index,emptySet())!!.toSet())ConfigVault(context).delete(key);prefs.edit().remove(index).commit();File(context.noBackupFilesDir,"tailscale/$id").deleteRecursively()
 }
 fun connect(service:X1oVpnService,id:String,raw:String,timeout:Long){
  go.Seq.setContext(service.applicationContext)
  val protector=object:Protector{override fun protect(fd:Long)=fd>=0&&fd<=Int.MAX_VALUE&&service.protect(fd.toInt());override fun resolve(host:String)=try{OpenVpnBackend.resolve(service,host)}catch(_:Exception){""}}
  val prefs=service.getSharedPreferences("x1o",0);val vault=ConfigVault(service)
  val store=object:SecureStore {
   private fun stateId(key:String)="state"+MessageDigest.getInstance("SHA-256").digest((id+"\u0000"+key).toByteArray()).joinToString(""){"%02x".format(it)}
   override fun load(key:String):String=try{val k=stateId(key);if(vault.contains(k))vault.readSecret(k) else ""}catch(_:Exception){"!"}
   override fun save(key:String,value:String):Boolean=try{
    require(key.length<=1024&&value.length<=5600000);val k=stateId(key);val index="tailState:"+id;val keys=prefs.getStringSet(index,emptySet())!!.toMutableSet()
    if(value.isEmpty()){vault.delete(k);keys.remove(k)}else{vault.writeSecret(k,value);keys.add(k)};prefs.edit().putStringSet(index,keys).commit()
   }catch(_:Exception){false}
  }
  val cm=service.getSystemService(ConnectivityManager::class.java)
  val networkInfo=object:NetworkInfo{
   override fun interfaces():String {
    val list=JSONArray();var default="";var gateway=""
    for(n in cm.allNetworks){val caps=cm.getNetworkCapabilities(n)?:continue;if(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)||!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))continue
     val lp=cm.getLinkProperties(n)?:continue;val name=lp.interfaceName?:continue
     val index=try{java.net.NetworkInterface.getByName(name)?.index?:list.length()+2}catch(_:Exception){list.length()+2}
     list.put(JSONObject().put("name",name).put("index",index).put("mtu",if(lp.mtu>0)lp.mtu else 1500).put("addresses",JSONArray(lp.linkAddresses.map{it.toString()})))
     if(default.isEmpty()){default=name;gateway=lp.routes.firstOrNull{it.isDefaultRoute}?.gateway?.hostAddress?:""}
    };return JSONObject().put("interfaces",list).put("default",default).put("gateway",gateway).toString()
   }
  }
  try {
   connectivity=cm
   networkCallback=object:ConnectivityManager.NetworkCallback(){override fun onAvailable(network:Network){Mobile.tailscaleNetworkChanged()};override fun onLost(network:Network){Mobile.tailscaleNetworkChanged()};override fun onLinkPropertiesChanged(network:Network,properties:LinkProperties){Mobile.tailscaleNetworkChanged()}}
   cm.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),networkCallback!!)
   val dir=File(service.noBackupFilesDir,"tailscale/$id").apply{mkdirs()}
   val addresses=JSONArray(Mobile.tailscaleStart(raw,dir.absolutePath,protector,store,networkInfo,timeout))
   val builder=service.rivetBuilder().setSession("XIO VPN").setMtu(1280).addDnsServer("9.9.9.9").setBlocking(false)
   for(i in 0 until addresses.length()){val ip=addresses.getString(i);builder.addAddress(ip,if(ip.contains(':'))128 else 32)}
   SplitRouting(service).applyNative(builder)
   val tun=builder.establish()?:error("VPN permission missing");val fd=tun.detachFd()
   try{Mobile.tailscaleAttachTun(fd.toLong())}catch(e:Exception){ParcelFileDescriptor.adoptFd(fd).close();throw e}
   established=true;prefs.edit().putString("activeId",id).putBoolean("vpnWanted",true).commit();X1oVpnService.stateChanged(true)
  }catch(e:Exception){stop();throw e}
 }
}
