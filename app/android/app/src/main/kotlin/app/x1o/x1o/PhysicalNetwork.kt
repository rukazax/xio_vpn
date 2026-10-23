package app.x1o.x1o

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import java.net.Inet4Address
import java.net.Inet6Address

/** DNS uses the physical Android network, retaining both A and AAAA answers. */
object PhysicalNetwork {
 fun resolve(service:VpnService,host:String):String {
  val cm=service.getSystemService(ConnectivityManager::class.java)
  val active=try{cm.activeNetwork}catch(_:Exception){null}
  val networks=try{listOfNotNull(active)+cm.allNetworks.toList()}catch(_:Exception){return ""}
  for(network in networks.distinct()) {
   val caps=try{cm.getNetworkCapabilities(network)}catch(_:Exception){null}?:continue
   if(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)||!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))continue
   try {
    val addresses=network.getAllByName(host).filter {it is Inet4Address || (it is Inet6Address && !it.isLinkLocalAddress && !it.isMulticastAddress)}.mapNotNull {it.hostAddress?.substringBefore("%") }.distinct().take(16)
    if(addresses.isNotEmpty())return addresses.joinToString(",")
   }catch(_:Exception){}
  }
  return ""
 }
}
