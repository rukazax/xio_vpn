package app.xio.xio

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** DNS uses the physical Android network, retaining both A and AAAA answers. */
object PhysicalNetwork {
 // Cap after interleaving, otherwise sixteen AAAA answers can hide the only A
 // answer (or the reverse) and make a usable physical family unreachable.
 internal fun numericAddresses(addresses:List<InetAddress>):List<String> {
  val usable=addresses.filter {
   (it is Inet4Address || it is Inet6Address) && !it.isAnyLocalAddress && !it.isMulticastAddress &&
    !(it is Inet6Address && it.isLinkLocalAddress)
  }.distinctBy {it.hostAddress?.substringBefore("%")}
  val first4=usable.firstOrNull() is Inet4Address
  val (primary,secondary)=usable.partition {(it is Inet4Address)==first4}
  return (0 until maxOf(primary.size,secondary.size)).flatMap {
   listOfNotNull(primary.getOrNull(it),secondary.getOrNull(it))
  }.mapNotNull {it.hostAddress?.substringBefore("%")}.take(16)
 }
 fun resolve(service:VpnService,host:String):String {
  val cm=service.getSystemService(ConnectivityManager::class.java)
  val active=try{cm.activeNetwork}catch(_:Exception){null}
  val networks=try{listOfNotNull(active)+cm.allNetworks.toList()}catch(_:Exception){return ""}
  for(network in networks.distinct()) {
   val caps=try{cm.getNetworkCapabilities(network)}catch(_:Exception){null}?:continue
   if(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)||!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))continue
   try {
    val addresses=numericAddresses(network.getAllByName(host).toList())
    if(addresses.isNotEmpty())return addresses.joinToString(",")
   }catch(_:Exception){}
  }
  return ""
 }
}
