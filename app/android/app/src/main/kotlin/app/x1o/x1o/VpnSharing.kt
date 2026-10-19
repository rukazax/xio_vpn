package app.x1o.x1o

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.TimeUnit

/** Root-only forwarding; no hidden claim that ordinary VpnService owns tethering. */
object VpnSharing {
    @Volatile private var working=false
    @Volatile private var lastVpn=""
    @Volatile private var lastApplied=0L
    @Volatile private var lastError=""
    private fun prefs(c:Context)=c.getSharedPreferences("x1o",0)
    private fun candidates():List<Map<String,String>> = NetworkInterface.getNetworkInterfaces().toList().filter {
        it.isUp && !it.isLoopback && Regex("(?:ap|swlan|wlan|rndis|usb|bnep|ncm)[a-zA-Z0-9_-]{0,12}").matches(it.name) &&
            it.inetAddresses.toList().any { a-> a is Inet4Address && a.isSiteLocalAddress }
    }.map { mapOf("id" to it.name,"name" to (it.name+" · "+it.inetAddresses.toList().filterIsInstance<Inet4Address>().joinToString{a->a.hostAddress?:""})) }
    fun status(c:Context):Map<String,Any?> = mapOf("supported" to true,"enabled" to prefs(c).getBoolean("vpnSharing",false),"interface" to prefs(c).getString("sharingInterface",""),"candidates" to candidates(),"message" to lastError)
    private fun vpn(c:Context):String {
        if(!Engine.isUp())return "-"
        val cm=c.getSystemService(ConnectivityManager::class.java)
        return cm.allNetworks.firstNotNullOfOrNull { network ->
            if(cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true)cm.getLinkProperties(network)?.interfaceName else null
        }?:"-"
    }
    private fun root(c:Context,mode:String,down:String,vpn:String) {
        require(mode=="enable"||mode=="disable")
        require(down=="-"||Regex("[a-zA-Z0-9_-]{1,15}").matches(down))
        require(vpn=="-"||Regex("[a-zA-Z0-9_-]{1,15}").matches(vpn))
        val executable=listOf("/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su","/debug_ramdisk/su").firstOrNull { File(it).canExecute() }
            ?: throw IllegalStateException("Необходим root")
        val p=ProcessBuilder(executable,"-c","sh -s -- $mode $down $vpn").redirectErrorStream(true).start()
        val out=java.io.ByteArrayOutputStream()
        val reader=Thread{p.inputStream.use { stream-> val b=ByteArray(4096);while(true){val n=stream.read(b);if(n<0)break;if(out.size()<32768)out.write(b,0,n)} }}.also{it.start()}
        p.outputStream.use { stream -> c.assets.open("flutter_assets/assets/vpn-sharing.sh").use { it.copyTo(stream) } }
        if(!p.waitFor(25,TimeUnit.SECONDS)){p.destroyForcibly();throw IllegalStateException("Необходим root: доступ не подтверждён")}
        reader.join(1000)
        if(p.exitValue()!=0)throw IllegalStateException(if(p.exitValue()==77||out.toString().contains("denied",true))"Необходим root" else "Не удалось настроить раздачу через VPN. Проверьте root, интерфейс и поддержку netfilter.")
    }
    @Synchronized fun set(c:Context,enabled:Boolean,iface:String):Map<String,Any?> {
        if(enabled){
            require(SplitRouting(c).read().mode=="all"){"Для VPN при раздаче отключите раздельное туннелирование"}
            // Check root before interface validation so stock phones get the exact prerequisite.
            val exists=listOf("/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su","/debug_ramdisk/su").any{File(it).canExecute()}
            check(exists){"Необходим root"}
            require(candidates().any{it["id"]==iface}){"Включите модем или точку доступа и выберите интерфейс раздачи"}
            try { root(c,"enable",iface,vpn(c)) } catch(e:Exception) {
                // A partially installed first setup must remain recoverable.
                runCatching { root(c,"disable","-","-") }
                throw e
            }
            prefs(c).edit().putBoolean("vpnSharing",true).putString("sharingInterface",iface).commit()
            lastError="Перезапустите раздачу после отключения аппаратного ускорения. IPv6 раздачи блокируется."
        }else{
            if(prefs(c).getBoolean("vpnSharing",false))root(c,"disable","-","-")
            prefs(c).edit().putBoolean("vpnSharing",false).remove("sharingInterface").commit();lastError=""
        }
        lastVpn="";lastApplied=0L
        return status(c)
    }
    fun schedule(c:Context,force:Boolean=false) {
        if(!prefs(c).getBoolean("vpnSharing",false)||working)return
        val now=android.os.SystemClock.elapsedRealtime();val current=vpn(c)
        if(!force&&current==lastVpn&&now-lastApplied<30000)return
        working=true
        Engine.worker.execute{try {
            synchronized(this){root(c,"enable",prefs(c).getString("sharingInterface","")!!,current);lastVpn=current;lastApplied=now}
        }catch(e:Exception){lastError=e.message?:"Не удалось обновить маршрут раздачи"}finally{working=false}}
    }
}
