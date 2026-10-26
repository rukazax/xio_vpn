package app.xio.xio

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import app.xio.openvpn.*
import org.json.JSONObject
import app.xio.mobile.Mobile
import app.xio.mobile.Protector
import java.net.Inet4Address
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Official OpenVPN 3 core. No Activity dependency or plaintext profile files. */
object OpenVpnBackend {
 init {System.loadLibrary("xio_openvpn")}
 private val nativeLock=Object()
 @Volatile private var client:Client?=null
 @Volatile private var thread:Thread?=null
 @Volatile var established=false
 @Volatile private var handshake=0L
 @Volatile private var secure=false
 fun validate(raw:String){
  require(raw.length<=65536)
  val j=JSONObject(raw);require(j.getString("protocol")=="cloak")
  val cfg=j.getString("config");require(cfg.length<=60000)
  var block=""
  for(original in cfg.lineSequence()){
   val line=original.trim();if(block.isNotEmpty()){if(line=="</$block>")block="";continue}
   if(line.isEmpty()||line.startsWith("#")||line.startsWith(";"))continue
   if(line.startsWith("<")){val tag=line.removePrefix("<").removeSuffix(">");require(tag in listOf("ca","cert","key","tls-auth","tls-crypt","tls-crypt-v2"));block=tag;continue}
   val fields=line.split(Regex("\\s+"));val key=fields[0]
   require(key !in listOf("config","up","down","plugin","script-security","route-up","ipchange","management","log","log-append","writepid","cd","chroot","askpass","tls-verify","auth-user-pass-verify"))
   require(key !in listOf("ca","cert","key","tls-auth","tls-crypt","tls-crypt-v2","pkcs12","crl-verify","extra-certs","secret"))
   if(key=="auth-user-pass")require(fields.size==1)
  };require(block.isEmpty())
 }
 fun status():JSONObject=synchronized(nativeLock){
  val s=client?.tun_stats()
  JSONObject().put("active",established).put("secure",secure).put("handshake",handshake).put("rx",s?.bytesIn?:0L).put("tx",s?.bytesOut?:0L)
 }
 fun stop(){
  val c=client;val t=thread;c?.stop();Mobile.cloakStop();if(t!=null&&t!==Thread.currentThread()){t.join(4000);check(!t.isAlive){"OpenVPN stop timeout"}}
  synchronized(nativeLock){client=null;thread=null;established=false;secure=false;handshake=0L;c?.delete()}
 }
 fun resolve(service:XioVpnService,host:String):String = PhysicalNetwork.resolve(service,host)
 fun connect(service:XioVpnService,id:String,raw:String,timeout:Long){
  var phase="validate"
  validate(raw);require(timeout>0);val j=JSONObject(raw);val c=Client(service);client=c
  val cfg=ClientAPI_Config();cfg.content=j.getString("config");cfg.tunPersist=true;cfg.compressionMode="no";cfg.connTimeout=((timeout+999)/1000).toInt();cfg.guiVersion="XIO";cfg.googleDnsFallback=false
  try{
   phase="evaluate";val eval=c.eval_config(cfg);check(!eval.error){"OpenVPN profile rejected"}
   if(j.getString("protocol")=="cloak"){
    go.Seq.setContext(service.applicationContext)
    val protector=object:Protector{override fun protect(fd:Long)=fd>=0&&fd<=Int.MAX_VALUE&&service.protect(fd.toInt());override fun resolve(host:String)=try{OpenVpnBackend.resolve(service,host)}catch(_:Exception){""}}
    phase="cloak-start";val port=Mobile.cloakStart(raw,protector,timeout)
    cfg.serverOverride="127.0.0.1";cfg.portOverride=port.toString();cfg.protoOverride="tcp"
   }else cfg.serverOverride=resolve(service,eval.remoteHost)
   phase="evaluate-resolved";val checked=c.eval_config(cfg);check(!checked.error)
   if(!checked.autologin){val creds=ClientAPI_ProvideCreds();creds.username=j.optString("username");creds.password=j.optString("password");check(!c.provide_creds(creds).error)}
   phase="connect"
   thread=Thread({try{val result=c.connect();if(result.error){android.util.Log.w("XIO/OpenVPN",result.status);c.failed=true}}catch(_:Exception){c.failed=true}finally{secure=false;c.ready.countDown()}},"XIO-OpenVPN").also{it.start()}
   check(c.ready.await(timeout,TimeUnit.MILLISECONDS)&&!c.failed&&established&&secure){"OpenVPN connection failed"}
   service.getSharedPreferences("xio",0).edit().putString("activeId",id).putBoolean("vpnWanted",true).commit();XioVpnService.stateChanged(true)
  }catch(e:Exception){android.util.Log.w("XIO/OpenVPN",phase+" "+e.javaClass.simpleName);stop();throw e}finally{cfg.delete()}
 }
 private class Client(val service:XioVpnService):ClientAPI_OpenVPNClient(){
  val ready=CountDownLatch(1);@Volatile var failed=false
  var builder:VpnService.Builder?=null
  var dns=false;var ipv6=false
  override fun socket_protect(socket:Int,remote:String,ipv6:Boolean)=service.protect(socket)
  override fun tun_builder_new():Boolean {builder=service.rivetBuilder().setSession("XIO VPN").setMtu(1280).setBlocking(false);dns=false;ipv6=false;return true}
  override fun tun_builder_set_layer(layer:Int)=layer==3
  override fun tun_builder_set_remote_address(address:String,ipv6:Boolean)=true
  override fun tun_builder_add_address(address:String,prefix_length:Int,gateway:String,ipv6:Boolean,net30:Boolean):Boolean{builder!!.addAddress(address,prefix_length);if(ipv6)this.ipv6=true;return true}
  override fun tun_builder_set_route_metric_default(metric:Int)=true
  override fun tun_builder_reroute_gw(ipv4:Boolean,ipv6:Boolean,flags:Long)=true
  override fun tun_builder_add_route(address:String,prefix_length:Int,metric:Int,ipv6:Boolean)=true
  override fun tun_builder_exclude_route(address:String,prefix_length:Int,metric:Int,ipv6:Boolean)=true
  override fun tun_builder_set_dns_options(options:DnsOptions):Boolean {
   for(s in options.servers.values)for(a in s.addresses){if(a.port!=0L&&a.port!=53L)return false;builder!!.addDnsServer(a.address);dns=true};return true
  }
  override fun tun_builder_set_mtu(mtu:Int):Boolean{builder!!.setMtu(mtu.coerceIn(1280,9000));return true}
  override fun tun_builder_set_session_name(name:String)=true
  override fun tun_builder_set_allow_family(af:Int,allow:Boolean)=true
  override fun tun_builder_set_allow_local_dns(allow:Boolean)=!allow
  override fun tun_builder_establish():Int {
   if(!dns)builder!!.addDnsServer("9.9.9.9")
   if(!ipv6)builder!!.addAddress("fd00:7869:6f::2",128)
   SplitRouting(service).applyNative(builder!!)
   val p=builder!!.establish()?:return -1;established=true;return p.detachFd()
  }
  override fun tun_builder_persist()=true
  override fun tun_builder_teardown(disconnect:Boolean){if(disconnect)established=false}
  override fun event(event:ClientAPI_Event){
   android.util.Log.i("XIO/OpenVPN",event.name)
   if(event.name=="CONNECTED"){secure=true;handshake=System.currentTimeMillis();ready.countDown()}
   if(event.name in listOf("RECONNECTING","DISCONNECTED"))secure=false
   if(event.fatal){failed=true;secure=false;ready.countDown()}
  }
  override fun log(info:ClientAPI_LogInfo){} // Profiles, peer addresses and keys never enter Android logs.
  override fun external_pki_cert_request(req:ClientAPI_ExternalPKICertRequest){req.error=true;req.errorText="External PKI unavailable"}
  override fun external_pki_sign_request(req:ClientAPI_ExternalPKISignRequest){req.error=true;req.errorText="External PKI unavailable"}
 }
}
