package app.x1o.x1o
import android.content.Context
import android.content.Intent
import android.net.*
import android.os.Build
import android.os.Process
import android.os.SystemClock
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Android's system IKEv2 implementation owns the tunnel independently of UI. */
object IkeBackend {
 @Volatile private var started=0L
 private fun manager(context:Context):VpnManager{check(Build.VERSION.SDK_INT>=30){"IKEv2 requires Android 11"};return context.getSystemService(VpnManager::class.java)}
 fun validate(raw:String){
  require(raw.length<=65536);val j=JSONObject(raw);require(j.getString("protocol")=="ikev2")
  for(key in listOf("server","identity","username","password")){val value=j.getString(key);require(value.isNotEmpty()&&value.length<=512&&!value.contains('\n')&&!value.contains('\r')&&!value.contains('\u0000'))}
  val ca=j.getString("ca");require(ca.length<=16384);val c=CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(ca.toByteArray())) as X509Certificate;c.checkValidity();require(c.basicConstraints>=0)
 }
 fun prepare(context:Context,id:String):Intent?{
  check(SplitRouting(context).read().mode=="all"){"System IKEv2 does not support the configured split rules"}
  val raw=ConfigVault(context).readSecret(id);validate(raw);val j=JSONObject(raw)
  val ca=CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(j.getString("ca").toByteArray())) as X509Certificate
  val b=Ikev2VpnProfile.Builder(j.getString("server"),j.getString("identity")).setAuthUsernamePassword(j.getString("username"),j.getString("password"),ca).setMaxMtu(1280).setBypassable(false).setMetered(false)
  if(Build.VERSION.SDK_INT>=33)b.setRequiresInternetValidation(false)
  val intent=manager(context).provisionVpnProfile(b.build())
  context.getSharedPreferences("x1o",0).edit().putString("ikeProvisionedId",id).commit();return intent
 }
 fun isUp(context:Context):Boolean {
  if(Build.VERSION.SDK_INT<30)return false
  return try {
   if(Build.VERSION.SDK_INT>=33)manager(context).provisionedVpnProfileState?.state==VpnProfileState.STATE_CONNECTED
   else {val cm=context.getSystemService(ConnectivityManager::class.java);cm.allNetworks.any{val c=cm.getNetworkCapabilities(it);c?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true&&c.ownerUid==Process.myUid()}}
  }catch(_:Exception){false}
 }
 fun handshake(context:Context):Long=if(isUp(context)) {if(started==0L)started=System.currentTimeMillis();started} else 0L
 fun connect(context:Context,id:String,timeout:Long){
  check(timeout>0);check(SplitRouting(context).read().mode=="all")
  val prefs=context.getSharedPreferences("x1o",0);check(prefs.getString("ikeProvisionedId",null)==id){"IKEv2 profile requires system authorization"}
  try {
   if(Build.VERSION.SDK_INT>=33)manager(context).startProvisionedVpnProfileSession() else manager(context).startProvisionedVpnProfile()
   val end=SystemClock.elapsedRealtime()+timeout
   while(SystemClock.elapsedRealtime()<end){if(isUp(context)){started=System.currentTimeMillis();prefs.edit().putString("activeId",id).putBoolean("vpnWanted",true).commit();return};Thread.sleep(100)}
   error("IKEv2 connection timeout")
  }catch(e:Exception){stop(context);throw e}
 }
 fun stop(context:Context){if(Build.VERSION.SDK_INT>=30)try{manager(context).stopProvisionedVpnProfile()}catch(_:Exception){};started=0L}
 fun delete(context:Context,id:String){val prefs=context.getSharedPreferences("x1o",0);if(Build.VERSION.SDK_INT>=30&&prefs.getString("ikeProvisionedId",null)==id){stop(context);manager(context).deleteProvisionedVpnProfile();prefs.edit().remove("ikeProvisionedId").commit()}}
}
