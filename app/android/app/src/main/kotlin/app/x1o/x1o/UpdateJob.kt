package app.x1o.x1o
import android.app.job.*
import android.content.*
import android.app.*
import android.content.pm.PackageManager
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom

/** Metadata check only. No background package download or installation. */
class UpdateJob: JobService() {
    @Volatile private var stopped = false
    private var connection: HttpURLConnection? = null
    override fun onStartJob(params:JobParameters):Boolean {
        if(packageManager.getApplicationInfo(packageName,PackageManager.GET_META_DATA).metaData?.getBoolean("xio.externalUpdates",false)!=true)return false
        stopped=false
        Thread {
            try {
                val c=URL("https://api.github.com/repos/rukazax/xio_vpn/releases?per_page=30").openConnection() as HttpURLConnection
                connection=c;c.connectTimeout=15000;c.readTimeout=15000;c.instanceFollowRedirects=false;c.setRequestProperty("User-Agent","XIO-Android-update")
                if(c.responseCode==200) {
                    val buffer=java.io.ByteArrayOutputStream()
                    c.inputStream.use { input -> val chunk=ByteArray(8192);var count=input.read(chunk);while(count>=0){buffer.write(chunk,0,count);require(buffer.size()<=2*1024*1024);count=input.read(chunk)} }
                    val releases=JSONArray(buffer.toString("UTF-8"))
                    val skipped=runCatching { org.json.JSONObject(java.io.File(filesDir,"updates.json").readText()).optString("skip") }.getOrDefault("")
                    @Suppress("DEPRECATION") val current=packageManager.getPackageInfo(packageName,0).versionName ?: "0.0.0"
                    var latest=""
                    for(i in 0 until releases.length()) {
                        val r=releases.getJSONObject(i);val tag=r.optString("tag_name")
                        val signedAsset=r.optJSONArray("assets")?.let { assets -> (0 until assets.length()).any { assets.getJSONObject(it).optString("name")=="XIO-update.json" } } == true
                        if(!r.optBoolean("draft") && Regex("""v[0-9]+[.][0-9]+[.][0-9]+""").matches(tag) && newer(tag.drop(1),current) && signedAsset && (latest.isEmpty() || newer(tag.drop(1),latest.drop(1)))) latest=tag
                    }
                    if(latest.isNotEmpty() && latest!=skipped && !stopped) notifyUpdate()
                }
            } catch(_:Exception) { /* No retry storm on network errors. */ }
            finally { connection?.disconnect();if(!stopped){ jobFinished(params,false);android.os.Handler(mainLooper).postDelayed({schedule(this,null,true)},1000) } }
        }.start();return true
    }
    override fun onStopJob(params:JobParameters):Boolean { stopped=true;connection?.disconnect();return true }
    private fun notifyUpdate() {
        val manager=getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("updates", "XIO",NotificationManager.IMPORTANCE_DEFAULT))
        val pending=PendingIntent.getActivity(this,711,Intent(this,MainActivity::class.java).putExtra("checkUpdates",true).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        try { manager.notify(711,Notification.Builder(this,"updates").setSmallIcon(R.drawable.ic_vpn).setContentTitle("XIO").setContentText(L10n.text(this,"Проверить обновления")).setContentIntent(pending).setAutoCancel(true).build()) } catch(_:SecurityException) {}
    }
    companion object {
        private const val ID=711
        fun newer(a:String,b:String):Boolean {
            val left=a.split('.').mapNotNull{it.toIntOrNull()};val right=b.split('.').mapNotNull{it.toIntOrNull()}
            if(left.size!=3||right.size!=3)return false
            for(i in 0..2)if(left[i]!=right[i])return left[i]>right[i]
            return false
        }
        fun schedule(context:Context,at:Long?,replace:Boolean=false) {
            val scheduler=context.getSystemService(JobScheduler::class.java)
            if(context.packageManager.getApplicationInfo(context.packageName,PackageManager.GET_META_DATA).metaData?.getBoolean("xio.externalUpdates",false)!=true){scheduler.cancel(ID);return}
            if(!replace && scheduler.getPendingJob(ID)!=null)return
            val delay=if(at!=null)(at-System.currentTimeMillis()).coerceAtLeast(60000) else 7L*86400000+SecureRandom().nextInt(86400000)
            scheduler.schedule(JobInfo.Builder(ID,ComponentName(context,UpdateJob::class.java)).setMinimumLatency(delay).setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).setPersisted(true).setBackoffCriteria(300000L+SecureRandom().nextInt(300000),JobInfo.BACKOFF_POLICY_EXPONENTIAL).build())
        }
    }
}
