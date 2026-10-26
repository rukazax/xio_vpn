package app.xio.xio

import android.content.Context
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.pm.PackageManager
import java.io.File

object UpdateInstaller {
    fun install(context: Context, path: String) {
        require(context.packageManager.getApplicationInfo(context.packageName,PackageManager.GET_META_DATA).metaData?.getBoolean("xio.externalUpdates", false) == true)
        val file = File(path).canonicalFile
        require(file.parentFile == File(context.filesDir,"update-staging").canonicalFile && file.extension == "apk" && file.isFile)
        @Suppress("DEPRECATION")
        val candidate = context.packageManager.getPackageArchiveInfo(file.path,PackageManager.GET_SIGNATURES) ?: error("Invalid APK")
        @Suppress("DEPRECATION")
        val installed = context.packageManager.getPackageInfo(context.packageName,PackageManager.GET_SIGNATURES)
        @Suppress("DEPRECATION")
        require(candidate.packageName == context.packageName && candidate.versionCode > installed.versionCode && candidate.signatures?.map { it.toCharsString() }?.toSet() == installed.signatures?.map { it.toCharsString() }?.toSet())
        if (!context.packageManager.canRequestPackageInstalls()) {
            context.startActivity(Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,android.net.Uri.parse("package:${context.packageName}")))
            error("Allow installation and retry")
        }
        val uri = androidx.core.content.FileProvider.getUriForFile(context,"${context.packageName}.updates",file)
        context.startActivity(Intent(Intent.ACTION_VIEW).apply { setDataAndType(uri,"application/vnd.android.package-archive");addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK) })
    }
}
class UpdateCleanupReceiver: BroadcastReceiver() {
    override fun onReceive(context:Context,intent:Intent) {
        if(intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            File(context.filesDir,"update-staging").deleteRecursively()
            UpdateJob.schedule(context,null)
        }
    }
}
