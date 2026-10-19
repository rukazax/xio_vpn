package app.x1o.x1o

import app.xio.mobile.Mobile
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.view.WindowManager
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.config.Config
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.ByteArrayInputStream
import java.util.concurrent.Executors

/** One owner across activity recreation. */
object Engine {
    lateinit var backend: GoBackend
    lateinit var app: android.content.Context
    @Volatile var backgroundBusy = false
    var kind = "awg"
    var lastConnectMillis=0L
    fun isUp()=OpenVpnBackend.established || XrayBackend.established || RivetBackend.established || backend.getState(tunnel)==Tunnel.State.UP
    fun handshake():Long {
        if(kind=="cloak"){val v=OpenVpnBackend.status();return if(v.optBoolean("secure"))v.optLong("handshake") else 0L}
        if(kind=="xray"){val v=XrayBackend.status();return if(v.optBoolean("secure"))v.optLong("handshake") else 0L}
        if(kind.startsWith("rivet-")){val v=RivetBackend.status();return if(v.optBoolean("secure"))v.optLong("handshake") else 0L}
        val stats=backend.getStatistics(tunnel);return stats.peers().mapNotNull{stats.peer(it)?.latestHandshakeEpochMillis()}.maxOrNull()?:0L
    }
    fun status():Map<String,Any?> {
        val prefs=app.getSharedPreferences("x1o",0);val up=isUp()
        if(kind=="xray"||kind=="cloak"){val v=if(kind=="cloak")OpenVpnBackend.status() else XrayBackend.status();if(!up)prefs.edit().remove("activeId").commit();return mapOf("active" to up,"id" to prefs.getString("activeId",null),"rx" to v.optLong("rx"),"tx" to v.optLong("tx"),"handshake" to handshake(),"protocol" to kind)}
        if(kind.startsWith("rivet-")){
            val value=RivetBackend.status();val actual=value.optString("protocol",kind);kind=actual
            if(up){
                val oldId=prefs.getString("activeId",null)
                if(oldId!=null){try{
                    val old=org.json.JSONObject(ConfigVault(app).readSecret(oldId))
                    if(old.optString("protocol")!=actual){
                        val ids=org.json.JSONObject(prefs.getString("connectionPlan","{}")!!).optJSONArray("ids")
                        if(ids!=null)for(i in 0 until ids.length()){
                            val candidate=ids.getString(i);if(!candidate.startsWith("rv"))continue
                            val cfg=org.json.JSONObject(ConfigVault(app).readSecret(candidate))
                            if(cfg.optString("id")==old.optString("id")&&cfg.optString("protocol")==actual){prefs.edit().putString("activeId",candidate).commit();break}
                        }
                    }
                }catch(_:Exception){}}
            }
            if(!up)prefs.edit().remove("activeId").commit()
            return mapOf("active" to up,"id" to prefs.getString("activeId",null),"rx" to value.optLong("rx"),"tx" to value.optLong("tx"),"handshake" to handshake(),"protocol" to actual,"phase" to value.optString("phase"))
        }
        if(!up)prefs.edit().remove("activeId").commit()
        val stats=if(up)backend.getStatistics(tunnel) else null
        return mapOf("active" to up,"id" to prefs.getString("activeId",null),"rx" to stats?.totalRx(),"tx" to stats?.totalTx(),"handshake" to if(up)handshake() else null,"protocol" to kind)
    }
    val worker = Executors.newSingleThreadExecutor()
    val tunnel = object : Tunnel {
        override fun getName() = "x1o0"
        override fun onStateChange(state: Tunnel.State) {
            if (state == Tunnel.State.DOWN) app.getSharedPreferences("x1o", 0).edit().remove("activeId").commit()
            X1oVpnService.stateChanged(state == Tunnel.State.UP)
            VpnTileService.refresh(app)
        }
    }
    @Synchronized fun initialize(context: android.content.Context) {
        app = context.applicationContext
        GoBackend.setVpnServiceClass(X1oVpnService::class.java)
        if (!::backend.isInitialized) backend = GoBackend(app)
    }
    fun disconnect() {
        app.getSharedPreferences("x1o",0).edit().putBoolean("vpnWanted",false).commit()
        OpenVpnBackend.stop()
        XrayBackend.stop()
        if(kind.startsWith("rivet-") || RivetBackend.established) RivetBackend.stop()
        backend.setState(tunnel, Tunnel.State.DOWN, null)
        VpnSharing.schedule(app,true)
        app.stopService(Intent(app,X1oVpnService::class.java))
        X1oVpnService.awaitStopped()
        app.getSharedPreferences("x1o", 0).edit().remove("activeId").commit()
    }
    private fun vpnNetworks(): Set<android.net.Network> {
        val cm=app.getSystemService(android.net.ConnectivityManager::class.java)
        return cm.allNetworks.filter{cm.getNetworkCapabilities(it)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)==true}.toSet()
    }
    private fun awaitNetworkReady(previous:Set<android.net.Network>,started:Long) {
        val policy=SplitRouting(app).read()
        val usesVpn=when(policy.mode){"include"->policy.packages.contains(app.packageName);"exclude"->!policy.packages.contains(app.packageName);else->true}
        if(!usesVpn)return // The visible split policy intentionally excludes this app.
        val cm=app.getSystemService(android.net.ConnectivityManager::class.java)
        val budget=org.json.JSONObject(app.getSharedPreferences("x1o",0).getString("connectionPlan","{}")!!).optInt("timeoutSeconds",15).coerceIn(5,60)*1000L
        val waiting=android.os.SystemClock.elapsedRealtime();val deadline=minOf(started+budget,waiting+5000L)
        while(android.os.SystemClock.elapsedRealtime()<deadline){
            val current=vpnNetworks()-previous
            if(current.any{cm.getLinkProperties(it)?.interfaceName!=null&&(policy.mode.startsWith("ip")||cm.activeNetwork==it)}){
                android.util.Log.i("XIO/Network","VPN route ready in "+(android.os.SystemClock.elapsedRealtime()-waiting)+"ms");return
            }
            Thread.sleep(50)
        }
        error("VPN network not ready")
    }
    fun connect(id: String, allowExistingService: Boolean = false) {
        check(app.getSharedPreferences("x1o",0).getString("consentRevision",null)=="2026-10-18") { "Open XIO and review VPN disclosure" }
        check(!isUp())
        val started=android.os.SystemClock.elapsedRealtime()
        val previousNetworks=vpnNetworks()
        if(!allowExistingService) X1oVpnService.awaitStopped()
        val raw=ConfigVault(app).readSecret(id)
        if(id.startsWith("ck")){
            kind="cloak"
            app.startForegroundService(Intent(app,X1oVpnService::class.java))
            val service=X1oVpnService.awaitCreated()
            val budget=org.json.JSONObject(app.getSharedPreferences("x1o",0).getString("connectionPlan","{}")!!).optInt("timeoutSeconds",15).coerceIn(5,60)*1000L
            OpenVpnBackend.connect(service,id,raw,budget-(android.os.SystemClock.elapsedRealtime()-started))
            awaitNetworkReady(previousNetworks,started)
            lastConnectMillis=android.os.SystemClock.elapsedRealtime()-started
            VpnTileService.refresh(app);return
        }
        if(id.startsWith("xr")){
            kind="xray"
            require(org.json.JSONObject(raw).getString("protocol")==kind)
            app.startForegroundService(Intent(app,X1oVpnService::class.java))
            val service=X1oVpnService.awaitCreated()
            val budget=org.json.JSONObject(app.getSharedPreferences("x1o",0).getString("connectionPlan","{}")!!).optInt("timeoutSeconds",15).coerceIn(5,60)*1000L
            XrayBackend.connect(service,id,raw,budget-(android.os.SystemClock.elapsedRealtime()-started))
            awaitNetworkReady(previousNetworks,started)
            lastConnectMillis=android.os.SystemClock.elapsedRealtime()-started
            VpnTileService.refresh(app);return
        }
        if(id.startsWith("rvh")||id.startsWith("rvs")){
            val cfg=org.json.JSONObject(raw);kind=cfg.getString("protocol")
            require(kind==if(id.startsWith("rvh"))"rivet-h3" else "rivet-s1")
            app.startForegroundService(Intent(app,X1oVpnService::class.java))
            val service=X1oVpnService.awaitCreated()
            val budget=org.json.JSONObject(app.getSharedPreferences("x1o",0).getString("connectionPlan","{}")!!).optInt("timeoutSeconds",15).coerceIn(5,60)*1000L
            val left=budget-(android.os.SystemClock.elapsedRealtime()-started);check(left>0)
            RivetBackend.connect(service,id,raw,left)
            awaitNetworkReady(previousNetworks,started)
            lastConnectMillis=android.os.SystemClock.elapsedRealtime()-started
            VpnTileService.refresh(app);return
        }
        val config = Config.parse(ByteArrayInputStream(raw.toByteArray()))
        require(id.startsWith("awg"));kind = "awg"
        val routing = SplitRouting(app)
        val policy = routing.read()
        val effective = routing.apply(config, policy)
        backend.setAllowUnroutedFamilies(policy.mode.startsWith("ip"))
        backend.setState(tunnel, Tunnel.State.UP, effective)
        app.getSharedPreferences("x1o",0).edit().putBoolean("vpnWanted",true).commit()
        app.getSharedPreferences("x1o", 0).edit().putString("activeId", id).commit()
        awaitNetworkReady(previousNetworks,started)
        lastConnectMillis=android.os.SystemClock.elapsedRealtime()-started
    }

}

class MainActivity : FlutterActivity() {
    private var pending: MethodChannel.Result? = null
    private var pendingId: String? = null
    private var pendingFile: MethodChannel.Result? = null
    private lateinit var engineChannel: MethodChannel
    private val prefs by lazy { getSharedPreferences("x1o", MODE_PRIVATE) }
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        AppIcons.ensureLauncher(this)
        Engine.initialize(this)
        engineChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "app.x1o/engine")
        engineChannel.setMethodCallHandler { call, result ->
            when (call.method) {
                "supportedProtocols" -> result.success(listOf("awg","rivet-h3","rivet-s1","xray","cloak"))
                "sharingStatus" -> result.success(VpnSharing.status(this))
                "sharingSet" -> Engine.worker.execute { try { val value=VpnSharing.set(this,call.argument<Boolean>("enabled")==true,call.argument<String>("interface")?:"");runOnUiThread{result.success(value)} } catch(e:Exception){runOnUiThread{result.error("SHARING",e.message?:"Не удалось настроить раздачу",null)}} }
                "connectionBusy" -> result.success(Engine.backgroundBusy)
                "getAppIcon" -> result.success(AppIcons.current(this))
                "setAppIcon" -> {
                    try { AppIcons.select(this, call.arguments as String); result.success(null) }
                    catch (_: Exception) { result.error("ICON", "Не удалось выполнить действие", null) }
                }
                "setLanguage" -> {
                    try { L10n.select(this, call.arguments as String); result.success(null) }
                    catch (_: Exception) { result.error("LANGUAGE", "Не удалось выполнить действие", null) }
                }
                "pickBundle" -> {
                    if (pendingFile != null) { result.error("BUSY", "Выбор файла уже открыт", null); return@setMethodCallHandler }
                    pendingFile = result
                    startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply { type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE) }, 873)
                }
                "shareBundle" -> {
                    try {
                        val raw = call.argument<String>("bundle") ?: ""
                        require((raw.startsWith("xio://") || raw.startsWith("x1o://") || raw.startsWith("xio-server://")) && raw.length <= 200000)
                        if (call.argument<Boolean>("asText") == true) {
                            startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, raw) }, "XIO"))
                            result.success(null); return@setMethodCallHandler
                        }
                        val dir = File(cacheDir, "shared_profiles").apply { mkdirs() }
                        dir.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > 3600000 }?.forEach { it.delete() }
                        val file = File(dir, "XIO-${java.util.UUID.randomUUID()}.xio").apply { writeText(raw) }
                        val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.profiles", file)
                        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                            type = "application/octet-stream"; putExtra(Intent.EXTRA_STREAM, uri)
                            clipData = android.content.ClipData.newRawUri("XIO", uri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }, L10n.text(this, "Поделиться профилем XIO")))
                        android.os.Handler(mainLooper).postDelayed({ file.delete() }, 3600000)
                        result.success(null)
                    } catch (_: Exception) { result.error("SHARE", "Не удалось открыть общий доступ", null) }
                }
                "addQuickTile" -> {
                    if (android.os.Build.VERSION.SDK_INT >= 33) {
                        getSystemService(android.app.StatusBarManager::class.java).requestAddTileService(
                            android.content.ComponentName(this, VpnTileService::class.java), "XIO VPN",
                            android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_vpn), mainExecutor
                        ) { code -> result.success(code) }
                    } else result.success(-1)
                }
                "prepareUpdateInstall" -> {
                    val allowed=packageManager.canRequestPackageInstalls()
                    if(!allowed)startActivity(Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,android.net.Uri.parse("package:$packageName")))
                    result.success(allowed)
                }
                "consumeUpdateRequest" -> { val requested=intent.getBooleanExtra("checkUpdates",false);intent.removeExtra("checkUpdates");result.success(requested) }
                "updateAbi" -> result.success(android.os.Build.SUPPORTED_ABIS.firstOrNull { it in listOf("arm64-v8a","armeabi-v7a","x86_64") } ?: "unsupported")
                "scheduleUpdateCheck" -> { UpdateJob.schedule(this,call.argument<Number>("at")?.toLong()); result.success(null) }
                "installUpdate" -> {
                    try { UpdateInstaller.install(this, call.argument<String>("path") ?: ""); result.success(null) }
                    catch (_: Exception) { result.error("UPDATE", "Установка обновления не завершена", null) }
                }
                "openExternalLink" -> {
                    try {
                        val uri = android.net.Uri.parse(call.argument<String>("url") ?: "")
                        require(uri.scheme == "https" && uri.userInfo == null)
                        startActivity(Intent(Intent.ACTION_VIEW,uri)); result.success(null)
                    } catch (_: Exception) { result.error("LINK","Не удалось открыть ссылку",null) }
                }
                "shareApplication" -> {
                    startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type="text/plain";putExtra(Intent.EXTRA_TEXT,call.argument<String>("text")) },"XIO"));result.success(null)
                }
                "openSupportLink" -> {
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://x1o.org/pay")))
                        result.success(null)
                    } catch (_: Exception) { result.error("LINK", "Не удалось открыть ссылку", null) }
                }
                "notificationSettings" -> {
                    startActivity(Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, packageName))
                    result.success(null)
                }
                "secureScreen" -> {
                    if (call.argument<Boolean>("enabled") == true) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    result.success(null)
                }
                "connect" -> {
                    if (pending != null) { result.error("BUSY", "Ожидается разрешение VPN", null); return@setMethodCallHandler }
                    val id = call.argument<String>("id") ?: ""
                    pending = result; pendingId = id
                    if (android.os.Build.VERSION.SDK_INT >= 33 &&
                        checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED &&
                        !prefs.getBoolean("notificationAsked", false)) {
                        prefs.edit().putBoolean("notificationAsked", true).apply()
                        requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 872)
                    } else preparePendingVpn()
                }
                else -> Engine.worker.execute {
                    try {
                        val value: Any? = when (call.method) {
                            "setConsent" -> {
                                val revision=call.argument<String>("revision") ?: ""
                                require(revision=="" || revision=="2026-10-18")
                                prefs.edit().putString("consentRevision",revision).commit();null
                            }
                            "consumeConnectRequest" -> {
                                val requested = prefs.getBoolean("connectRequested", false)
                                prefs.edit().remove("connectRequested").commit()
                                requested
                            }
                            "routingGet" -> SplitRouting(this).read().map()
                            "routingApps" -> SplitRouting(this).applications()
                            "routingSave" -> {
                                if (Engine.isUp())
                                    throw RoutingException("Сначала отключите VPN, затем сохраните правила")
                                SplitRouting(this).save(call.argument<String>("mode") ?: "", call.argument<List<String>>("packages") ?: emptyList(), call.argument<List<String>>("networks") ?: emptyList()).map()
                            }
                            "dataDirectory" -> filesDir.absolutePath
                            "saveConfig" -> {
                                val id = call.argument<String>("id")!!
                                val raw = call.argument<String>("config")!!
                                require(raw.length <= 65536)
                                if(id.startsWith("ck"))OpenVpnBackend.validate(raw) else if(id.startsWith("xr"))Mobile.xrayValidate(raw) else if(id.startsWith("rvh")||id.startsWith("rvs"))Mobile.validate(raw) else { require(id.startsWith("awg")); Config.parse(ByteArrayInputStream(raw.toByteArray())) }
                                ConfigVault(this).writeSecret(id, raw); null
                            }
                            "credentialRead" -> {
                                val id = call.argument<String>("id")!!
                                if (ConfigVault(this).contains(id)) ConfigVault(this).readSecret(id) else null
                            }
                            "credentialWrite" -> {
                                val id = call.argument<String>("id")!!
                                require(id.startsWith("ssh"))
                                val value = call.argument<String>("value")!!
                                require(value.length <= 32768)
                                ConfigVault(this).writeSecret(id, value); null
                            }
                            "credentialDelete" -> { ConfigVault(this).delete(call.argument<String>("id")!!); null }
                            "saveConnectionPlan" -> {
                                val raw = call.arguments as String
                                require(raw.length <= 32768)
                                prefs.edit().putString("connectionPlan", raw).commit(); null
                            }
                            "readConfig" -> ConfigVault(this).readSecret(call.argument<String>("id")!!)
                            "deleteConfig" -> { ConfigVault(this).delete(call.argument<String>("id")!!);null }
                            "activeId" -> prefs.getString("activeId", null)
                            "disconnect" -> {
                                Engine.disconnect(); null
                            }
                            "status" -> Engine.status()
                            else -> throw UnsupportedOperationException("Unknown method")
                        }
                        runOnUiThread { result.success(value) }
                    } catch (e: Exception) {
                        runOnUiThread { result.error("ENGINE", if (e is RoutingException) e.message else "Не удалось выполнить операцию VPN", null) }
                    }
                }
            }
        }
    }
    private fun connect(id: String, result: MethodChannel.Result) {
        Engine.worker.execute {
            try {
                Engine.connect(id)
                runOnUiThread { result.success(mapOf("connectMillis" to Engine.lastConnectMillis)) }
            } catch (e: Exception) {
                runOnUiThread { result.error(if (e is RoutingException) "ROUTING" else "VPN", if (e is RoutingException) e.message else "Не удалось запустить VPN-движок", null) }
            }
        }
    }

    private fun preparePendingVpn() {
        val id=pendingId?:return
        val intent=VpnService.prepare(this)
        if (intent != null) {
            @Suppress("DEPRECATION") startActivityForResult(intent, 871)
        } else {
            val callback = pending ?: return
            val id = pendingId ?: ""
            pending = null; pendingId = null
            connect(id, callback)
        }
    }
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 872 && pending != null) preparePendingVpn()
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if(intent.getBooleanExtra("checkUpdates",false) && ::engineChannel.isInitialized) engineChannel.invokeMethod("requestUpdates",null)
        handleTileIntent()
    }
    override fun onPostResume() {
        super.onPostResume()
        handleTileIntent()
    }
    private fun handleTileIntent() {
        if (intent?.action != "app.x1o.CONNECT_SELECTED") return
        intent.action = Intent.ACTION_MAIN
        prefs.edit().putBoolean("connectRequested", true).commit()
        if (::engineChannel.isInitialized) engineChannel.invokeMethod("requestConnect", null)
    }
    @Deprecated("Android compatibility callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 873) {
            val callback = pendingFile ?: return
            pendingFile = null
            if (resultCode != Activity.RESULT_OK) { callback.success(null); return }
            try {
                val uri = data?.data ?: throw IllegalArgumentException()
                val bytes = contentResolver.openInputStream(uri)!!.use { input ->
                    val out = java.io.ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    while (out.size() <= 200000) {
                        val count = input.read(buffer, 0, minOf(buffer.size, 200001 - out.size()))
                        if (count < 0) break
                        out.write(buffer, 0, count)
                    }
                    out.toByteArray()
                }
                require(bytes.size <= 200000)
                callback.success(bytes.toString(Charsets.UTF_8))
            } catch (_: Exception) { callback.error("IMPORT", "Не удалось прочитать профиль", null) }
        }
        if (requestCode == 871) {
            val callback = pending ?: return
            val id = pendingId ?: ""
            pending = null; pendingId = null
            if (resultCode == Activity.RESULT_OK) connect(id, callback)
            else callback.error("DENIED", "Разрешение VPN не предоставлено", null)
        }
    }
}
