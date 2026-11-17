package app.xio.xio

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
    @Volatile var cleanupIncomplete = false
        private set
    @Volatile private var ownedRoundId: String? = null
    @Volatile private var operationBudget: ConnectionBudget? = null
    @Volatile private var activationRevoked = false
    private val publication = PublicationLease()
    fun registerConnect(budget:ConnectionBudget) = publication.register(budget)
    fun releaseConnect(budget:ConnectionBudget) = publication.release(budget)
    fun publicationToken() = publication.token()
    fun acceptsUpPublication(token:Long) = publication.accepts(token) && ConnectionBudget.canPublishUp(cleanupIncomplete,activationRevoked,operationBudget,token,publicationToken())
    /** Synchronous DOWN fence only: no JNI, fsync, status, TUN or teardown here. */
    /**
     * Synchronous DOWN activation fence only: no JNI, fsync, journal, status,
     * TUN or teardown here. Each DOWN caller also calls [revokeLogicalPolicy]
     * AFTER releasing every publication monitor.
     */
    fun revokePublication(roundId: String? = null) {
        synchronized(publication) {
            if(roundId != null && ownedRoundId != roundId) return
            publication.revoke()
            activationRevoked = true
            cleanupIncomplete = true
            operationBudget?.cancel()
        }
    }
    /**
     * Logical journal revocation plus physical settlement. Must run with NO
     * publication monitor held: the journal lane acquires that monitor, so
     * entering the journal while holding it would invert the lock order.
     */
    fun revokeLogicalPolicy() {
        PolicyBridge.revokeLogical()
        worker.execute { PolicyBridge.reconcileBlocked() }
    }
    fun cancelConnect(roundId: String? = null, expectedBudget:ConnectionBudget? = null):Long? {
        var globalDown = false
        val token=synchronized(publication) {
            if(roundId != null && ownedRoundId != roundId) return null
            if(roundId == null) revokePublication()
            if(roundId == null) globalDown = true
            if(roundId != null) {
                // Child failure is not DOWN. Match the exact child before any JNI cancel.
                if(!publication.retire(roundId,expectedBudget))return null
                activationRevoked=true;cleanupIncomplete=true
                operationBudget?.cancel()
            }
            publication.reserveCancellation()
            publication.token()
        }
        // Journal revocation only after the publication monitor is released.
        if(globalDown) revokeLogicalPolicy()
        try {
            if(kind == "awg") backend.cancelPendingHandshake()
            if(kind.startsWith("rivet-")) Mobile.cancelConnect()
        } finally { publication.finishCancellation() }
        return token
    }
    // Called only by the serialized worker: obsolete failure must not tear down a successor.
    fun disconnectOwned(roundId:String,expectedBudget:ConnectionBudget,budget:ConnectionBudget) {
        if(ownedRoundId==roundId && publication.owns(roundId,expectedBudget))disconnect(budget)
    }
    fun retireRound(roundId:String,budget:ConnectionBudget,expectedBudget:ConnectionBudget) {
        worker.execute {
            try { disconnectOwned(roundId,expectedBudget,budget) }catch(_:Exception) { /* Reservation stays incomplete. */ }
        }
    }
    /** Protocol the active rivet id was last reconciled against, so the vault
     *  is not decrypted on every status poll. */
    @Volatile var reconciledProtocol: String? = null
    fun acceptsUpPublication() = acceptsUpPublication(publicationToken())
    fun hasPublicationOwner() = ownedRoundId != null && acceptsUpPublication()
    fun requireActivation(token:Long=publicationToken()) {
        synchronized(publication) {
            check(acceptsUpPublication(token)) { "VPN activation revoked" }
            operationBudget?.remainingMillis()
        } // The admitted native call can be in flight; revocation never joins it here.
    }
    fun isUp(known: org.json.JSONObject? = null): Boolean {
        if(!acceptsUpPublication()) return false
        if(kind.startsWith("rivet-")) return RivetBackend.established && (known ?: RivetBackend.status()).optBoolean("active")
        return OpenVpnBackend.established || XrayBackend.established || backend.getState(tunnel)==Tunnel.State.UP
    }
    /** [known] reuses a status JSON already read by the caller: the rivet
     *  backend would otherwise be asked twice per poll. */
    fun handshake(known: org.json.JSONObject? = null):Long {
        if(kind=="cloak"){val v=known?:OpenVpnBackend.status();return if(v.optBoolean("secure"))v.optLong("handshake") else 0L}
        if(kind=="xray"){val v=known?:XrayBackend.status();return if(v.optBoolean("secure"))v.optLong("handshake") else 0L}
        if(kind.startsWith("rivet-")){val v=known?:RivetBackend.status();return if(v.optBoolean("secure"))v.optLong("handshake") else 0L}
        val stats=backend.getStatistics(tunnel);return stats.peers().mapNotNull{stats.peer(it)?.latestHandshakeEpochMillis()}.maxOrNull()?:0L
    }
    /** Clears the active id only when it is really stored: an unconditional
     *  `remove().commit()` rewrote the preferences file on every poll. */
    fun clearActiveId(prefs:android.content.SharedPreferences) {
        if(prefs.contains("activeId"))prefs.edit().remove("activeId").commit()
    }
    fun status():Map<String,Any?> {
        val prefs=app.getSharedPreferences("xio",0);val known=if(kind.startsWith("rivet-"))RivetBackend.status() else null;val up=isUp(known)
        if(kind=="xray"||kind=="cloak"){val v=if(kind=="cloak")OpenVpnBackend.status() else XrayBackend.status();if(!up)clearActiveId(prefs);return mapOf("active" to up,"id" to prefs.getString("activeId",null),"rx" to v.optLong("rx"),"tx" to v.optLong("tx"),"handshake" to handshake(v),"protocol" to kind)}
        if(kind.startsWith("rivet-")){
            val value=known!!;val actual=value.optString("protocol",kind);kind=actual
            if(up&&actual!=reconciledProtocol){
                // One decrypt per negotiated protocol, not one per poll.
                reconciledProtocol=actual
                val oldId=prefs.getString("activeId",null)
                if(oldId!=null){try{
                    val old=org.json.JSONObject(ConfigVault(app).readSecret(oldId))
                    if(old.optString("protocol")!=actual){
                        val candidates=PolicyBridge.candidateIds()
                        if(candidates!=null)for(candidate in candidates){
                            if(!candidate.startsWith("rv"))continue
                            val cfg=org.json.JSONObject(ConfigVault(app).readSecret(candidate))
                            if(cfg.optString("id")==old.optString("id")&&cfg.optString("protocol")==actual){prefs.edit().putString("activeId",candidate).commit();break}
                        }
                    }
                }catch(_:Exception){}}
            }
            if(!up && !value.optBoolean("recoveryPending") && !value.optBoolean("cleanupPending")){reconciledProtocol=null;clearActiveId(prefs)}
            return mapOf("active" to up,"id" to prefs.getString("activeId",null),"rx" to value.optLong("rx"),"tx" to value.optLong("tx"),"handshake" to handshake(value),"protocol" to actual,"phase" to value.optString("phase"),"recoveryPending" to value.optBoolean("recoveryPending"),"recoveryId" to value.optLong("recoveryId").toString(),"recoveryRemainingMillis" to value.optLong("recoveryRemainingMillis"),"cleanupPending" to (cleanupIncomplete || value.optBoolean("cleanupPending")),"interfaceUp" to value.optBoolean("interfaceUp"))
        }
        if(!up)clearActiveId(prefs)
        val stats=if(up)backend.getStatistics(tunnel) else null
        return mapOf("active" to up,"id" to prefs.getString("activeId",null),"rx" to stats?.totalRx(),"tx" to stats?.totalTx(),"handshake" to if(up)handshake() else null,"protocol" to kind)
    }
    val worker = Executors.newSingleThreadExecutor()
    private fun activationTunnel(token:Long) = object : Tunnel {
        override fun getName() = "xio0"
        override fun onStateChange(state: Tunnel.State) {
            if(!publication.accepts(token))return
            if (state == Tunnel.State.DOWN) { reconciledProtocol=null; clearActiveId(app.getSharedPreferences("xio", 0)) }
            XioVpnService.stateChanged(state == Tunnel.State.UP && acceptsUpPublication(token),token)
            VpnTileService.refresh(app)
        }
    }
    @Volatile var tunnel:Tunnel=activationTunnel(publicationToken())
        private set
    @Synchronized fun initialize(context: android.content.Context) {
        app = context.applicationContext
        GoBackend.setVpnServiceClass(XioVpnService::class.java)
        if (!::backend.isInitialized) backend = GoBackend(app)
        PolicyBridge.initialize(app)
    }
    /**
     * The versioned policy reservation is a distinct identity from every epoch
     * above. These wrappers keep the gate's monitor short: only flags/tickets.
     */
    fun policyReserve(transactionId:String) {
        synchronized(publication) {
            try {
                publication.reservePolicy(transactionId)
                Diag.append("policy-gate", "reserve ok ${transactionId.take(8)}")
            } catch(e:Exception) {
                Diag.append("policy-gate", "reserve refused ${transactionId.take(8)}: ${e.message}")
                throw PolicyFailure(PolicyFailure.BUSY, e.message ?: "Policy publication is busy")
            }
        }
    }
    fun policyRevoke(transactionId:String) {
        synchronized(publication){ publication.revokePolicy(transactionId) }
        Diag.append("policy-gate", "revoke ${transactionId.take(8)}")
    }
    fun policyRelease(transactionId:String) {
        synchronized(publication){ publication.releasePolicy(transactionId) }
        Diag.append("policy-gate", "release ${transactionId.take(8)}")
    }
    /**
     * The activation of THIS round is established: the tunnel stays up, but it no
     * longer blocks the policy lane. Without it the round that just confirmed a
     * candidate could not publish its selection (automatic failover stopped with
     * POLICY_BUSY right after the winning candidate connected).
     */
    fun settleActivation(roundId:String) {
        synchronized(publication){ publication.settleActivation(roundId) }
        Diag.append("policy-gate", "activation settled ${roundId.take(12)}")
    }
    fun policyAdmissionOpen():Boolean = synchronized(publication){ publication.admissionOpen() }
    fun requirePolicyAdmissionOpen() = synchronized(publication) {
        if(!publication.admissionOpen()) throw PolicyFailure(PolicyFailure.BUSY, "Connection policy publication or settings write in progress")
    }
    /** Config save/delete and routingSave fence READY admission before their IO. */
    fun beginConfigMutation():Long = synchronized(publication){ publication.beginConfigMutation() }
    fun endConfigMutation(token:Long) { synchronized(publication){ publication.endConfigMutation(token) } }
    @Volatile private var admittedSite:String?=null
    @Volatile private var admittedSiteCheck=false
    /** Site policy of the plan actually admitted for this activation; never a default. */
    fun capturedSite():String = admittedSite ?: error("No admitted site policy")
    fun capturedSiteCheck():Boolean = admittedSiteCheck
    fun disconnect(budget: ConnectionBudget? = null) {
        // Serialized candidate cleanup invalidates callbacks, not the parent round.
        synchronized(publication) {
            publication.invalidate()
            operationBudget?.cancel()
            cleanupIncomplete=true;activationRevoked=true
        }
        app.getSharedPreferences("xio",0).edit().putBoolean("vpnWanted",false).commit()
        reconciledProtocol=null
        OpenVpnBackend.stop()
        XrayBackend.stop()
        if(kind.startsWith("rivet-") || RivetBackend.established) RivetBackend.stop((budget?.cleanupMillis() ?: 5000L).coerceIn(1,30000))
        backend.setState(tunnel, Tunnel.State.DOWN, null)
        if (!BuildConfig.CLIENT_ONLY) VpnSharing.schedule(app,true)
        app.stopService(Intent(app,XioVpnService::class.java))
        XioVpnService.awaitStopped((budget?.cleanupMillis() ?: 5000L).coerceAtMost(5000))
        cleanupIncomplete=false;activationRevoked=false;ownedRoundId=null
        clearActiveId(app.getSharedPreferences("xio", 0))
    }
    private fun vpnNetworks(): Set<android.net.Network> {
        val cm=app.getSystemService(android.net.ConnectivityManager::class.java)
        return cm.allNetworks.filter{cm.getNetworkCapabilities(it)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)==true}.toSet()
    }
    private fun awaitNetworkReady(previous:Set<android.net.Network>,budget:ConnectionBudget) {
        budget.remainingMillis()
        val policy=SplitRouting(app).read()
        val usesVpn=when(policy.mode){"include"->policy.packages.contains(app.packageName);"exclude"->!policy.packages.contains(app.packageName);else->true}
        if(!usesVpn)return // The visible split policy intentionally excludes this app.
        val cm=app.getSystemService(android.net.ConnectivityManager::class.java)
        val waiting=android.os.SystemClock.elapsedRealtime();val deadline=waiting+minOf(budget.remainingMillis(),5000L)
        while(android.os.SystemClock.elapsedRealtime()<deadline){
            budget.remainingMillis()
            val current=vpnNetworks()-previous
            if(current.any{cm.getLinkProperties(it)?.interfaceName!=null&&(policy.mode.startsWith("ip")||cm.activeNetwork==it)}){
                XLog.i("XIO/Network","VPN route ready in "+(android.os.SystemClock.elapsedRealtime()-waiting)+"ms");return
            }
            Thread.sleep(50)
        }
        error("VPN network not ready")
    }
    fun connect(id: String, allowExistingService: Boolean = false,
        budget: ConnectionBudget = ConnectionBudget(15000, android.os.SystemClock::elapsedRealtime),
        policyJSON: String = "{\"mode\":\"automatic\",\"roundMillis\":30000}",
        roundId: String = "legacy-${android.os.SystemClock.elapsedRealtime()}",
        admissionToken: Long = publication.admissionToken(),
        policyReceipt: Map<String,Any?>? = null):Long {
        check(!cleanupIncomplete && publication.idle()) { "VPN cleanup incomplete" }
        budget.remainingMillis()
        ConnectionBudget.mode(org.json.JSONObject(policyJSON).getString("mode"))
        check(app.getSharedPreferences("xio",0).getString("consentRevision",null)=="2026-10-18") { "Open XIO and review VPN disclosure" }
        check(!isUp())
        // Admission BEFORE Mobile.stopWithTimeout and every other effect: validate
        // the attachment, then re-derive digests/routing/priority/selection from
        // the actual stored state. A missing receipt after versioned ownership
        // began is POLICY_UNSUPPORTED, never a legacy automatic fallback.
        requirePolicyAdmissionOpen()
        val admission = PolicyBridge.requireAdmission(app, policyReceipt, id)
        requirePolicyAdmissionOpen()
        admittedSite = admission.site
        admittedSiteCheck = admission.siteCheckEnabled
        val frozenPolicy = admission.policyJson()
        // Retire a failed/recovering RIVET owner before ANY replacement protocol.
        try { Mobile.stopWithTimeout(budget.remainingMillis()) }
        catch(e:Exception) { cleanupIncomplete=true;throw ConnectionBudget.CleanupIncomplete(e) }
        val publicationToken=synchronized(publication) {
            check(!cleanupIncomplete && publication.idle()) { "VPN cleanup incomplete" }
            val token=publication.begin(admissionToken,budget,roundId)
            ownedRoundId=roundId;activationRevoked=false;operationBudget=budget
            token
        }
        try {
        reconciledProtocol=null
        val started=android.os.SystemClock.elapsedRealtime()
        val previousNetworks=vpnNetworks()
        if(!allowExistingService) XioVpnService.awaitStopped(minOf(5000,budget.remainingMillis()))
        val raw=ConfigVault(app).readSecret(id)
        if(id.startsWith("ck")){
            kind="cloak"
            app.startForegroundService(Intent(app,XioVpnService::class.java))
            val service=XioVpnService.awaitCreated(minOf(5000,budget.remainingMillis()))
            OpenVpnBackend.connect(service,id,raw,budget.remainingMillis())
            awaitNetworkReady(previousNetworks,budget)
            budget.remainingMillis()
            lastConnectMillis=android.os.SystemClock.elapsedRealtime()-started
            VpnTileService.refresh(app);settleActivation(roundId);return publicationToken
        }
        if(id.startsWith("xr")){
            kind="xray"
            require(org.json.JSONObject(raw).getString("protocol")==kind)
            app.startForegroundService(Intent(app,XioVpnService::class.java))
            val service=XioVpnService.awaitCreated(minOf(5000,budget.remainingMillis()))
            XrayBackend.connect(service,id,raw,budget.remainingMillis())
            awaitNetworkReady(previousNetworks,budget)
            budget.remainingMillis()
            lastConnectMillis=android.os.SystemClock.elapsedRealtime()-started
            VpnTileService.refresh(app);settleActivation(roundId);return publicationToken
        }
        if(id.startsWith("rvh")||id.startsWith("rvs")){
            val cfg=org.json.JSONObject(raw);kind=cfg.getString("protocol")
            require(kind==if(id.startsWith("rvh"))"rivet-h3" else "rivet-s1")
            app.startForegroundService(Intent(app,XioVpnService::class.java))
            val service=XioVpnService.awaitCreated(minOf(5000,budget.remainingMillis()))
            val left=budget.remainingMillis();check(left>0)
            RivetBackend.connect(service,id,raw,left,frozenPolicy)
            awaitNetworkReady(previousNetworks,budget)
            budget.remainingMillis()
            lastConnectMillis=android.os.SystemClock.elapsedRealtime()-started
            VpnTileService.refresh(app);settleActivation(roundId);return publicationToken
        }
        val config = Config.parse(ByteArrayInputStream(raw.toByteArray()))
        require(id.startsWith("awg"));kind = "awg"
        val routing = SplitRouting(app)
        val policy = routing.read()
        val effective = routing.apply(config, policy)
        backend.setAllowUnroutedFamilies(policy.mode.startsWith("ip"))
        val remaining=budget.remainingMillis();check(remaining>0){"Connection deadline"}
        backend.setEndpointResolutionTimeoutMillis(remaining)
        requireActivation(publicationToken)
        tunnel=activationTunnel(publicationToken)
        backend.setState(tunnel, Tunnel.State.UP, effective)
        budget.remainingMillis()
        check(!activationRevoked)
        app.getSharedPreferences("xio",0).edit().putBoolean("vpnWanted",true).commit()
        app.getSharedPreferences("xio", 0).edit().putString("activeId", id).commit()
        awaitNetworkReady(previousNetworks,budget)
            budget.remainingMillis()
        lastConnectMillis=android.os.SystemClock.elapsedRealtime()-started
        } catch(e:Exception) { cancelConnect(roundId,budget);throw e }
        finally { if(operationBudget === budget) operationBudget=null;releaseConnect(budget) }
        settleActivation(roundId)
        return publicationToken
    }

}

class MainActivity : FlutterActivity() {
    private val testCommands = java.util.ArrayDeque<String>()
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        // Secure before Flutter renders or reads the persisted global opt-in.
        // Each new Activity starts secure; Dart reapplies the owner's choice.
        // The diagnostic build deliberately starts without FLAG_SECURE so the
        // screen can be captured while testing.
        if (!BuildConfig.TEST_BUILD) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        Diag.init(this)
        Diag.append("app", "activity onCreate test=${BuildConfig.TEST_BUILD}")
        queueTestCommand(intent)
    }
    private fun queueTestCommand(intent: Intent?) {
        if (!BuildConfig.TEST_BUILD) return
        // The device shell strips double quotes from `--es`, so the supported
        // form is a URL-safe base64 payload; the legacy plain extra stays for
        // values without JSON punctuation.
        val plain = intent?.getStringExtra("xioTest")
        val encoded = intent?.getStringExtra("xioTest64")
        val raw = plain ?: (encoded?.let {
            try {
                String(android.util.Base64.decode(it, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP))
            } catch (_: Exception) { null }
        }) ?: return
        if (raw.isBlank() || raw.length > 262144) return
        synchronized(testCommands) { testCommands.addLast(raw) }
        Diag.append("test", "command queued")
        if (::engineChannel.isInitialized) engineChannel.invokeMethod("testCommandPending", null)
    }
    private data class ConnectRequest(val id:String,val callback:MethodChannel.Result,
        val budget:ConnectionBudget,val round:ConnectionBudget,val policy:String,val roundId:String,
        val policyReceipt:Map<String,Any?>?=null,
        val admissionToken:Long=Engine.registerConnect(round),
        val delivered:java.util.concurrent.atomic.AtomicBoolean=java.util.concurrent.atomic.AtomicBoolean())
    private var pending: ConnectRequest? = null
    private var activeRequest: ConnectRequest? = null
    override fun onDestroy() {
        activeRequest?.let {expire(it,"CANCELLED")}
        super.onDestroy()
    }
    private var permissionOutstanding=false
    private var notificationOutstanding=false
    private val deadlines=android.os.Handler(android.os.Looper.getMainLooper())
    private fun expire(request:ConnectRequest,code:String="TIMEOUT") {
        if(!request.delivered.compareAndSet(false,true))return
        request.budget.cancel()
        Engine.releaseConnect(request.round)
        if(pending === request)pending=null
        if(activeRequest === request)activeRequest=null
        Engine.cancelConnect(request.roundId,request.budget)
        Engine.retireRound(request.roundId,request.round,request.budget)
        request.callback.error(code,"Connection round ended",null)
    }
    private var pendingFile: MethodChannel.Result? = null
    private lateinit var engineChannel: MethodChannel
    private val prefs by lazy { getSharedPreferences("xio", MODE_PRIVATE) }
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        AppIcons.ensureLauncher(this)
        Engine.initialize(this)
        engineChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "app.xio/engine")
        engineChannel.setMethodCallHandler { call, result ->
            if(call.method=="disconnect") {
                val id=call.argument<String>("roundId")
                activeRequest?.let { if(id==null || id.startsWith("disconnect-") || id==it.roundId)expire(it,"CANCELLED") }
                Engine.cancelConnect(if(id?.startsWith("disconnect-")==true)null else id)
            }
            if (BuildConfig.CLIENT_ONLY && call.method in setOf(
                "sharingStatus", "sharingSet", "credentialRead", "credentialWrite", "credentialDelete",
                "issuanceJournalLeasePath", "issuanceJournalRead", "issuanceJournalWrite",
                "issuanceJournalSeal", "issuanceJournalOpen", "issuanceJournalProvision",
                "prepareUpdateInstall", "consumeUpdateRequest", "updateAbi", "scheduleUpdateCheck",
                "installUpdate", "shareBundle", "shareApplication", "openSupportLink"
            )) {
                result.error("CLIENT_ONLY", "Недоступно в XIO Client", null)
                return@setMethodCallHandler
            }
            when (call.method) {
                "diagVersion" -> result.success(mapOf(
                    "version" to BuildConfig.VERSION_NAME,
                    "code" to BuildConfig.VERSION_CODE,
                    "test" to BuildConfig.TEST_BUILD))
                "diagLog" -> {
                    Diag.append(call.argument<String>("tag") ?: "dart", call.argument<String>("message") ?: "")
                    result.success(null)
                }
                "diagSnapshot" -> result.success(Diag.snapshot(call.argument<Number>("max")?.toInt() ?: 200000))
                "diagBundle" -> result.success(Diag.bundle()?.absolutePath)
                "shareTextFile" -> {
                    try {
                        val name = (call.argument<String>("name") ?: "xio.conf").replace(Regex("[^A-Za-z0-9._-]"), "-").take(80)
                        val text = call.argument<String>("text") ?: ""
                        require(text.isNotBlank() && text.length <= 65536)
                        val dir = File(cacheDir, "shared_profiles").apply { mkdirs() }
                        dir.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > 3600000 }?.forEach { it.delete() }
                        val file = File(dir, if (name.contains('.')) name else "xio-$name.conf").apply { writeText(text) }
                        val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.profiles", file)
                        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                            type = "application/octet-stream"; putExtra(Intent.EXTRA_STREAM, uri)
                            clipData = android.content.ClipData.newRawUri("XIO", uri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }, "XIO"))
                        android.os.Handler(mainLooper).postDelayed({ file.delete() }, 3600000)
                        result.success(null)
                    } catch (_: Exception) { result.error("SHARE", "Не удалось поделиться файлом", null) }
                }
                "shareDiag" -> {
                    try {
                        val path = call.argument<String>("path") ?: ""
                        require(path.isNotBlank() && File(path).exists() && File(path).canonicalPath.startsWith(cacheDir.canonicalPath + "/"))
                        val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.profiles", File(path))
                        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                            type = "application/zip"; putExtra(Intent.EXTRA_STREAM, uri)
                            clipData = android.content.ClipData.newRawUri("XIO", uri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }, "XIO diagnostics"))
                        result.success(null)
                    } catch (_: Exception) { result.error("SHARE", "Не удалось поделиться журналом", null) }
                }
                "diagLogcat" -> result.success(Diag.logcat())
                "consumeTestCommand" -> result.success(
                    if (BuildConfig.TEST_BUILD) synchronized(testCommands) { testCommands.pollFirst() } else null)
                "supportedProtocols" -> result.success(listOf("awg","rivet-h3","rivet-s1","xray"))
                "sharingStatus" -> result.success(VpnSharing.status(this))
                "sharingSet" -> Engine.worker.execute { try { val value=VpnSharing.set(this,call.argument<Boolean>("enabled")==true,call.argument<String>("interface")?:"");runOnUiThread{result.success(value)} } catch(e:Exception){runOnUiThread{result.error("SHARING",e.message?:"Не удалось настроить раздачу",null)}} }
                "connectionBusy" -> result.success(Engine.backgroundBusy || activeRequest!=null || pending!=null || permissionOutstanding || notificationOutstanding || !Engine.policyAdmissionOpen())
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
                "shareBundle", "shareClientBundle" -> {
                    try {
                        val raw = call.argument<String>("bundle") ?: ""
                        require(raw.length <= 200000)
                        if (BuildConfig.CLIENT_ONLY) {
                            require(call.method == "shareClientBundle" && raw.startsWith("xio://"))
                            val obj = org.json.JSONObject(String(android.util.Base64.decode(raw.substring(6), android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP)))
                            require(obj.getInt("schema") == 1 && !obj.has("adminAccess") && !obj.has("clientAccess"))
                            require(obj.keys().asSequence().toSet() == setOf("schema","name","userId","serverId","configs"))
                        }
                        require((raw.startsWith("xio://") || raw.startsWith("xio-server://")) && raw.length <= 200000)
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
                // Ссылка MTProto-прокси: Telegram сам покажет диалог добавления.
                // Разрешена только схема tg, иначе приложение стало бы
                // универсальным диспетчером произвольных интентов.
                "openTelegramLink" -> {
                    try {
                        val uri = android.net.Uri.parse(call.argument<String>("url") ?: "")
                        require(uri.scheme == "tg" && uri.userInfo == null)
                        startActivity(Intent(Intent.ACTION_VIEW,uri)); result.success(null)
                    } catch (_: Exception) { result.error("LINK","Telegram не установлен или ссылка не открылась",null) }
                }
                "shareApplication" -> {
                    startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type="text/plain";putExtra(Intent.EXTRA_TEXT,call.argument<String>("text")) },"XIO"));result.success(null)
                }
                "openSupportLink" -> {
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://xio.org/pay")))
                        result.success(null)
                    } catch (_: Exception) { result.error("LINK", "Не удалось открыть ссылку", null) }
                }
                "notificationSettings" -> {
                    startActivity(Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, packageName))
                    result.success(null)
                }
                "secureScreen" -> {
                    // The diagnostic build keeps the window capturable: refuse
                    // to re-enable FLAG_SECURE even if an old document asked.
                    val enabled = !BuildConfig.TEST_BUILD && call.argument<Boolean>("enabled") == true
                    if (enabled) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    Diag.append("app", "secureScreen enabled=$enabled")
                    result.success(null)
                }
                // Автозапуск после загрузки: Kotlin хранит копию флага для
                // BootReceiver и включает/выключает сам ресивер, потому что
                // BOOT_COMPLETED нельзя поймать динамической регистрацией.
                "setAutostart" -> {
                    val enabled = call.argument<Boolean>("enabled") == true
                    prefs.edit().putBoolean("autostart", enabled).apply()
                    packageManager.setComponentEnabledSetting(
                        android.content.ComponentName(this, BootReceiver::class.java),
                        if (enabled) android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        else android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        android.content.pm.PackageManager.DONT_KILL_APP
                    )
                    result.success(null)
                }
                "setAutoConnectOnStart" -> {
                    prefs.edit().putBoolean("autoConnectOnStart", call.argument<Boolean>("enabled") == true).apply()
                    result.success(null)
                }
                "connect" -> {
                    if (activeRequest != null || pending != null || permissionOutstanding || notificationOutstanding) { result.error("BUSY", "Ожидается разрешение VPN", null); return@setMethodCallHandler }
                    val id = call.argument<String>("id") ?: ""
                    val total=(call.argument<Number>("roundMillis")?.toLong() ?: 30000L).coerceIn(1,30000)
                    val round=ConnectionBudget(total,android.os.SystemClock::elapsedRealtime)
                    val budget=round.cap((call.argument<Number>("timeoutMillis")?.toLong() ?: 15000L).coerceIn(1,30000))
                    val policy=org.json.JSONObject(call.argument<Map<String,Any?>>("policy") ?: mapOf("mode" to "automatic","roundMillis" to 30000))
                    try { ConnectionBudget.mode(policy.getString("mode"));require(policy.optLong("roundMillis",30000) in 1..30000) }
                    catch(e:Exception){result.error("POLICY","Unsupported connection policy",null);return@setMethodCallHandler}
                    val request=try {
                        ConnectRequest(id,result,budget,round,policy.toString(),
                            call.argument<String>("roundId") ?: "activity-${android.os.SystemClock.elapsedRealtime()}",
                            policyReceipt = call.argument<Map<String,Any?>>("policyReceipt"))
                    } catch(e:Exception) {
                        // A publication reservation or a settings write owns admission.
                        Diag.append("policy-gate", "connect register refused: ${e.message}")
                        result.error("POLICY_BUSY","Connection policy is being updated",null);return@setMethodCallHandler
                    }
                    pending = request
                    activeRequest = request
                    deadlines.postDelayed({expire(request)},budget.remainingMillis())
                    if (android.os.Build.VERSION.SDK_INT >= 33 &&
                        checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED &&
                        !prefs.getBoolean("notificationAsked", false)) {
                        prefs.edit().putBoolean("notificationAsked", true).apply()
                        notificationOutstanding=true
                        requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 872)
                    } else preparePendingVpn()
                }
                else -> {
                    // Config save/delete and routingSave fence READY admission
                    // synchronously, before their IO is queued.
                    val fence = if (call.method in setOf("saveConfig","deleteConfig","routingSave"))
                        Engine.beginConfigMutation() else 0L
                    Engine.worker.execute {
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
                                SplitRouting(this).save(
                                    call.argument<String>("mode") ?: "",
                                    call.argument<List<String>>("packages") ?: emptyList(),
                                    call.argument<List<String>>("networks") ?: emptyList(),
                                    call.argument<List<String>>("domains") ?: emptyList(),
                                ).map()
                            }
                            // Домены разрешаются в приложении; адреса приходят
                            // отдельным вызовом и заменяют предыдущий набор.
                            "routingBegin" -> SplitRouting(this)
                                .beginResolution(call.argument<String>("lease") ?: "", call.argument<String>("resolutionId"))
                            "routingCancel" -> {
                                SplitRouting(this).cancelResolution(
                                    call.argument<String>("revision") ?: "",
                                    call.argument<String>("lease") ?: "",
                                ); null
                            }
                            "routingResolved" -> SplitRouting(this)
                                .saveResolved(
                                    call.argument<List<String>>("networks") ?: emptyList(),
                                    call.argument<String>("revision") ?: "",
                                    call.argument<String>("lease") ?: "",
                                    call.argument<Number>("validForMillis")?.toLong() ?: 0,
                                    call.argument<String>("resolutionId") ?: "",
                                ).map()
                            "dataDirectory" -> filesDir.absolutePath
                            "saveConfig" -> {
                                val id = call.argument<String>("id")!!
                                val raw = call.argument<String>("config")!!
                                require(raw.length <= 65536)
                                if(id.startsWith("ck"))OpenVpnBackend.validate(raw) else if(id.startsWith("xr"))Mobile.xrayValidate(raw) else if(id.startsWith("rvh")||id.startsWith("rvs"))Mobile.validate(raw) else { require(id.startsWith("awg")); Config.parse(ByteArrayInputStream(raw.toByteArray())) }
                                ConfigVault(this).writeSecret(id, raw); null
                            }
                            "accountAccessRead" -> {
                                val id=call.argument<String>("id")!!; require(Regex("^state[a-f0-9]{64}$").matches(id))
                                if(ConfigVault(this).contains(id)) ConfigVault(this).readSecret(id) else null
                            }
                            "accountAccessWrite" -> {
                                val id=call.argument<String>("id")!!; require(Regex("^state[a-f0-9]{64}$").matches(id))
                                val value=call.argument<String>("value")!!; require(value.length<=200000)
                                ConfigVault(this).writeSecret(id,value);null
                            }
                            "accountAccessDelete" -> {
                                val id=call.argument<String>("id")!!; require(Regex("^state[a-f0-9]{64}$").matches(id))
                                ConfigVault(this).delete(id);null
                            }
                            "issuanceJournalLeasePath" -> IssuanceVault(this).leasePath()
                            "issuanceJournalProvision" -> { IssuanceVault(this).provision(); null }
                            "issuanceJournalRead" -> {
                                val id=call.argument<String>("id")!!; require(Regex("^state[a-f0-9]{64}$").matches(id))
                                IssuanceVault(this).read(id)
                            }
                            "issuanceJournalWrite" -> {
                                val id=call.argument<String>("id")!!; require(Regex("^state[a-f0-9]{64}$").matches(id))
                                val value=call.argument<ByteArray>("value")!!
                                require(value.size<=1024*1024)
                                IssuanceVault(this).write(id,value); null
                            }
                            "issuanceJournalSeal" -> {
                                val id=call.argument<String>("id")!!; require(Regex("^state[a-f0-9]{64}$").matches(id))
                                val aad=call.argument<ByteArray>("aad")!!
                                val value=call.argument<ByteArray>("value")!!
                                require(value.size<=512*1024)
                                IssuanceVault(this).seal(id,aad,value)
                            }
                            "issuanceJournalOpen" -> {
                                val id=call.argument<String>("id")!!; require(Regex("^state[a-f0-9]{64}$").matches(id))
                                val aad=call.argument<ByteArray>("aad")!!
                                val value=call.argument<ByteArray>("value")!!
                                require(value.size<=1024*1024)
                                IssuanceVault(this).open(id,aad,value)
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
                                // The pre-envelope raw plan is only a migration source
                                // for a validated legacy-automatic plan. It is never an
                                // admission authority once the versioned envelope exists.
                                val parsed = StrictJson.asObject(StrictJson.parse(raw), "connectionPlan")
                                val schema = parsed["schema"]
                                if (schema != null && StrictJson.integer(schema, "schema") == PolicyPlan.SCHEMA.toLong()) {
                                    // A dual-writing app still goes through policyBegin/Commit;
                                    // keep the mirror non-authoritative and never read it.
                                    PolicyPlan.parse(parsed, "connectionPlanMirror")
                                    prefs.edit().putString("connectionPlanMirror", raw).apply()
                                } else {
                                    LegacyPlan.parseExactStored(raw)
                                    prefs.edit().putString("connectionPlan", raw).apply()
                                }
                                null
                            }
                            "readConfig" -> {
                                val id=call.argument<String>("id")!!
                                if(BuildConfig.CLIENT_ONLY) require(Regex("^(awg|rvh|rvs|xr|ck)[0-9]{1,24}$").matches(id))
                                ConfigVault(this).readSecret(id)
                            }
                            "deleteConfig" -> {
                                val id=call.argument<String>("id")!!
                                if(BuildConfig.CLIENT_ONLY) require(Regex("^(awg|rvh|rvs|xr|ck)[0-9]{1,24}$").matches(id))
                                ConfigVault(this).delete(id);null
                            }
                            "activeId" -> prefs.getString("activeId", null)
                            "disconnect" -> {
                                val timeout=(call.argument<Number>("timeoutMillis")?.toLong() ?: 30000L).coerceIn(1,30000)
                                Engine.disconnect(ConnectionBudget(timeout,android.os.SystemClock::elapsedRealtime)); null
                            }
                            "status" -> Engine.status()
                            "policyCapabilities" -> PolicyBridge.capabilities()
                            "policyState" -> PolicyBridge.state()
                            "policyBegin" -> PolicyBridge.begin(policyArguments(call.arguments))
                            "policyCommit" -> PolicyBridge.commit(policyArguments(call.arguments))
                            "policyReconcile" -> PolicyBridge.reconcile(policyArguments(call.arguments))
                            "policyAbort" -> PolicyBridge.abort(policyArguments(call.arguments))
                            else -> throw UnsupportedOperationException("Unknown method")
                        }
                        runOnUiThread { result.success(value) }
                    } catch (e: Exception) {
                        XLog.w("XIO/Engine", call.method + " failed: " + (e.message ?: e.javaClass.simpleName), e)
                        runOnUiThread {
                            result.error(
                                if (e is PolicyFailure) e.code else "ENGINE",
                                if (e is PolicyFailure) e.message ?: "Connection policy operation failed"
                                else if (e is RoutingException) e.message
                                else "Не удалось выполнить операцию VPN",
                                null,
                            )
                        }
                    } finally {
                        if (fence != 0L) Engine.endConfigMutation(fence)
                    }
                }
            }
        }
        }
    }
    private fun connect(request: ConnectRequest) {
        Engine.worker.execute {
            try {
                request.budget.remainingMillis()
                val publicationToken=Engine.connect(request.id,budget=request.budget,policyJSON=request.policy,roundId=request.roundId,admissionToken=request.admissionToken,policyReceipt=request.policyReceipt)
                request.budget.remainingMillis()
                runOnUiThread {
                    if(request.budget.availableMillis()==0L || !Engine.acceptsUpPublication(publicationToken))expire(request)
                    else if(request.delivered.compareAndSet(false,true)) {
                        Engine.releaseConnect(request.round)
                        if(activeRequest===request)activeRequest=null
                        request.callback.success(mapOf("connectMillis" to Engine.lastConnectMillis,"policyMode" to org.json.JSONObject(request.policy).getString("mode")))
                    }
                }
            } catch (e: Exception) {
                XLog.w("XIO/Engine", "connect failed: " + (e.message ?: e.javaClass.simpleName), e)
                Engine.cancelConnect(request.roundId,request.budget)
                var cleanup=false
                try { Engine.disconnectOwned(request.roundId,request.budget,request.round) } catch(_:Exception) { cleanup=true }
                runOnUiThread {
                    if(request.delivered.compareAndSet(false,true)) {
                        Engine.releaseConnect(request.round)
                        if(activeRequest===request)activeRequest=null
                        request.callback.error(
                            if(cleanup)"CLEANUP" else if(e is PolicyFailure)e.code else if(e is RoutingException)"ROUTING" else "VPN",
                            if(e is PolicyFailure)e.message ?: "Connection policy rejected this attempt" else if(e is RoutingException)e.message else "Не удалось запустить VPN-движок",
                            null)
                    }
                }
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun policyArguments(arguments: Any?): Map<String, Any?> =
        arguments as? Map<String, Any?> ?: emptyMap()

    private fun preparePendingVpn() {
        val request=pending?:return
        try { request.budget.remainingMillis() } catch(_:Exception){expire(request);return}
        val intent=VpnService.prepare(this)
        if (intent != null) {
            permissionOutstanding=true
            @Suppress("DEPRECATION") startActivityForResult(intent, 871)
        } else {
            pending=null
            connect(request)
        }
    }
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 872) { notificationOutstanding=false;if(pending!=null)preparePendingVpn() }
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if(intent.getBooleanExtra("checkUpdates",false) && ::engineChannel.isInitialized) engineChannel.invokeMethod("requestUpdates",null)
        queueTestCommand(intent)
        handleTileIntent()
    }
    override fun onPostResume() {
        super.onPostResume()
        handleTileIntent()
    }
    private fun handleTileIntent() {
        if (intent?.action != "app.xio.CONNECT_SELECTED") return
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
            permissionOutstanding=false
            val request = pending ?: return
            pending = null
            if (resultCode == Activity.RESULT_OK) {
                try {request.budget.remainingMillis();connect(request)}catch(_:Exception){expire(request)}
            } else if(request.delivered.compareAndSet(false,true)) {
                if(activeRequest===request)activeRequest=null
                request.budget.cancel()
                Engine.releaseConnect(request.round)
                request.callback.error("DENIED", "Разрешение VPN не предоставлено", null)
            }
        }
    }
}

