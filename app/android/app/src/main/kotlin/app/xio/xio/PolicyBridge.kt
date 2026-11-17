package app.xio.xio

import android.content.Context

/**
 * One versioned policy envelope, in its own preferences file.
 *
 * The envelope is deliberately separate from the unrelated `xio` preferences:
 * a failed `commit()` elsewhere can then never persist a stale ready value, and
 * this file has exactly one writer (the Engine worker lane).
 */
class PolicyPrefs(context: Context) : PolicyJournal.Store {
    private val prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
    override fun cached(): String? = prefs.getString(KEY, null)
    override fun commit(value: String): Boolean = prefs.edit().putString(KEY, value).commit()

    companion object {
        const val FILE = "xio.policy"
        const val KEY = "envelope"
    }
}

/**
 * Cheap durable questions for boot/service paths that must not touch the vault.
 *
 * "Ready" here means process-confirmed durable: once this process has written the
 * envelope, only the journal can confirm it (SharedPreferences' cached string may
 * show a READY value that a failed commit never persisted). A fresh process that
 * has written nothing yet reads the value SharedPreferences loaded from disk.
 */
object PolicyEnvelopes {
    /** A READY envelope that is confirmed durable in this process (or loaded at start). */
    fun ready(context: Context): Boolean {
        if (PolicyBridge.initialized) return PolicyBridge.confirmedReady()
        val raw = context.getSharedPreferences(PolicyPrefs.FILE, Context.MODE_PRIVATE)
            .getString(PolicyPrefs.KEY, null) ?: return false
        return try {
            PolicyEnvelope.parse(StrictJson.parse(raw), "envelope").phase == PublicationPhase.READY
        } catch (_: Exception) {
            false
        }
    }

    /** A pre-envelope plan exists; it is only ever admitted as legacy automatic. */
    fun legacyPlan(context: Context): Boolean =
        context.getSharedPreferences("xio", Context.MODE_PRIVATE).getString("connectionPlan", null) != null

    /**
     * Whether the autonomous restart consumer may start at all.
     *
     * Any versioned envelope present (pending, blocked, malformed) means versioned
     * ownership began: only a confirmed READY envelope may auto-reconnect, never
     * the old raw plan. The old raw plan is considered only when the durable app
     * document is genuinely pre-versioned (no connectionPolicy key, no receipt).
     */
    fun autonomous(context: Context): Boolean {
        val versioned = context.getSharedPreferences(PolicyPrefs.FILE, Context.MODE_PRIVATE)
            .contains(PolicyPrefs.KEY)
        if (versioned) return ready(context)
        return legacyAutonomous(context)
    }

    private fun legacyAutonomous(context: Context): Boolean {
        if (!legacyPlan(context)) return false
        val file = java.io.File(context.filesDir, "profiles.json")
        if (!file.exists()) return false
        val document = try {
            DurableDocument.parse(file.readText())
        } catch (_: Exception) {
            return false
        }
        return !document.hasConnectionPolicy && !document.hasPlanReceiptKey
    }
}

/**
 * The exact admission a request was captured with: the receipt and candidate
 * list are copied together and carried through every candidate, never re-sampled.
 */
class CapturedAdmission internal constructor(
    internal val admission: DurableAdmission.Admission,
    val receipt: Map<String, Any?>?,
) {
    val candidates: List<String> get() = admission.candidates
    val mode: String get() = admission.policy.mode
    val site: String get() = admission.site
    val siteCheckEnabled: Boolean get() = admission.siteCheckEnabled
    val timeoutSeconds: Int get() = admission.timeoutSeconds
    val generation: String get() = admission.generation
    val legacy: Boolean get() = admission.legacy

    /** The frozen policy fragment the existing engine entry point consumes. */
    fun policyJson(): String = StrictJson.canonical(mapOf("mode" to mode, "roundMillis" to ConnectionPolicy.ROUND_MILLIS))
}

/**
 * Native side of the versioned policy publication.
 *
 * Every write runs on `Engine.worker` (the single policy lane). Checks that can
 * block are done off the PublicationLease monitor; the lease only ever holds
 * short flags/tickets. Nothing here rewrites the app document.
 */
object PolicyBridge {
    private lateinit var context: Context
    private lateinit var store: PolicyPrefs
    private lateinit var journal: PolicyJournal

    @Volatile
    var instanceNonce: String = ""
        private set

    @Volatile
    var initialized: Boolean = false
        private set

    @Synchronized
    fun initialize(context: Context) {
        if (initialized) return
        this.context = context.applicationContext
        store = PolicyPrefs(this.context)
        instanceNonce = randomNonce()
        journal = PolicyJournal(store, object : PolicyJournal.Gate {
            override fun reservePolicy(transactionId: String) = Engine.policyReserve(transactionId)
            override fun revokePolicy(transactionId: String) = Engine.policyRevoke(transactionId)
            override fun releasePolicy(transactionId: String) = Engine.policyRelease(transactionId)
        })
        journal.instanceNonce(instanceNonce)
        journal.load()
        initialized = true
    }

    private fun randomNonce(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        val out = StringBuilder(32)
        for (byte in bytes) out.append(String.format(java.util.Locale.ROOT, "%02x", byte))
        return out.toString()
    }

    private fun readyJournal(): PolicyJournal {
        check(initialized) { "Policy store is unavailable" }
        journal.load()
        return journal
    }

    // ------------------------------------------------------------- queries

    fun capabilities(): Map<String, Any?> {
        val journal = readyJournal()
        val state = when (journal.status()) {
            PolicyJournal.Status.PENDING, PolicyJournal.Status.PENDING_UNKNOWN -> "pending"
            PolicyJournal.Status.BLOCKED -> "blocked"
            else -> "ready"
        }
        val resources = when {
            journal.hasActiveReservation() -> "owned"
            journal.error() != null -> "unknown"
            else -> "clean"
        }
        return mapOf(
            "version" to 1,
            "instanceNonce" to instanceNonce,
            "state" to state,
            "resourceState" to resources,
        )
    }

    fun state(): Map<String, Any?> {
        val journal = readyJournal()
        val envelope = journal.envelope()
        val result = LinkedHashMap<String, Any?>()
        result["version"] = 1
        result["instanceNonce"] = instanceNonce
        result["state"] = when (journal.status()) {
            PolicyJournal.Status.READY -> "ready"
            PolicyJournal.Status.PENDING, PolicyJournal.Status.PENDING_UNKNOWN -> "pending"
            PolicyJournal.Status.BLOCKED -> "blocked"
            else -> "absent"
        }
        result["phase"] = envelope?.phase?.wire ?: "absent"
        result["resourceState"] = if (journal.hasActiveReservation()) "owned" else "clean"
        result["storeIdentity"] = envelope?.storeIdentity
        result["controllerNonce"] = envelope?.controllerNonce
        result["transactionId"] = envelope?.transactionId
        result["planGeneration"] = envelope?.planGeneration
        result["receipt"] = if (journal.status() == PolicyJournal.Status.READY) {
            try { journal.readyReceipt(instanceNonce).toJson() } catch (_: PolicyFailure) { null }
        } else null
        result["pendingTransaction"] = journal.active()?.transactionId
        result["error"] = journal.error()
        return result
    }

    // ----------------------------------------------------------- mutation

    fun begin(args: Map<String, Any?>): Map<String, Any?> {
        val journal = readyJournal()
        val request = parseRequest(args)
        requireInstance(request.instanceNonce)
        val reservation = journal.reserveBegin(request.storeIdentity, request.controllerNonce, request.transactionId,
            request.expectedGeneration, request.planGeneration, request.plan)
        val bytes = journal.pendingJson(reservation)
        val settle = drain(journal, journal.settlePending(reservation, store.commit(bytes)), reservation)
        return ack(settle)
    }

    fun commit(args: Map<String, Any?>): Map<String, Any?> {
        val journal = readyJournal()
        val request = parseRequest(args)
        requireInstance(request.instanceNonce)
        // Identity/CAS validation first: a foreign request must NOT revoke or release
        // the legitimate owner's reservation. Only the exact owner may reach the
        // proposal validation that can abort on a stale document.
        val reservation = journal.requireSameProposal(request.storeIdentity, request.controllerNonce,
            request.transactionId, request.expectedGeneration, request.planGeneration, request.plan)
        // A ready ACK is only honest if the stored document, its receipt, the
        // routing snapshot, the selection and every saved config already match.
        requireProposal(reservation)
        val bytes = journal.readyJson(reservation)
        val settle = drain(journal, journal.settleReady(reservation, store.commit(bytes)), reservation)
        return ack(settle)
    }

    fun reconcile(args: Map<String, Any?>): Map<String, Any?> {
        val journal = readyJournal()
        val request = parseRequest(args)
        requireInstance(request.instanceNonce)
        val reservation = journal.reserveReconcile(request.storeIdentity, request.controllerNonce, request.transactionId,
            request.expectedGeneration, request.planGeneration, request.plan)
        // Reconcile is held to the same receipt-required standard as commit: an ACK
        // without the durable receipt would produce a boot-inconsistent READY.
        requireProposal(reservation)
        val bytes = journal.readyJson(reservation)
        val settle = drain(journal, journal.settleReady(reservation, store.commit(bytes)), reservation)
        return ack(settle)
    }

    /** Re-derives stored identity; on mismatch revoke the proposal and write BLOCKED. */
    private fun requireProposal(reservation: PolicyJournal.Reservation) {
        try {
            DurableAdmission.validateProposal(reservation.plan, reservation.transactionId, reservation.planGeneration,
                routingSource(), configSource(), clientOnly(), document())
        } catch (failure: PolicyFailure) {
            runCatching { drain(journal, journal.abort(reservation.transactionId), reservation) }
            throw failure
        }
    }

    fun abort(args: Map<String, Any?>): Map<String, Any?> {
        val journal = readyJournal()
        // Exactly {version, instanceNonce, transactionId}; all three are required.
        val allowed = setOf("version", "instanceNonce", "transactionId")
        for (key in args.keys) if (key !in allowed) throw PolicyFailure(PolicyFailure.INVALID, "Unsupported field: $key")
        for (key in allowed) if (!args.containsKey(key)) throw PolicyFailure(PolicyFailure.INVALID, "Missing field: $key")
        if (StrictJson.integer(args["version"], "version") != 1L)
            throw PolicyFailure(PolicyFailure.UNSUPPORTED, "Unsupported policy version")
        requireInstance(hex(args["instanceNonce"], 32, "instanceNonce"))
        val transactionId = hex(args["transactionId"], 32, "transactionId")
        val reservation = journal.active()
        drain(journal, journal.abort(transactionId), reservation)
        return mapOf("version" to 1, "state" to stateName(journal), "transactionId" to transactionId)
    }

    /** DOWN/dispose: revoke the logical owner synchronously; the writer stays owned. */
    fun revokeLogical() {
        if (!initialized) return
        journal.revokeAll()
    }

    /** Same lane, after the settle: write the blocked receipt and only then release. */
    fun reconcileBlocked() {
        if (!initialized) return
        val reservation = journal.active() ?: return
        try {
            drain(journal, journal.revokeAll(), reservation)
        } catch (failure: RuntimeException) {
            // The journal stays pendingUnknown/owned: a failed receipt never frees the lane.
            XLog.w("XIO/Policy", "blocked reconciliation failed: " + (failure.message ?: failure.javaClass.simpleName))
        }
    }

    private fun drain(journal: PolicyJournal, initial: PolicyJournal.Settle,
                      reservation: PolicyJournal.Reservation?): PolicyJournal.Settle {
        var settle = initial
        while (settle.blockedWriteRequired && reservation != null && journal.active() === reservation) {
            val bytes = journal.blockedJson(reservation, "Policy publication did not complete")
            settle = journal.settleBlocked(reservation, store.commit(bytes))
        }
        return settle
    }

    private fun ack(settle: PolicyJournal.Settle): Map<String, Any?> {
        val ack = settle.ack
            ?: throw PolicyFailure(settle.failureCode ?: PolicyFailure.STALE, "Policy publication did not complete")
        val result = LinkedHashMap<String, Any?>()
        result["version"] = 1
        result["instanceNonce"] = instanceNonce
        result["controllerNonce"] = ack.controllerNonce
        result["transactionId"] = ack.transactionId
        result["planGeneration"] = ack.planGeneration
        result["state"] = ack.phase.wire
        return result
    }

    /** Exact lowercase hex, reported as POLICY_INVALID rather than a generic channel error. */
    private fun hex(value: Any?, length: Int, field: String): String =
        try { PolicyReceipt.requireHex(StrictJson.string(value, field), length, field) }
        catch (failure: StrictJson.Invalid) { throw PolicyFailure(PolicyFailure.INVALID, failure.message ?: field) }

    /** The caller must hold the capabilities nonce of this engine lifetime. */
    private fun requireInstance(nonce: String) {
        if (nonce != instanceNonce)
            throw PolicyFailure(PolicyFailure.STALE, "Policy request belongs to a previous engine lifetime")
    }

    private fun stateName(journal: PolicyJournal): String = when (journal.status()) {
        PolicyJournal.Status.READY -> "ready"
        PolicyJournal.Status.PENDING, PolicyJournal.Status.PENDING_UNKNOWN -> "pending"
        PolicyJournal.Status.BLOCKED -> "blocked"
        else -> "absent"
    }

    private class PublicationRequest(
        val storeIdentity: String,
        val controllerNonce: String,
        val instanceNonce: String,
        val transactionId: String,
        val expectedGeneration: String?,
        val planGeneration: String,
        val plan: PolicyPlan,
    )

    private val REQUEST_FIELDS = setOf(
        "version", "storeIdentity", "controllerNonce", "instanceNonce", "transactionId", "expectedGeneration",
        "planGeneration", "plan",
    )

    private fun parseRequest(args: Map<String, Any?>): PublicationRequest {
        for (key in args.keys) if (key !in REQUEST_FIELDS) throw PolicyFailure(PolicyFailure.INVALID, "Unsupported field: $key")
        for (key in REQUEST_FIELDS) if (!args.containsKey(key)) throw PolicyFailure(PolicyFailure.INVALID, "Missing field: $key")
        val version = StrictJson.integer(args["version"], "version")
        if (version != 1L) throw PolicyFailure(PolicyFailure.UNSUPPORTED, "Unsupported policy version")
        val plan = try {
            PolicyPlan.parse(args["plan"], "plan")
        } catch (failure: StrictJson.Invalid) {
            throw PolicyFailure(PolicyFailure.INVALID, failure.message ?: "Invalid plan")
        }
        val expected = args["expectedGeneration"]
        return PublicationRequest(
            hex(args["storeIdentity"], 64, "storeIdentity"),
            hex(args["controllerNonce"], 32, "controllerNonce"),
            hex(args["instanceNonce"], 32, "instanceNonce"),
            hex(args["transactionId"], 32, "transactionId"),
            if (expected == null) null else hex(expected, 32, "expectedGeneration"),
            hex(args["planGeneration"], 32, "planGeneration"),
            plan,
        )
    }

    // ---------------------------------------------------------- admission

    /** Boot/Tile capture: prove the durable document pair, then copy receipt+plan together. */
    fun capture(context: Context): CapturedAdmission {
        initialize(context)
        val journal = readyJournal()
        val envelope = revalidatableEnvelope(journal)
        if (envelope != null) {
            val admission = try {
                DurableAdmission.validateReady(envelope, routingSource(), configSource(), clientOnly(), document())
            } catch (failure: PolicyFailure) {
                journal.invalidateInMemory(failure.message ?: "Connection policy validation failed")
                throw failure
            }
            admission.requireActivatable()
            if (journal.status() != PolicyJournal.Status.READY) journal.adoptDurable(envelope)
            return CapturedAdmission(admission, journal.readyReceipt(instanceNonce).toJson())
        }
        // Legacy automatic only against genuinely pre-versioned native AND app state.
        if (journal.status() == PolicyJournal.Status.ABSENT && !journal.versionedOwnership()) return legacyCapture(context)
        throw PolicyFailure(PolicyFailure.UNKNOWN, "Connection policy is not ready (" + journal.status() + ")")
    }

    /**
     * Candidate ids for display/active-id reconciliation only (never admission):
     * a revalidatable READY plan wins; otherwise the strictly validated legacy
     * automatic plan, or null when neither is usable.
     */
    fun candidateIds(): List<String>? {
        if (!initialized) return null
        journal.revalidatable()?.let { return it.plan?.ids }
        // The raw mirror is display-only AND pristine-only: any versioned envelope
        // (pending/blocked/malformed) or versioned document wins over it.
        val raw = context.getSharedPreferences("xio", Context.MODE_PRIVATE).getString("connectionPlan", null)
            ?: return null
        val documentText = try { document() } catch (_: PolicyFailure) { null }
        return DurableAdmission.legacyIdsIfPristine(journal.versionedOwnership(), raw, documentText)
    }

    /** Process-confirmed durable READY; a cached-looking envelope alone never counts. */
    fun confirmedReady(): Boolean {
        if (!initialized) return false
        return readyJournal().readyForAdmission()
    }

    /**
     * Per-candidate admission: validate the attachment, then re-derive digests,
     * routing, priority, selection and eligibility from stored state. Called
     * before any stop/setup effect; every mismatch is POLICY_STALE.
     */
    fun requireAdmission(context: Context, receiptMap: Map<String, Any?>?, attemptedId: String): CapturedAdmission {
        initialize(context)
        val journal = readyJournal()
        val document = document()
        val routing = routingSource()
        val configs = configSource()
        if (receiptMap == null) {
            // Missing attachment is only legal before versioned ownership began,
            // and only for a genuinely pre-versioned durable app document.
            if (journal.versionedOwnership())
                throw PolicyFailure(PolicyFailure.UNSUPPORTED, "The app must finish saving the connection policy first")
            val legacy = legacyPlan(context)
            val admission = DurableAdmission.validateLegacy(legacy, routing, configs, clientOnly(), document)
            DurableAdmission.validateCandidate(admission, attemptedId, routing, configs, clientOnly(), document)
            return CapturedAdmission(admission, null)
        }
        val receipt = try {
            PolicyReceipt.parse(receiptMap, "policyReceipt")
        } catch (failure: StrictJson.Invalid) {
            throw PolicyFailure(PolicyFailure.INVALID, failure.message ?: "Invalid policy receipt")
        }
        val envelope = revalidatableEnvelope(journal)
            ?: throw PolicyFailure(PolicyFailure.UNKNOWN, "No confirmed committed connection policy")
        if (!receipt.storeIdentity.equals(envelope.storeIdentity)
            || !receipt.controllerNonce.equals(envelope.controllerNonce)
            || !receipt.transactionId.equals(envelope.transactionId)
            || !receipt.planGeneration.equals(envelope.planGeneration))
            throw PolicyFailure(PolicyFailure.STALE, "Policy receipt does not match the committed plan")
        if (receipt.instanceNonce != instanceNonce)
            throw PolicyFailure(PolicyFailure.STALE, "Policy receipt belongs to a previous engine lifetime")
        val admission = DurableAdmission.validateReady(envelope, routing, configs, clientOnly(), document)
        DurableAdmission.validateCandidate(admission, attemptedId, routing, configs, clientOnly(), document)
        if (journal.status() != PolicyJournal.Status.READY) journal.adoptDurable(envelope)
        return CapturedAdmission(admission, receipt.toJson())
    }

    /**
     * A READY envelope may be re-validated only while no publication/write is
     * outstanding; a failed commit leaves the previous READY bytes in memory but
     * must never be treated as the current authority.
     */
    private fun revalidatableEnvelope(journal: PolicyJournal): PolicyEnvelope? = journal.revalidatable()

    private fun legacyPlan(context: Context): LegacyPlan {
        val raw = context.getSharedPreferences("xio", Context.MODE_PRIVATE).getString("connectionPlan", null)
            ?: throw PolicyFailure(PolicyFailure.UNKNOWN, "No saved connection plan")
        return try {
            LegacyPlan.parseExactStored(raw)
        } catch (failure: StrictJson.Invalid) {
            throw PolicyFailure(PolicyFailure.INVALID, failure.message ?: "Saved connection plan is invalid")
        }
    }

    private fun legacyCapture(context: Context): CapturedAdmission {
        val admission = DurableAdmission.validateLegacy(legacyPlan(context), routingSource(), configSource(),
            clientOnly(), document())
        admission.requireActivatable()
        return CapturedAdmission(admission, null)
    }

    private fun document(): String {
        val file = java.io.File(context.filesDir, "profiles.json")
        if (!file.exists()) throw PolicyFailure(PolicyFailure.UNKNOWN, "Saved app document is unavailable")
        return try {
            file.readText()
        } catch (_: Exception) {
            throw PolicyFailure(PolicyFailure.UNKNOWN, "Saved app document is unreadable")
        }
    }

    /** The canonical routing policy native already reports to `routingGet`. */
    private fun routingSource(): DurableAdmission.RoutingSource = DurableAdmission.RoutingSource {
        val policy = SplitRouting(context).read()
        RoutingCanon.canonical(policy.mode, policy.packages, policy.networks, policy.domains)
    }

    /** Exact saved/base config text: the same bytes `readConfig` returns. */
    private fun configSource(): DurableAdmission.ConfigSource = DurableAdmission.ConfigSource { id ->
        ConfigVault(context).readSecret(id)
    }

    private fun clientOnly(): Boolean = BuildConfig.CLIENT_ONLY
}

