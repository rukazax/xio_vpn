package app.xio.xio

/** Native monotonic DNS provenance is separate from revocable activation ownership.
 * The production caller supplies elapsedRealtime (including Android deep sleep).
 */
class RoutingResolutionGate(private val now: () -> Long) {
    data class Resolution(val id: String, val reuseAllowed: Boolean)
    private var revision: String? = null
    private var lease: String? = null
    private var beganAt = 0L
    private var candidateId: String? = null
    private var candidateUntil = 0L
    private var originId: String? = null
    private var originAt = 0L
    private var originUntil = 0L
    private var readyUntil: Long? = null

    @Synchronized fun begin(revision: String, lease: String, requestedId: String? = null): Resolution {
        require(revision.isNotEmpty() && lease.isNotEmpty())
        if (this.revision != revision) invalidate()
        this.revision = revision
        this.lease = lease
        beganAt = now()
        readyUntil = null
        val reuse = requestedId != null && requestedId == originId &&
            beganAt >= originAt && beganAt < originUntil
        candidateId = if (reuse) originId else java.util.UUID.randomUUID().toString()
        candidateUntil = if (reuse) originUntil else beganAt + 600_000
        return Resolution(candidateId!!, reuse)
    }

    @Synchronized fun cancel(revision: String, lease: String) {
        if (this.revision == revision && this.lease == lease) {
            // DOWN revokes activation, NOT the original DNS deadline.
            this.lease = null
            candidateId = null
            readyUntil = null
        }
    }

    @Synchronized fun invalidate() {
        revision = null
        lease = null
        candidateId = null
        originId = null
        originUntil = 0L
        readyUntil = null
    }

    @Synchronized fun commit(expectedRevision: String, expectedLease: String, validForMillis: Long = 600_000,
                             resolutionId: String? = candidateId, write: () -> Unit) {
        check(revision == expectedRevision && lease == expectedLease && lease != null) { "Routing resolution superseded" }
        check(resolutionId != null && resolutionId == candidateId) { "Routing resolution identity changed" }
        require(validForMillis in 1..600_000)
        // A Dart wall-clock allowance can shorten, NEVER renew native provenance.
        val until = minOf(candidateUntil, beganAt + validForMillis)
        readyUntil = null
        check(now() >= beganAt && now() < until) { "Routing resolution expired" }
        write()
        check(now() >= beganAt && now() < until) { "Routing resolution expired" }
        if (originId != resolutionId) originAt = beganAt
        originId = resolutionId
        originUntil = until
        candidateUntil = until
        readyUntil = until
    }

    @Synchronized fun ready(expectedRevision: String): Boolean {
        val until = readyUntil ?: return false
        val current = now()
        return revision == expectedRevision && lease != null && current >= beganAt && current < until
    }
}
