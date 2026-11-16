package app.xio.xio

import java.io.File

object RoutingProvenanceTest {
    @JvmStatic fun main(args: Array<String>) {
        // Consume both H's frozen actual old-Sync allowance and the new actual
        // native-aware Sync allowance. The required !ready assertion is unchanged.
        for (path in args) {
            val input = File(path).readLines().map { it.toLong() }
            var mono = 0L
            val gate = RoutingResolutionGate { mono }
            val first = gate.begin("r1", "first")
            check(!first.reuseAllowed)
            gate.commit("r1", "first", 600_000, first.id) {}
            gate.cancel("r1", "first")
            check(!gate.ready("r1"))
            mono = input[0]
            val cached = gate.begin("r1", "cached", first.id)
            check(cached.reuseAllowed && cached.id == first.id)
            gate.commit("r1", "cached", input[1], cached.id) {}
            gate.cancel("r1", "first") // Old cancellation cannot revoke winner.
            check(gate.ready("r1"))
            mono = 599_999
            check(gate.ready("r1"))
            mono = 600_000
            check(!gate.ready("r1"))
            mono = 660_000
            check(!gate.ready("r1")) { "CONTRACT FAILURE: cached DNS older than original10m remains activatable" }
            val fresh = gate.begin("r1", "fresh", cached.id)
            check(!fresh.reuseAllowed && fresh.id != cached.id)
            var writes = 0
            try { gate.commit("r1", "fresh", 600_000, cached.id) { writes++ }; error("old DNS identity accepted") }
            catch (_: IllegalStateException) {}
            check(writes == 0)
            gate.commit("r1", "fresh", 600_000, fresh.id) { writes++ }
            check(writes == 1 && gate.ready("r1"))
            println("PASS originalDeadline600000/realAge660000: secondBegin=${input[0]} actualDartAllowance=${input[1]} sameOrigin=true ready=false; fresh identity required")
        }
        var now = 0L
        val gate = RoutingResolutionGate { now }
        val first = gate.begin("r1", "a")
        gate.commit("r1", "a", 10, first.id) {}
        gate.commit("r1", "a", 600_000, first.id) {} // Same-owner retry cannot renew either.
        now = 10
        check(!gate.ready("r1"))
        val unknown = gate.begin("r1", "unknown", "missing-id")
        check(!unknown.reuseAllowed && unknown.id != first.id)
        gate.commit("r1", "unknown", 600_000, unknown.id) {}
        val changed = gate.begin("r2", "policy-change", unknown.id)
        check(!changed.reuseAllowed)
        gate.commit("r2", "policy-change", 600_000, changed.id) {}
        gate.invalidate()
        check(!gate.begin("r2", "edited", changed.id).reuseAllowed)
        check(!RoutingResolutionGate { now }.begin("r2", "restart", changed.id).reuseAllowed)
        // A suspend-inclusive elapsedRealtime jump is expiry even if no timer ran.
        val sleep = gate.begin("r2", "sleep")
        gate.commit("r2", "sleep", 600_000, sleep.id) {}
        now += 600_001
        check(!gate.ready("r2"))
        check(!gate.begin("r2", "wake", sleep.id).reuseAllowed)
        println("PASS same-lease nonrenewal, unknown ID, policy revision/invalidate, restart, suspend-inclusive jump")
    }
}
