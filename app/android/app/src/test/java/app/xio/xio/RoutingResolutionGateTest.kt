package app.xio.xio

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

object RoutingResolutionGateTest {
    @JvmStatic fun main(args: Array<String>) {
        var now = 1000L
        val gate = RoutingResolutionGate { now }
        check(!gate.ready("r1"))
        gate.begin("r1", "old")
        gate.begin("r1", "new")
        gate.cancel("r1", "old")
        var writes = 0
        try { gate.commit("r1", "old") { writes++ }; error("stale commit accepted") }
        catch (_: IllegalStateException) {}
        check(writes == 0)
        gate.commit("r1", "new") { writes++ }
        check(writes == 1 && gate.ready("r1"))
        gate.cancel("r2", "new")
        check(gate.ready("r1"))
        gate.cancel("r1", "new")
        check(!gate.ready("r1"))
        gate.begin("r2", "retry")
        try { gate.commit("r2", "retry") { throw IllegalArgumentException("write failed") } }
        catch (_: IllegalArgumentException) {}
        check(!gate.ready("r2"))
        gate.commit("r2", "retry") { writes++ }
        check(gate.ready("r2"))
        now += 599_999
        check(gate.ready("r2"))
        now += 1
        check(!gate.ready("r2"))
        gate.begin("short", "cached")
        gate.commit("short", "cached", 10) { writes++ }
        now += 10
        check(!gate.ready("short"))
        gate.begin("clock", "skew")
        gate.commit("clock", "skew") { writes++ }
        now -= 1
        check(!gate.ready("clock"))
        now += 1
        check(!RoutingResolutionGate { now }.ready("r2")) // Restart has no receipt.

        // A policy edit using the SAME monitor cannot interleave inside commit.
        val writing = CountDownLatch(1)
        val release = CountDownLatch(1)
        val edited = CountDownLatch(1)
        gate.begin("r3", "write")
        val writer = Thread {
            gate.commit("r3", "write") {
                writing.countDown()
                check(release.await(2, TimeUnit.SECONDS))
            }
        }
        writer.start(); check(writing.await(2, TimeUnit.SECONDS))
        val editor = Thread { synchronized(gate) { gate.invalidate(); edited.countDown() } }
        editor.start()
        release.countDown()
        writer.join(2000); editor.join(2000)
        check(edited.count == 0L && !gate.ready("r3"))
        println("PASS routing gate: stale/cross-revision cancel, stale commit, failed-write retry, expiry, restart, atomic edit/commit")
    }
}
