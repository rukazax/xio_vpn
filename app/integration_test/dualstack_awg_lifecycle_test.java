/* SPDX-License-Identifier: Apache-2.0
 * Focused JVM tests for activation + VpnService identity ownership.
 * No Android, gomobile, AAR or native library is loaded.
 */
package org.amnezia.awg.backend;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class dualstack_awg_lifecycle_test {
    private static int checks;

    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    private static void join(Thread thread) throws Exception {
        thread.join(2000);
        if (thread.isAlive()) throw new AssertionError("thread did not finish");
    }

    private static AwgActivationLifecycle.Execution begin(AwgActivationLifecycle<String, String> life) {
        return life.begin("tun");
    }

    private static void expectBeginRefused(AwgActivationLifecycle<String, String> life, String message) {
        boolean refused = false;
        try {
            life.begin("tun");
        } catch (IllegalStateException expected) {
            refused = true;
        }
        check(refused, message);
    }

    private static void expectBeginAllowed(AwgActivationLifecycle<String, String> life, String message) {
        boolean allowed = true;
        try {
            life.begin("tun").done();
        } catch (IllegalStateException e) {
            allowed = false;
        }
        check(allowed, message);
    }

    public static void main(String[] args) throws Exception {
        executionBlocksBeginUntilFinally();
        pendingDownJoinsExecution();
        lateNativeHandleBlocksBeginUntilExecutionDone();
        retireBlocksBeginUntilServiceDestroyed();
        staleServiceDestroyCannotResetNewFuture();
        retireWithoutDestroyStaysBusyFailClosed();
        serviceAliveGuardsRetiredInstance();
        adoptRejectsRetiredAndStaleEpoch();
        publishDownRetireAndExactlyOneClose();
        repeatedDownDestroyCancelAndReentry();
        concurrentFailAndDestroyExactlyOnce();
        cancelWaitsForCommitPublication();
        serviceFuturePublicationIsIdentitySafe();
        foreignNeverAdoptedDestroyDoesNotReset();
        rejectedPublicationCannotAdoptOwner();
        System.out.println("XIO_AWG_LIFECYCLE_JVM_PASS checks=" + checks +
                "; pure-helper-only; no AAR/Android/native/handshake certification");
    }

    private static void executionBlocksBeginUntilFinally() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution execution = begin(life);
        expectBeginRefused(life, "second activation body is refused while first runs");
        execution.done();
        execution.done();
        life.down().complete();
        expectBeginAllowed(life, "begin allowed after execution finally (idempotent done)");
    }

    private static void pendingDownJoinsExecution() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution execution = begin(life);
        check(life.matches("tun"), "public DOWN predicate matches pending attempt");
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        check(down.wasActive() && down.handle() == AwgActivationLifecycle.NO_HANDLE,
                "DOWN before service/handle owns teardown");
        down.complete();
        expectBeginRefused(life, "B refused while A execution still in flight");
        execution.done();
        expectBeginAllowed(life, "B allowed after A execution joined");
    }

    private static void lateNativeHandleBlocksBeginUntilExecutionDone() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution execution = begin(life);
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        down.complete();
        // A resumes after DOWN and creates a native handle; attach must fail.
        check(!life.attach(execution.epoch(), 301), "late attach after DOWN is refused");
        expectBeginRefused(life, "B refused before A closes the late untracked handle");
        execution.done(); // backend catch closed 301 before finally
        expectBeginAllowed(life, "B allowed after late handle closed and A returned");
    }

    private static void retireBlocksBeginUntilServiceDestroyed() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution execution = begin(life);
        check(life.attach(execution.epoch(), 401), "attach");
        check(life.adoptService(execution.epoch(), 5001, "svc-A"), "adopt A service");
        AwgActivationLifecycle.Commit<String, String> commit = life.commit(
                execution.epoch(), 401, "tun", "cfg", () -> { });
        check(commit.outcome() == AwgActivationLifecycle.Outcome.PUBLISHED, "A published");
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        check(down.ownsService() && down.serviceToken() == 5001, "DOWN owns adopted service");
        check(life.retireService(5001) == 1, "service retirement awaits onDestroy");
        down.complete();
        execution.done();
        check(life.awaitingServiceDestroy(), "retired service still pending");
        expectBeginRefused(life, "B cannot begin while retired service alive");
        AwgActivationLifecycle.ServiceDestroy<String, String> destroyed = life.destroyService(5001);
        check(!destroyed.teardown().wasActive(), "retired onDestroy has no live teardown");
        check(!destroyed.resetFuture(), "retired onDestroy must not reset the fresh future");
        check(!life.awaitingServiceDestroy(), "retirement cleared");
        AwgActivationLifecycle.Execution next = life.begin("tun");
        check(life.attach(next.epoch(), 402), "B attaches");
        check(life.adoptService(next.epoch(), 5002, "svc-B"), "B adopts its own service");
        next.done();
    }

    private static void staleServiceDestroyCannotResetNewFuture() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution a = begin(life);
        check(life.attach(a.epoch(), 411), "A attach");
        check(life.adoptService(a.epoch(), 5101, "svc-old"), "A adopt");
        check(life.commit(a.epoch(), 411, "tun", "cfg", () -> { })
                .outcome() == AwgActivationLifecycle.Outcome.PUBLISHED, "A published");
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        check(life.retireService(5101) == 1, "A service retired");
        down.complete();
        a.done();
        check(!life.destroyService(5101).resetFuture(), "A onDestroy clears retire without future reset");
        AwgActivationLifecycle.Execution b = life.begin("tun");
        check(life.attach(b.epoch(), 412), "B attach");
        check(life.adoptService(b.epoch(), 5102, "svc-new"), "B adopt new service");
        check(life.commit(b.epoch(), 412, "tun", "cfg", () -> { })
                .outcome() == AwgActivationLifecycle.Outcome.PUBLISHED, "B published");
        AwgActivationLifecycle.ServiceDestroy<String, String> late = life.destroyService(5101);
        check(!late.teardown().wasActive(), "stale A onDestroy cannot tear down B");
        check(!late.resetFuture(), "stale A onDestroy cannot reset B future");
        check(life.up() && life.upHandle("tun") == 412, "B remains UP");
        AwgActivationLifecycle.ServiceDestroy<String, String> own = life.destroyService(5102);
        check(own.resetFuture() && own.teardown().wasActive() && own.teardown().handle() == 412,
                "B onDestroy owns its handle and resets its future");
        own.teardown().complete();
        b.done();
    }

    private static void retireWithoutDestroyStaysBusyFailClosed() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution a = begin(life);
        check(life.attach(a.epoch(), 421), "attach");
        check(life.adoptService(a.epoch(), 5201, "svc-stuck"), "adopt");
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        check(life.retireService(5201) == 1, "retire");
        down.complete();
        a.done();
        check(life.busy(), "backend stays busy without onDestroy");
        expectBeginRefused(life, "no timeout may release a retired reservation");
    }

    private static void serviceAliveGuardsRetiredInstance() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution a = begin(life);
        check(life.attach(a.epoch(), 431), "attach");
        check(life.adoptService(a.epoch(), 5301, "svc"), "adopt");
        downAndRetire(life, 431, 5301);
        a.done();
        check(!life.serviceAlive(5301), "retired instance cannot complete a fresh future");
        check(!life.destroyService(5301).resetFuture(), "old onDestroy does not reset future");
        check(!life.serviceAlive(5301), "destroyed instance is not alive");
    }

    private static void adoptRejectsRetiredAndStaleEpoch() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution a = begin(life);
        long stale = a.epoch();
        check(life.adoptService(stale, 5401, "svc-A"), "adopt A");
        downAndRetire(life, AwgActivationLifecycle.NO_HANDLE, 5401);
        a.done();
        check(!life.destroyService(5401).resetFuture(), "retired service cleared");
        AwgActivationLifecycle.Execution b = life.begin("tun");
        check(!life.adoptService(stale, 5402, "svc-stale"), "stale epoch cannot adopt");
        check(!life.adoptService(b.epoch(), 5401, "svc-retired"), "retired token cannot be adopted again");
        check(life.adoptService(b.epoch(), 5403, "svc-B"), "current epoch adopts live token");
        b.done();
    }

    private static void publishDownRetireAndExactlyOneClose() {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution a = begin(life);
        check(life.attach(a.epoch(), 441), "attach");
        check(life.adoptService(a.epoch(), 5501, "svc"), "adopt");
        check(life.commit(a.epoch(), 441, "tun", "cfg", () -> { })
                .outcome() == AwgActivationLifecycle.Outcome.PUBLISHED, "published");
        check(life.cancelPending() == AwgActivationLifecycle.NO_HANDLE, "UP is not cancelled");
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        check(down.wasActive() && down.handle() == 441 && down.serviceToken() == 5501, "DOWN owns handle+service");
        check(!life.down().wasActive(), "repeated DOWN during teardown is empty");
        check(life.retireService(5501) == 1, "retire once");
        check(life.retireService(5501) == 1, "repeated retire is idempotent");
        down.complete();
        a.done();
        check(life.retireService(5501) == 2 || life.retireService(5501) == 1,
                "retire after complete does not close anything");
    }

    private static void repeatedDownDestroyCancelAndReentry() throws Exception {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution a = begin(life);
        check(life.attach(a.epoch(), 451), "attach");
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        check(down.wasActive() && down.handle() == 451, "DOWN owns handle");
        check(!life.down().wasActive() && !life.destroyService(0).teardown().wasActive(),
                "repeated teardown empty");
        down.complete();
        a.done();
        check(life.cancelPending() == AwgActivationLifecycle.NO_HANDLE, "cancel after DOWN empty");
        check(life.cancelPending() == AwgActivationLifecycle.NO_HANDLE, "repeated cancel empty");

        AwgActivationLifecycle.Execution b = life.begin("tun");
        check(life.attach(b.epoch(), 452), "B attach");
        AtomicReference<AwgActivationLifecycle.Teardown<String, String>> reentrant = new AtomicReference<>();
        AwgActivationLifecycle.Commit<String, String> commit = life.commit(b.epoch(), 452, "tun", "cfg", () -> {
            reentrant.set(life.down());
        });
        check(commit.outcome() == AwgActivationLifecycle.Outcome.TORN_DOWN, "reentrant DOWN wins");
        check(commit.teardown() == null, "commit has no second teardown");
        check(reentrant.get() != null && reentrant.get().handle() == 452, "reentrant DOWN owns handle once");
        check(!life.up() && life.busy(), "teardown in flight keeps gate closed");
        reentrant.get().complete();
        b.done();
        check(!life.up() && !life.busy(), "reentrant DOWN completes to idle");
    }

    private static void concurrentFailAndDestroyExactlyOnce() throws Exception {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution a = begin(life);
        check(life.attach(a.epoch(), 461), "attach");
        check(life.adoptService(a.epoch(), 5601, "svc"), "adopt");
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<AwgActivationLifecycle.Teardown<String, String>> failed = new AtomicReference<>();
        AtomicReference<AwgActivationLifecycle.ServiceDestroy<String, String>> destroyed = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        long epoch = a.epoch();
        Thread failThread = new Thread(() -> {
            try {
                start.await(2, TimeUnit.SECONDS);
                failed.set(life.fail(epoch, 461));
            } catch (Throwable t) {
                failure.set(t);
            }
        }, "fail-cleanup");
        Thread destroyThread = new Thread(() -> {
            try {
                start.await(2, TimeUnit.SECONDS);
                destroyed.set(life.destroyService(5601));
            } catch (Throwable t) {
                failure.set(t);
            }
        }, "service-destroy");
        failThread.start();
        destroyThread.start();
        start.countDown();
        join(failThread);
        join(destroyThread);
        check(failure.get() == null, "concurrent cleanup did not throw");
        int owners = 0;
        if (failed.get() != null && failed.get().wasActive()) owners++;
        if (destroyed.get() != null && destroyed.get().teardown().wasActive()) owners++;
        check(owners == 1, "exactly one owner of native handle");
        if (failed.get() != null) failed.get().complete();
        if (destroyed.get() != null) destroyed.get().teardown().complete();
        a.done();
    }

    private static void cancelWaitsForCommitPublication() throws Exception {
        AwgActivationLifecycle<String, String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution a = begin(life);
        check(life.attach(a.epoch(), 471), "attach");
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<AwgActivationLifecycle.Outcome> outcome = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread activation = new Thread(() -> {
            try {
                outcome.set(life.commit(a.epoch(), 471, "tun", "cfg", () -> {
                    entered.countDown();
                    release.await(2, TimeUnit.SECONDS);
                }).outcome());
            } catch (Throwable t) {
                failure.set(t);
            }
        }, "commit");
        activation.start();
        check(entered.await(2, TimeUnit.SECONDS), "commit entered publication");
        AtomicInteger cancelled = new AtomicInteger(AwgActivationLifecycle.NO_HANDLE);
        Thread cancel = new Thread(() -> cancelled.set(life.cancelPending()), "cancel");
        cancel.start();
        release.countDown();
        join(activation);
        join(cancel);
        check(failure.get() == null, "commit thread did not throw");
        check(outcome.get() == AwgActivationLifecycle.Outcome.PUBLISHED, "commit wins publication");
        check(cancelled.get() == AwgActivationLifecycle.NO_HANDLE, "cancel after publish is empty");
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        check(down.handle() == 471, "DOWN owns the published handle");
        down.complete();
        a.done();
    }

    private static void downAndRetire(AwgActivationLifecycle<String, String> life, int handle, long token) {
        AwgActivationLifecycle.Teardown<String, String> down = life.down();
        check(down.wasActive(), "down active");
        if (down.handle() != AwgActivationLifecycle.NO_HANDLE)
            check(down.handle() == handle, "down handle");
        check(down.serviceToken() == token, "down service token");
        check(life.retireService(token) == 1, "retire service");
        down.complete();
    }

    private static void serviceFuturePublicationIsIdentitySafe() {
        AwgServicePublication<String> slot = new AwgServicePublication<>();
        AtomicReference<String> future = new AtomicReference<>();
        check(slot.publish("A", 9001, () -> future.set("A")), "publish A");
        slot.retire("A", 9001, () -> future.set(null));
        check(future.get() == null, "retire A clears A future");
        check(!slot.publish("A", 9001, () -> future.set("A")), "retired A cannot re-complete future");
        check(slot.publish("B", 9002, () -> future.set("B")), "publish B");
        slot.retire("A", 9001, () -> future.set(null));
        check("B".equals(future.get()), "late A destroy preserves B future");
        slot.retire("never-adopted", 9003, () -> future.set(null));
        check("B".equals(future.get()), "foreign never-adopted destroy preserves B future");
        check(!slot.publish("never-adopted", 9003, () -> future.set("foreign")), "destroyed foreign cannot publish");
        check(!slot.adopt("A", 9001, () -> future.set("bad owner")), "old A cannot set owner");
        check(slot.adopt("B", 9002, () -> {}), "B owner adoption succeeds");
        slot.retire("B", 9002, () -> future.set(null));
        check(future.get() == null, "only B destroy clears B future");
    }
    private static void foreignNeverAdoptedDestroyDoesNotReset() {
        AwgActivationLifecycle<String,String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution execution = begin(life);
        check(life.adoptService(execution.epoch(), 9101, "B"), "adopt live B");
        check(life.attach(execution.epoch(), 911), "attach live B");
        check(life.commit(execution.epoch(),911,"tun","cfg",()->{}).outcome() == AwgActivationLifecycle.Outcome.PUBLISHED,"publish live B");
        execution.done();
        AwgActivationLifecycle.ServiceDestroy<String,String> foreign = life.destroyService(9199);
        check(!foreign.resetFuture() && !foreign.teardown().wasActive(), "unknown old token cannot reset future");
        check(life.upHandle("tun") == 911, "foreign destroy keeps B handle");
        AwgActivationLifecycle.ServiceDestroy<String,String> own = life.destroyService(9101);
        check(own.resetFuture() && own.teardown().handle() == 911, "B destroy owns only B handle");
        own.teardown().complete();
    }
    private static void rejectedPublicationCannotAdoptOwner() {
        AwgActivationLifecycle<String,String> life = new AwgActivationLifecycle<>();
        AwgActivationLifecycle.Execution execution = begin(life);
        AtomicInteger owners = new AtomicInteger();
        check(!life.adoptService(execution.epoch(), 9201, "old", () -> false), "dead service adoption rejected atomically");
        check(life.adoptService(execution.epoch(), 9202, "live", () -> {owners.incrementAndGet();return true;}), "live service adoption works after rejected old token");
        check(owners.get() == 1, "only live owner published");
        AwgActivationLifecycle.Teardown<String,String> down = life.down();
        check(down.serviceToken() == 9202, "teardown owns the actually adopted service");
        down.complete(); execution.done();
    }
}
