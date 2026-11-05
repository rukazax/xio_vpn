/* SPDX-License-Identifier: Apache-2.0
 * XIO: pure activation/service ownership for the AWG backend.
 * No Android or generated-binding dependencies; behavior is JVM-testable.
 */
package org.amnezia.awg.backend;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Serializes activation attempts, teardown and VpnService identity.
 *
 * <p>Invariants:
 * <ul>
 *   <li>{@link #begin(Object)} is refused while an activation body is still
 *       executing, while a teardown reservation is open, or while a retired
 *       service has not reached {@code onDestroy}. There is no timeout: if
 *       Android never destroys the service the backend stays busy (fail closed).</li>
 *   <li>Service instances carry a unique token. A retired token can neither
 *       complete the current future nor tear down a newer attempt.</li>
 *   <li>Publication runs under the lifecycle lock; a re-entrant DOWN owns the
 *       only native close.</li>
 * </ul>
 */
final class AwgActivationLifecycle<T, C> {
    static final int NO_HANDLE = -1;
    private static final AtomicLong SERVICE_TOKENS = new AtomicLong();

    /** Globally unique identity for one VpnService instance. */
    static long newServiceToken() {
        return SERVICE_TOKENS.incrementAndGet();
    }

    interface ServiceAdoption { boolean adopt(); }

    interface Publication {
        void publish() throws Exception;
    }

    enum Outcome { PUBLISHED, NOT_OWNED, TORN_DOWN, FAILED }

    /** One executing activation body; must be completed in a finally block. */
    static final class Execution {
        private final AwgActivationLifecycle<?, ?> owner;
        private final long epoch;
        private final AtomicBoolean done = new AtomicBoolean();

        Execution(AwgActivationLifecycle<?, ?> owner, long epoch) {
            this.owner = owner;
            this.epoch = epoch;
        }

        long epoch() { return epoch; }

        void done() {
            if (done.compareAndSet(false, true)) owner.executionDone();
        }
    }

    static final class Teardown<T, C> {
        private final AwgActivationLifecycle<T, C> owner;
        private final long reservation;
        private final boolean active;
        private final int handle;
        private final T tunnel;
        private final C config;
        private final Object service;
        private final long serviceToken;
        private final AtomicBoolean completed = new AtomicBoolean();

        Teardown(AwgActivationLifecycle<T, C> owner, long reservation, boolean active,
                 int handle, T tunnel, C config, Object service, long serviceToken) {
            this.owner = owner;
            this.reservation = reservation;
            this.active = active;
            this.handle = handle;
            this.tunnel = tunnel;
            this.config = config;
            this.service = service;
            this.serviceToken = serviceToken;
        }

        boolean wasActive() { return active; }
        int handle() { return handle; }
        T tunnel() { return tunnel; }
        C config() { return config; }
        Object service() { return service; }
        long serviceToken() { return serviceToken; }
        boolean ownsService() { return active && serviceToken != 0; }

        /** Releases the reservation; idempotent and stale-safe. */
        void complete() {
            if (completed.compareAndSet(false, true)) owner.completeTeardown(reservation);
        }
    }

    static final class Commit<T, C> {
        private final Outcome outcome;
        private final Teardown<T, C> teardown;
        private final Throwable failure;

        Commit(Outcome outcome, Teardown<T, C> teardown, Throwable failure) {
            this.outcome = outcome;
            this.teardown = teardown;
            this.failure = failure;
        }

        Outcome outcome() { return outcome; }
        Teardown<T, C> teardown() { return teardown; }
        Throwable failure() { return failure; }
    }

    /** Result of a VpnService.onDestroy for one instance token. */
    static final class ServiceDestroy<T, C> {
        private final Teardown<T, C> teardown;
        private final boolean resetFuture;

        ServiceDestroy(Teardown<T, C> teardown, boolean resetFuture) {
            this.teardown = teardown;
            this.resetFuture = resetFuture;
        }

        Teardown<T, C> teardown() { return teardown; }
        boolean resetFuture() { return resetFuture; }
    }

    private final Object lock = new Object();
    private long epoch;
    private boolean pending;
    private boolean cancelled;
    private boolean committed;
    private int handle = NO_HANDLE;
    private T target;
    private T tunnel;
    private C config;
    private long nextReservation;
    private long reservationId;
    private boolean cancelSignalled;
    private int executions;
    private long serviceToken;
    private Object serviceInstance;
    private long retirePending;
    private final Set<Long> destroyedServices = new HashSet<>();

    /** Starts an activation body and invalidates older epochs. */
    Execution begin(T tunnel) {
        synchronized (lock) {
            if (pending || committed || handle != NO_HANDLE || reservationId != 0 ||
                    executions != 0 || retirePending != 0) {
                throw new IllegalStateException("AWG activation still owned");
            }
            epoch++;
            pending = true;
            cancelled = false;
            committed = false;
            handle = NO_HANDLE;
            target = tunnel;
            this.tunnel = null;
            config = null;
            cancelSignalled = false;
            executions = 1;
            return new Execution(this, epoch);
        }
    }

    private void executionDone() {
        synchronized (lock) {
            if (executions > 0) executions--;
        }
    }

    boolean isCurrent(long epoch) {
        synchronized (lock) {
            return this.epoch == epoch && !cancelled;
        }
    }

    /** True while this tunnel owns the backend: pending attempt or published UP. */
    boolean matches(T candidate) {
        synchronized (lock) {
            if (candidate == null) return false;
            if (pending && !committed) return target == candidate;
            return committed && handle != NO_HANDLE && tunnel == candidate;
        }
    }

    boolean busy() {
        synchronized (lock) {
            return pending || committed || handle != NO_HANDLE || reservationId != 0 ||
                    executions != 0 || retirePending != 0;
        }
    }

    /** True while a retired service has not reached onDestroy. */
    boolean awaitingServiceDestroy() {
        synchronized (lock) {
            return retirePending != 0;
        }
    }

    int handle() {
        synchronized (lock) {
            return handle;
        }
    }

    /** Binds the native handle to this attempt. A cancelled/stale attempt cannot. */
    boolean attach(long epoch, int nativeHandle) {
        synchronized (lock) {
            if (this.epoch != epoch || cancelled || committed ||
                    !pending || handle != NO_HANDLE || nativeHandle < 0) {
                return false;
            }
            handle = nativeHandle;
            return true;
        }
    }

    /**
     * Adopts one service instance for this attempt. Must be called only while
     * the epoch is current, before startService/setOwner effects are trusted.
     */
    boolean adoptService(long epoch, long token, Object service) {
        return adoptService(epoch, token, service, () -> true);
    }

    boolean adoptService(long epoch, long token, Object service, ServiceAdoption adoption) {
        synchronized (lock) {
            if (this.epoch != epoch || cancelled || committed || !pending ||
                    token == 0 || serviceToken != 0 || retirePending != 0 ||
                    destroyedServices.contains(token)) {
                return false;
            }
            if (!adoption.adopt()) return false;
            serviceToken = token;
            serviceInstance = service;
            return true;
        }
    }

    /** A retired instance may neither complete nor serve a new attempt. */
    boolean serviceAlive(long token) {
        synchronized (lock) {
            return token != 0 && token != retirePending && !destroyedServices.contains(token);
        }
    }

    /**
     * Retires the adopted service early so a fresh future can be installed and
     * the old instance can no longer complete it. Returns 0 when there is no
     * owned live token, 1 when retirement now awaits onDestroy, 2 when the
     * instance is already destroyed.
     */
    int retireService(long token) {
        synchronized (lock) {
            if (token == 0) return 0;
            if (serviceToken == token) { serviceToken = 0; serviceInstance = null; }
            if (destroyedServices.contains(token)) return 2;
            if (retirePending == 0) {
                retirePending = token;
                return 1;
            }
            return retirePending == token ? 1 : 0;
        }
    }

    /**
     * Cancels a pending attempt. Returns its native handle once for
     * {@code awgCancelHandshake}. A committed tunnel is torn down by DOWN.
     */
    int cancelPending() {
        synchronized (lock) {
            if (!pending || committed || cancelSignalled) {
                return NO_HANDLE;
            }
            cancelled = true;
            cancelSignalled = true;
            return handle;
        }
    }

    /**
     * Publishes a fully authenticated attempt. The callback runs under the
     * lifecycle lock. A throwable rolls publication back and returns a teardown
     * reservation; a re-entrant DOWN returns TORN_DOWN and owns cleanup.
     */
    Commit<T, C> commit(long epoch, int nativeHandle, T newTunnel, C newConfig,
                        Publication publication) {
        synchronized (lock) {
            if (this.epoch != epoch || cancelled || committed || !pending ||
                    handle != nativeHandle || nativeHandle < 0) {
                return new Commit<>(Outcome.NOT_OWNED, null, null);
            }
            tunnel = newTunnel;
            config = newConfig;
            committed = true;
            long publishedEpoch = epoch;
            try {
                publication.publish();
                if (committed && this.epoch == publishedEpoch && handle == nativeHandle) {
                    return new Commit<>(Outcome.PUBLISHED, null, null);
                }
                return new Commit<>(Outcome.TORN_DOWN, null, null);
            } catch (Throwable failure) {
                if (this.epoch == publishedEpoch && handle == nativeHandle) {
                    int owned = handle;
                    long service = serviceToken;
                    Object instance = serviceInstance;
                    handle = NO_HANDLE;
                    serviceToken = 0;
                    serviceInstance = null;
                    pending = false;
                    cancelled = true;
                    committed = false;
                    this.tunnel = null;
                    config = null;
                    target = null;
                    long reservation = reserve();
                    return new Commit<>(Outcome.FAILED,
                            new Teardown<>(this, reservation, true, owned, null, null, instance, service),
                            failure);
                }
                return new Commit<>(Outcome.NOT_OWNED, null, failure);
            }
        }
    }

    /** Claims teardown for a failed attempt; stale epochs get an inactive token. */
    Teardown<T, C> fail(long epoch, int expectedHandle) {
        synchronized (lock) {
            if (this.epoch != epoch || handle != expectedHandle) {
                return inactive();
            }
            int owned = handle;
            long service = serviceToken;
            Object instance = serviceInstance;
            handle = NO_HANDLE;
            serviceToken = 0;
            serviceInstance = null;
            pending = false;
            cancelled = true;
            committed = false;
            tunnel = null;
            config = null;
            target = null;
            long reservation = reserve();
            return new Teardown<>(this, reservation, true, owned, null, null, instance, service);
        }
    }

    /** Invalidates the attempt and transfers ownership exactly once. */
    Teardown<T, C> down() {
        synchronized (lock) {
            return downLocked();
        }
    }

    private Teardown<T, C> downLocked() {
        if (reservationId != 0) return inactive();
        boolean active = pending || committed || handle != NO_HANDLE;
        if (!active) return inactive();
        int owned = handle;
        T oldTunnel = tunnel;
        C oldConfig = config;
        long service = serviceToken;
        Object instance = serviceInstance;
        epoch++;
        pending = false;
        cancelled = false;
        committed = false;
        handle = NO_HANDLE;
        tunnel = null;
        config = null;
        target = null;
        serviceToken = 0;
        serviceInstance = null;
        long reservation = reserve();
        return new Teardown<>(this, reservation, true, owned, oldTunnel, oldConfig, instance, service);
    }

    /**
     * Handles onDestroy for one instance token. A retired token only clears its
     * retirement; it never returns a live teardown and never resets the future.
     */
    ServiceDestroy<T, C> destroyService(long token) {
        synchronized (lock) {
            if (token == 0) return new ServiceDestroy<>(inactive(), false);
            if (destroyedServices.contains(token)) {
                // Repeated/late onDestroy for an already retired instance.
                return new ServiceDestroy<>(inactive(), false);
            }
            if (retirePending == token) {
                retirePending = 0;
                destroyedServices.add(token);
                return new ServiceDestroy<>(inactive(), false);
            }
            if (serviceToken != token) {
                destroyedServices.add(token);
                return new ServiceDestroy<>(inactive(), false);
            }
            serviceToken = 0;
            serviceInstance = null;
            destroyedServices.add(token);
            return new ServiceDestroy<>(downLocked(), true);
        }
    }

    boolean up() {
        synchronized (lock) {
            return committed && handle != NO_HANDLE;
        }
    }

    boolean upFor(T candidate) {
        synchronized (lock) {
            return committed && handle != NO_HANDLE && tunnel == candidate;
        }
    }

    int upHandle(T candidate) {
        synchronized (lock) {
            return committed && handle != NO_HANDLE && tunnel == candidate ? handle : NO_HANDLE;
        }
    }

    T upTunnel() {
        synchronized (lock) {
            return committed && handle != NO_HANDLE ? tunnel : null;
        }
    }

    boolean isPublished(T candidateTunnel, C candidateConfig) {
        synchronized (lock) {
            return committed && handle != NO_HANDLE &&
                    tunnel == candidateTunnel && config == candidateConfig;
        }
    }

    T tunnel() {
        synchronized (lock) {
            return committed ? tunnel : null;
        }
    }

    C config() {
        synchronized (lock) {
            return committed ? config : null;
        }
    }

    private long reserve() {
        reservationId = ++nextReservation;
        return reservationId;
    }

    private void completeTeardown(long token) {
        synchronized (lock) {
            if (reservationId == token) reservationId = 0;
        }
    }

    private Teardown<T, C> inactive() {
        return new Teardown<>(this, 0, false, NO_HANDLE, null, null, null, 0);
    }
}
