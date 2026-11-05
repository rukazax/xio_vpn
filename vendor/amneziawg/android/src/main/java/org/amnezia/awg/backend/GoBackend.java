/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg.backend;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import org.amnezia.awg.backend.BackendException.Reason;
import org.amnezia.awg.backend.Tunnel.State;
import org.amnezia.awg.util.SharedLibraryLoader;
import org.amnezia.awg.config.Config;
import org.amnezia.awg.config.InetEndpoint;
import org.amnezia.awg.config.InetNetwork;
import org.amnezia.awg.config.Peer;
import org.amnezia.awg.crypto.Key;
import org.amnezia.awg.crypto.KeyFormatException;
import org.amnezia.awg.util.NonNullForAll;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

import static org.amnezia.awg.GoBackend.*;

/**
 * Implementation of {@link Backend} that uses the amneziawg-go userspace implementation to provide
 * AmneziaWG tunnels.
 */
@NonNullForAll
public final class GoBackend implements Backend {
    private long endpointResolutionTimeoutMillis = 15000;
    public void setEndpointResolutionTimeoutMillis(long value) {
        if (activation.busy()) throw new IllegalStateException("Tunnel must be down");
        if (value < 1 || value > 60000) throw new IllegalArgumentException("Invalid endpoint deadline");
        endpointResolutionTimeoutMillis = value;
    }
    private static final String TAG = "AmneziaWG/GoBackend";
    @Nullable private static AlwaysOnCallback alwaysOnCallback;
    private static final AwgServicePublication<VpnService> servicePublication = new AwgServicePublication<>();
    private static volatile GhettoCompletableFuture<VpnService> vpnService = new GhettoCompletableFuture<>();
    private final Context context;
    private boolean allowUnroutedFamilies;

    /** Explicit IP split mode may bypass either address family outside its routes.
     * Set only while DOWN, from the serialized application worker. */
    public void setAllowUnroutedFamilies(boolean enabled) {
        if (activation.busy()) throw new IllegalStateException("Tunnel must be down");
        allowUnroutedFamilies = enabled;
    }
    private final AwgActivationLifecycle<Tunnel, Config> activation =
            new AwgActivationLifecycle<>();
    /** Cancels only a pending activation; a committed tunnel is torn down by DOWN. */
    public void cancelPendingHandshake() {
        int handle = activation.cancelPending();
        if (handle != AwgActivationLifecycle.NO_HANDLE) awgCancelHandshake(handle);
    }
    @Nullable private Thread statusThread;
    @Nullable private StatusCallback statusCallback;

    /**
     * Public constructor for GoBackend.
     *
     * @param context An Android {@link Context}
     */
    private static Class<? extends VpnService> vpnServiceClass = VpnService.class;
    public static void setVpnServiceClass(final Class<? extends VpnService> clazz) {
        vpnServiceClass = clazz;
    }

    public GoBackend(final Context context) {
        go.Seq.setContext(context.getApplicationContext());
        this.context = context;
    }

    /**
     * Set a {@link AlwaysOnCallback} to be invoked when {@link VpnService} is started by the
     * system's Always-On VPN mode.
     *
     * @param cb Callback to be invoked
     */
    public static void setAlwaysOnCallback(final AlwaysOnCallback cb) {
        alwaysOnCallback = cb;
    }



    /**
     * Method to get the names of running tunnels.
     *
     * @return A set of string values denoting names of running tunnels.
     */
    @Override
    public Set<String> getRunningTunnelNames() {
        final Tunnel tunnel = activation.upTunnel();
        if (tunnel != null) {
            final Set<String> runningTunnels = new ArraySet<>();
            runningTunnels.add(tunnel.getName());
            return runningTunnels;
        }
        return Collections.emptySet();
    }

    /**
     * Get the associated {@link State} for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to examine the state of.
     * @return {@link State} associated with the given tunnel.
     */
    @Override
    public State getState(final Tunnel tunnel) {
        return activation.upFor(tunnel) ? State.UP : State.DOWN;
    }

    /**
     * Get the associated {@link Statistics} for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to retrieve statistics for.
     * @return {@link Statistics} associated with the given tunnel.
     */
    @Override
    public Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        final int handle = activation.upHandle(tunnel);
        if (handle == AwgActivationLifecycle.NO_HANDLE)
            return stats;
        final String config = awgGetConfig(handle);
        if (config == null)
            return stats;
        Key key = null;
        long rx = 0;
        long tx = 0;
        long latestHandshakeMSec = 0;
        for (final String line : config.split("\\n")) {
            if (line.startsWith("public_key=")) {
                if (key != null)
                    stats.add(key, rx, tx, latestHandshakeMSec);
                rx = 0;
                tx = 0;
                latestHandshakeMSec = 0;
                try {
                    key = Key.fromHex(line.substring(11));
                } catch (final KeyFormatException ignored) {
                    key = null;
                }
            } else if (line.startsWith("rx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    rx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    rx = 0;
                }
            } else if (line.startsWith("tx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    tx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    tx = 0;
                }
            } else if (line.startsWith("last_handshake_time_sec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(24)) * 1000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            } else if (line.startsWith("last_handshake_time_nsec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(25)) / 1000000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            }
        }
        if (key != null)
            stats.add(key, rx, tx, latestHandshakeMSec);
        return stats;
    }


    /**
     * Get the last handshake time for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to retrieve the last handshake time for.
     * @return Last handshake time in seconds (>=0), -1 if no handshake found, -2 on error, -3 if tunnel not active.
     */
    @Override
    public long getLastHandshake(final Tunnel tunnel) {
        final int handle = activation.upHandle(tunnel);
        if (handle == AwgActivationLifecycle.NO_HANDLE)
            return -3; // Tunnel not active
        final String config = awgGetConfig(handle);
        if (config == null) {
            Log.e(TAG, "Failed to get tunnel config");
            return -2;
        }

        for (final String line : config.split("\\n")) {
            if (line.startsWith("last_handshake_time_sec=")) {
                try {
                    return Long.parseLong(line.substring(24));
                } catch (final NumberFormatException ignored) {
                    Log.e(TAG, "Failed to parse last_handshake_time_sec");
                    return -2;
                }
            }
        }

        Log.e(TAG, "Failed to get last_handshake_time_sec");
        return -1;
    }

    /**
     * Set a callback to be notified when connection status changes.
     *
     * @param callback The callback to invoke on status change
     */
    public void setStatusCallback(@Nullable final StatusCallback callback) {
        this.statusCallback = callback;
    }

    /**
     * Launch a background thread to poll handshake status and determine connection state.
     * This is called after tunnel creation to wait for the first successful handshake.
     */
    private void launchStatusJob() {
        stopStatusJob();
        Log.d(TAG, "Launch status job");
        statusThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                final Tunnel active = activation.upTunnel();
                final long lastHandshake = active == null ? -3L : getLastHandshake(active);

                // Check if tunnel is no longer active (race condition protection)
                if (lastHandshake == -3L) {
                    Log.d(TAG, "Tunnel is no longer active, stopping status job");
                    break;
                }

                // 0 means no handshake yet, wait and retry
                if (lastHandshake == 0L) {
                    try {
                        Thread.sleep(1000);
                    } catch (final InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    continue;
                }

                // Only positive handshake time indicates successful connection
                // -1 may be returned if unable to parse output (doesn't mean no connection)
                // -2 indicates command execution error (also doesn't mean no connection)
                if (lastHandshake > 0L) {
                    if (statusCallback != null) {
                        statusCallback.onStatusChanged(true);
                    }
                    break;
                }

                // For -1 or -2, retry after delay instead of reporting disconnected
                try {
                    Thread.sleep(1000);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            statusThread = null;
        }, "StatusJob");
        statusThread.start();
    }

    /**
     * Stop the status polling thread if running.
     */
    private void stopStatusJob() {
        if (statusThread != null) {
            statusThread.interrupt();
            statusThread = null;
        }
    }

    /**
     * Get the version of the underlying amneziawg-go library.
     *
     * @return {@link String} value of the version of the amneziawg-go library.
     */
    @Override
    public String getVersion() {
        return awgVersion();
    }

    /**
     * Change the state of a given {@link Tunnel}, optionally applying a given {@link Config}.
     *
     * @param tunnel The tunnel to control the state of.
     * @param state  The new state for this tunnel. Must be {@code UP}, {@code DOWN}, or
     *               {@code TOGGLE}.
     * @param config The configuration for this tunnel, may be null if state is {@code DOWN}.
     * @return {@link State} of the tunnel after state changes are applied.
     * @throws Exception Exception raised while changing tunnel state.
     */
    @Override
    public State setState(final Tunnel tunnel, State state, @Nullable final Config config) throws Exception {
        final State originalState = getState(tunnel);

        if (state == State.TOGGLE)
            state = originalState == State.UP ? State.DOWN : State.UP;
        if (state == originalState && activation.isPublished(tunnel, config))
            return originalState;
        if (state == State.UP) {
            final Tunnel originalTunnel = activation.tunnel();
            final Config originalConfig = activation.config();
            if (originalTunnel != null)
                setStateInternal(originalTunnel, null, State.DOWN);
            try {
                setStateInternal(tunnel, config, state);
            } catch (final Exception e) {
                if (originalTunnel != null)
                    setStateInternal(originalTunnel, originalConfig, State.UP);
                throw e;
            }
        } else if (state == State.DOWN && activation.matches(tunnel)) {
            setStateInternal(tunnel, null, State.DOWN);
        }
        return getState(tunnel);
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state)
            throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        if (state == State.UP) {
            if (config == null)
                throw new BackendException(Reason.TUNNEL_MISSING_CONFIG);
            if (activation.busy()) {
                Log.w(TAG, "Tunnel already up or activating");
                return;
            }

            // The epoch is allocated before any permission/service/DNS/TUN work.
            // Every checkpoint and the final publication are fenced by it.
            final AwgActivationLifecycle.Execution execution;
            try {
                execution = activation.begin(tunnel);
            } catch (IllegalStateException alreadyOwned) {
                Log.w(TAG, "Tunnel already up or activating");
                return;
            }
            final long epoch = execution.epoch();
            final long endpointDeadline = System.nanoTime() +
                    TimeUnit.MILLISECONDS.toNanos(endpointResolutionTimeoutMillis);
            VpnService service = null;
            int nativeHandle = AwgActivationLifecycle.NO_HANDLE;
            boolean attached = false;
            final boolean[] upNotified = {false};
            try {
                if (VpnService.prepare(context) != null)
                    throw new BackendException(Reason.VPN_NOT_AUTHORIZED);
                if (!activation.isCurrent(epoch))
                    throw new InterruptedException("AWG activation canceled");

                if (!vpnService.isDone()) {
                    Log.d(TAG, "Requesting to start VpnService");
                    context.startService(new Intent(context, vpnServiceClass));
                }
                try {
                    service = vpnService.get(2, TimeUnit.SECONDS);
                } catch (final TimeoutException e) {
                    final Exception be = new BackendException(Reason.UNABLE_TO_START_VPN);
                    be.initCause(e);
                    throw be;
                }
                final VpnService serviceForAdoption = service;
                // Adopt before any setOwner effect is trusted; a retired service
                // token cannot be adopted even if Android handed it back.
                if (!activation.isCurrent(epoch) ||
                        !activation.adoptService(epoch, service.serviceToken(), service,
                                () -> serviceForAdoption.adoptOwner(this)))
                    throw new InterruptedException("AWG activation canceled");
                if (!activation.isCurrent(epoch))
                    throw new InterruptedException("AWG activation canceled");

                // Resolve each peer only through a NOT_VPN Android Network. One
                // overall DNS deadline; serialization below is strictly cache-only.
                for (final Peer peer : config.getPeers()) {
                    final InetEndpoint ep = peer.getEndpoint().orElse(null);
                    if (ep == null) continue;
                    final long remaining = TimeUnit.NANOSECONDS.toMillis(endpointDeadline - System.nanoTime());
                    if (!activation.isCurrent(epoch) || remaining <= 0 ||
                            !ep.getResolved(service::resolveEndpoint, remaining).isPresent())
                        throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, ep.getHost());
                }

                // Build config
                final String goConfig = config.toAwgUserspaceString();

                // Create the vpn tunnel with android API
                final VpnService.Builder builder = service.getBuilder();
                builder.setSession(tunnel.getName());

                for (final String excludedApplication : config.getInterface().getExcludedApplications())
                    builder.addDisallowedApplication(excludedApplication);

                for (final String includedApplication : config.getInterface().getIncludedApplications())
                    builder.addAllowedApplication(includedApplication);

                for (final InetNetwork addr : config.getInterface().getAddresses())
                    builder.addAddress(addr.getAddress(), addr.getMask());

                for (final InetAddress addr : config.getInterface().getDnsServers())
                    builder.addDnsServer(addr.getHostAddress());

                for (final String dnsSearchDomain : config.getInterface().getDnsSearchDomains())
                    builder.addSearchDomain(dnsSearchDomain);

                boolean sawDefaultRoute = false;
                for (final Peer peer : config.getPeers()) {
                    for (final InetNetwork addr : peer.getAllowedIps()) {
                        if (addr.getMask() == 0)
                            sawDefaultRoute = true;
                        builder.addRoute(addr.getAddress(), addr.getMask());
                    }
                }

                // "Kill-switch" semantics
                if (allowUnroutedFamilies || !(sawDefaultRoute && config.getPeers().size() == 1)) {
                    builder.allowFamily(OsConstants.AF_INET);
                    builder.allowFamily(OsConstants.AF_INET6);
                }

                builder.setMtu(config.getInterface().getMtu().orElse(1280));

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                    builder.setMetered(false);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                    service.setUnderlyingNetworks(null);

                builder.setBlocking(true);
                try (final ParcelFileDescriptor tun = builder.establish()) {
                    if (tun == null)
                        throw new BackendException(Reason.TUN_CREATION_ERROR);
                    if (!activation.isCurrent(epoch))
                        throw new InterruptedException("AWG activation canceled");
                    Log.d(TAG, "Go backend " + awgVersion());
                    nativeHandle = awgTurnOn(tunnel.getName(), tun.detachFd(), goConfig, service);
                }
                if (nativeHandle < 0)
                    throw new BackendException(Reason.GO_ACTIVATION_ERROR_CODE, nativeHandle);
                attached = activation.attach(epoch, nativeHandle);
                if (!attached)
                    throw new InterruptedException("AWG activation canceled");

                final int handle = nativeHandle;
                final VpnService publishedService = service;
                int verified = 0;
                for (Peer peer : config.getPeers()) {
                    InetEndpoint endpoint = peer.getEndpoint().orElse(null);
                    if (endpoint == null) continue;
                    StringBuilder candidates = new StringBuilder();
                    for (InetEndpoint candidate : endpoint.getResolvedCandidates()) {
                        if (candidates.length() > 0) candidates.append(',');
                        candidates.append(candidate.toString());
                    }
                    long remaining = TimeUnit.NANOSECONDS.toMillis(endpointDeadline - System.nanoTime());
                    if (!activation.isCurrent(epoch) || remaining <= 0)
                        throw new TimeoutException("AWG connection canceled or deadline");
                    awgHandshakeCandidates(handle, peer.getPublicKey().toHex(), candidates.toString(), remaining);
                    if (!activation.isCurrent(epoch))
                        throw new InterruptedException("AWG activation canceled");
                    verified++;
                }
                if (verified == 0)
                    throw new IllegalStateException("No authenticated endpoint");

                // Socket protection is outside the lifecycle lock; publication
                // and its UP callback stay fenced against DOWN/cancel.
                publishedService.protect(awgGetSocketV4(handle));
                publishedService.protect(awgGetSocketV6(handle));
                final AwgActivationLifecycle.Commit<Tunnel, Config> committed =
                        activation.commit(epoch, handle, tunnel, config, () -> {
                            upNotified[0] = true;
                            tunnel.onStateChange(State.UP);
                        });
                switch (committed.outcome()) {
                    case PUBLISHED:
                        return;
                    case TORN_DOWN:
                        // The re-entrant DOWN/destroy owns close, service and
                        // the DOWN callback; do not duplicate any of them.
                        return;
                    case FAILED:
                        finishTeardown(committed.teardown(), tunnel, upNotified[0]);
                        throw rethrow(committed.failure());
                    default:
                        throw new InterruptedException("AWG activation canceled");
                }
            } catch (Throwable failure) {
                // Only the attempt that still owns its epoch/handle tears down;
                // a stale A failure can never close or stop a replacement B.
                final AwgActivationLifecycle.Teardown<Tunnel, Config> teardown =
                        activation.fail(epoch, attached ? nativeHandle
                                : AwgActivationLifecycle.NO_HANDLE);
                if (teardown.wasActive()) {
                    // Compensation DOWN stays inside the teardown reservation, so
                    // a newer attempt cannot publish UP before it is delivered.
                    finishTeardown(teardown, tunnel, upNotified[0]);
                } else if (!attached && nativeHandle != AwgActivationLifecycle.NO_HANDLE) {
                    // awgTurnOn succeeded but attach lost the epoch race: this
                    // handle was never published, so it is ours to close.
                    awgTurnOff(nativeHandle);
                }
                // Never compensate DOWN after a newer attempt owns the backend.
                if (upNotified[0] && teardown.wasActive())
                    notifyCompensationDown(tunnel);
                throw rethrow(failure);
            } finally {
                // Keeps begin() refused until the late untracked handle above is
                // closed and any teardown reservation has been released.
                execution.done();
            }
        } else {
            final AwgActivationLifecycle.Teardown<Tunnel, Config> down = activation.down();
            if (!down.wasActive()) {
                Log.w(TAG, "Tunnel already down");
                return;
            }
            try {
                stopStatusJob();
                finishTeardown(down, null, false);
                if (down.tunnel() != null)
                    down.tunnel().onStateChange(State.DOWN);
            } finally {
                down.complete();
            }
        }
    }

    /** Native close, service retirement and optional compensation DOWN. */
    private void finishTeardown(final AwgActivationLifecycle.Teardown<Tunnel, Config> teardown,
                                final Tunnel tunnel, final boolean compensateDown) {
        try {
            if (teardown.handle() != AwgActivationLifecycle.NO_HANDLE)
                awgTurnOff(teardown.handle());
            releaseService(teardown);
            if (compensateDown) notifyCompensationDown(tunnel);
        } finally {
            teardown.complete();
        }
    }

    /**
     * Retires the exact adopted service instance so its late onStartCommand can
     * never complete the replacement future, invalidates that future now, then
     * asks the instance to stop. The activation gate stays closed until the
     * retired instance reaches onDestroy.
     */
    private void releaseService(final AwgActivationLifecycle.Teardown<Tunnel, Config> teardown) {
        if (!teardown.ownsService()) return;
        final long token = teardown.serviceToken();
        final int action = activation.retireService(token);
        if (action > 0 && teardown.service() instanceof VpnService) {
            final VpnService retired = (VpnService) teardown.service();
            servicePublication.retire(retired, token,
                    () -> vpnService = vpnService.newIncompleteFuture());
            if (action == 1) {
                try { retired.stopSelf(); } catch (RuntimeException ignored) { }
            }
        }
    }

    private static void notifyCompensationDown(final Tunnel tunnel) {
        try {
            tunnel.onStateChange(State.DOWN);
        } catch (RuntimeException | Error ignored) { }
    }

    private static Exception rethrow(final Throwable failure) {
        if (failure instanceof Exception) return (Exception) failure;
        if (failure instanceof Error) throw (Error) failure;
        return new BackendException(Reason.GO_ACTIVATION_ERROR_CODE, -1, failure);
    }

    /**
     * Callback for {@link GoBackend} that is invoked when {@link VpnService} is started by the
     * system's Always-On VPN mode.
     */
    public interface AlwaysOnCallback {
        void alwaysOnTriggered();
    }

    // TODO: When we finally drop API 21 and move to API 24, delete this and replace with the ordinary CompletableFuture.
    private static final class GhettoCompletableFuture<V> {
        private final LinkedBlockingQueue<V> completion = new LinkedBlockingQueue<>(1);
        private final FutureTask<V> result = new FutureTask<>(completion::peek);

        public boolean complete(final V value) {
            final boolean offered = completion.offer(value);
            if (offered)
                result.run();
            return offered;
        }

        public V get() throws ExecutionException, InterruptedException {
            return result.get();
        }

        public V get(final long timeout, final TimeUnit unit) throws ExecutionException, InterruptedException, TimeoutException {
            return result.get(timeout, unit);
        }

        public boolean isDone() {
            return !completion.isEmpty();
        }

        public GhettoCompletableFuture<V> newIncompleteFuture() {
            return new GhettoCompletableFuture<>();
        }
    }

    /**
     * {@link android.net.VpnService} implementation for {@link GoBackend}
     */
    public static class VpnService extends android.net.VpnService {
        @Nullable private volatile GoBackend owner;
        private final long serviceToken = AwgActivationLifecycle.newServiceToken();

        long serviceToken() { return serviceToken; }

        /** Physical Android DNS only; unavailable networks fail closed. */
        public InetAddress[] resolveEndpoint(String host) throws java.net.UnknownHostException {
            android.net.ConnectivityManager cm = getSystemService(android.net.ConnectivityManager.class);
            java.util.List<android.net.Network> networks = new java.util.ArrayList<>();
            android.net.Network active = cm.getActiveNetwork();
            if (active != null) networks.add(active);
            java.util.Collections.addAll(networks, cm.getAllNetworks());
            for (android.net.Network network : new java.util.LinkedHashSet<>(networks)) {
                android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                if (caps == null || !caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                        !caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue;
                try {
                    java.util.List<InetAddress> addresses = org.amnezia.awg.config.EndpointResolver.order(network.getAllByName(host));
                    if (!addresses.isEmpty()) return addresses.toArray(new InetAddress[0]);
                } catch (java.net.UnknownHostException ignored) { }
            }
            throw new java.net.UnknownHostException("Physical endpoint DNS unavailable");
        }

        public Builder getBuilder() {
            return new Builder();
        }

        @Override
        public void onCreate() {
            // A retired instance must never complete a replacement future.
            servicePublication.publish(this, serviceToken, () -> vpnService.complete(this));
            super.onCreate();
        }

        @Override
        public void onDestroy() {
            // Clear only this exact instance, before releasing its teardown.
            // An old/never-adopted service must not reset B's future.
            servicePublication.retire(this, serviceToken,
                    () -> vpnService = vpnService.newIncompleteFuture());
            final GoBackend owningBackend = owner;
            if (owningBackend != null) {
                final AwgActivationLifecycle.ServiceDestroy<Tunnel, Config> destroyed =
                        owningBackend.activation.destroyService(serviceToken);
                final AwgActivationLifecycle.Teardown<Tunnel, Config> down = destroyed.teardown();
                try {
                    if (down.wasActive()) {
                        if (down.handle() != AwgActivationLifecycle.NO_HANDLE) awgTurnOff(down.handle());
                        if (down.tunnel() != null) {
                            try { down.tunnel().onStateChange(State.DOWN); }
                            catch (RuntimeException | Error ignored) { }
                        }
                    }
                } finally { down.complete(); }
            }
            super.onDestroy();
        }

        @Override
        public int onStartCommand(@Nullable final Intent intent, final int flags, final int startId) {
            servicePublication.publish(this, serviceToken, () -> vpnService.complete(this));
            if (intent == null || intent.getComponent() == null || !intent.getComponent().getPackageName().equals(getPackageName())) {
                Log.d(TAG, "Service started by Always-on VPN feature");
                if (alwaysOnCallback != null)
                    alwaysOnCallback.alwaysOnTriggered();
            }
            return super.onStartCommand(intent, flags, startId);
        }

        private boolean adoptOwner(final GoBackend owner) {
            return servicePublication.adopt(this, serviceToken, () -> this.owner = owner);
        }

        public void setOwner(final GoBackend owner) {
            this.owner = owner;
        }
    }
}
