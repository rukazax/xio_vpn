/* SPDX-License-Identifier: Apache-2.0
 * XIO physical-network endpoint selection. No system DNS fallback.
 */
package org.amnezia.awg.config;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

public final class EndpointResolver {
    public interface Resolver { InetAddress[] resolve(String host) throws Exception; }
    // A timed-out synchronous Android DNS request may outlive its caller. Do not
    // accumulate unbounded threads on repeated reconnects while it is stuck.
    private static final Semaphore IN_FLIGHT = new Semaphore(1);
    public static List<InetAddress> order(InetAddress[] addresses) {
        List<InetAddress> usable = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (InetAddress address : addresses) {
            if (address == null || address.isAnyLocalAddress() || address.isMulticastAddress() ||
                    address instanceof Inet6Address && address.isLinkLocalAddress()) continue;
            if (seen.add(address.getHostAddress())) usable.add(address);
        }
        List<InetAddress> primary = new ArrayList<>(), secondary = new ArrayList<>();
        boolean first4 = !usable.isEmpty() && usable.get(0) instanceof Inet4Address;
        for (InetAddress address : usable)
            ((address instanceof Inet4Address) == first4 ? primary : secondary).add(address);
        List<InetAddress> result = new ArrayList<>();
        for (int i = 0; i < Math.max(primary.size(), secondary.size()) && result.size() < 16; i++) {
            if (i < primary.size()) result.add(primary.get(i));
            if (i < secondary.size() && result.size() < 16) result.add(secondary.get(i));
        }
        return result;
    }
    public static List<InetAddress> resolve(String host, Resolver resolver, long timeoutMillis) throws Exception {
        if (resolver == null || timeoutMillis <= 0 || !IN_FLIGHT.tryAcquire())
            throw new IllegalStateException("Physical endpoint DNS unavailable");
        AtomicBoolean started = new AtomicBoolean();
        FutureTask<InetAddress[]> result = new FutureTask<>(() -> {
            started.set(true);
            try { return resolver.resolve(host); } finally { IN_FLIGHT.release(); }
        });
        Thread worker = new Thread(() -> { try { result.run(); } finally { if (!started.get()) IN_FLIGHT.release(); } }, "xio-awg-physical-dns");
        worker.setDaemon(true);
        try { worker.start(); } catch (RuntimeException | Error e) { IN_FLIGHT.release(); throw e; }
        try { return order(result.get(timeoutMillis, TimeUnit.MILLISECONDS)); }
        finally { result.cancel(true); }
    }
    private EndpointResolver() { }
}
