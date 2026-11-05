/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg.config;

import org.amnezia.awg.util.NonNullForAll;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.regex.Pattern;

import androidx.annotation.Nullable;


/**
 * An external endpoint (host and port) used to connect to an AmneziaWG {@link Peer}.
 * <p>
 * Instances of this class are externally immutable.
 */
@NonNullForAll
public final class InetEndpoint {
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");

    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    @Nullable private InetEndpoint resolved;
    private java.util.List<InetEndpoint> resolvedCandidates = java.util.Collections.emptyList();
    public java.util.List<InetEndpoint> getResolvedCandidates() {
        if (isResolved) return java.util.Collections.singletonList(this);
        synchronized(lock) { return new java.util.ArrayList<>(resolvedCandidates); }
    }

    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }

    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");
        final URI uri;
        try {
            uri = new URI("awg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(InetEndpoint.class, endpoint, e);
        }
        if (uri.getPort() < 0 || uri.getPort() > 65535)
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
        String parsedHost = uri.getHost();
        if (parsedHost == null) throw new ParseException(InetEndpoint.class, endpoint, "Missing host");
        if (parsedHost.startsWith("[") && parsedHost.endsWith("]")) parsedHost = parsedHost.substring(1, parsedHost.length() - 1);
        try {
            InetAddresses.parse(parsedHost);
            // Parsing ths host as a numeric address worked, so we don't need to do DNS lookups.
            return new InetEndpoint(parsedHost, true, uri.getPort());
        } catch (final ParseException ignored) {
            // Failed to parse the host as a numeric address, so it must be a DNS hostname/FQDN.
            return new InetEndpoint(parsedHost, false, uri.getPort());
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof InetEndpoint))
            return false;
        final InetEndpoint other = (InetEndpoint) obj;
        return host.equals(other.host) && port == other.port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    /**
     * Return the numeric endpoint or the last explicitly physical-resolved value.
     * Cache-only: this API never performs system/VPN DNS I/O.
     *
     * @return the resolved endpoint, or {@link Optional#empty()}
     */
    public Optional<InetEndpoint> getResolved() {
        if (isResolved)
            return Optional.of(this);
        // Serialization is cache-only: never fall back to the VPN/system DNS.
        synchronized (lock) { return Optional.ofNullable(resolved); }
    }

    /** Explicit, bounded physical-network resolution before userspace serialization.
     * Retains Android's preferred family (including DNS64), not unconditional A.
     * Selecting the first candidate is NOT transport/handshake failover. */
    public Optional<InetEndpoint> getResolved(EndpointResolver.Resolver resolver, long timeoutMillis) {
        if (isResolved) return Optional.of(this);
        synchronized (lock) {
            resolved = null;
            resolvedCandidates = java.util.Collections.emptyList();
            try {
                java.util.List<InetAddress> addresses = EndpointResolver.resolve(host, resolver, timeoutMillis);
                java.util.List<InetEndpoint> candidates = new java.util.ArrayList<>();
                for(InetAddress address:addresses) candidates.add(new InetEndpoint(address.getHostAddress(), true, port));
                resolvedCandidates = candidates;
                if (!candidates.isEmpty()) resolved = candidates.get(0);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception ignored) { }
            return Optional.ofNullable(resolved);
        }
    }

    @Override
    public int hashCode() {
        return host.hashCode() ^ port;
    }

    @Override
    public String toString() {
        final boolean isBareIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
    }
}
