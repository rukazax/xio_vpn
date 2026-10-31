package rivet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"xio.local/rivet/internal/physical"
)

// endpointLookup is the operating-system resolver boundary used only by the
// explicit diagnostic API. Protected VPN dialing never uses it: a profile that
// still carries a hostname is resolved by the platform's physical-network
// resolver before DialWithTimeout.
type endpointLookup func(context.Context, string) ([]netip.Addr, error)

func systemEndpointLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ResolveEndpointCandidates resolves a hostname endpoint through the operating
// system resolver and returns one numeric copy of the profile per candidate,
// ordered by the shared physical DNS contract (deduplicated, families
// interleaved, bounded). ServerName, pin and every other field are preserved.
//
// It is intended for standalone diagnostics such as `rivet probe`. The VPN
// data path must use the platform resolver and DialWithTimeout, which rejects
// unresolved hostnames.
func ResolveEndpointCandidates(ctx context.Context, c ClientConfig, timeout time.Duration) ([]ClientConfig, error) {
	return resolveEndpointCandidates(ctx, c, timeout, systemEndpointLookup)
}

func resolveEndpointCandidates(ctx context.Context, c ClientConfig, timeout time.Duration, lookup endpointLookup) ([]ClientConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	host, port, err := physical.ParseEndpoint(c.Endpoint)
	if err != nil {
		return nil, ErrProtocol
	}
	if net.ParseIP(host) != nil {
		return []ClientConfig{c}, nil
	}
	if lookup == nil {
		return nil, errors.New("rivet: endpoint resolver unavailable")
	}
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan struct {
		addresses []netip.Addr
		err       error
	}, 1)
	go func() {
		addresses, err := lookup(attempt, host)
		done <- struct {
			addresses []netip.Addr
			err       error
		}{addresses, err}
	}()
	var found []netip.Addr
	select {
	case <-attempt.Done():
		return nil, attempt.Err()
	case result := <-done:
		if attempt.Err() != nil {
			return nil, attempt.Err()
		}
		if result.err != nil {
			return nil, errors.New("rivet: endpoint DNS failed")
		}
		found = result.addresses
	}
	values := make([]string, 0, len(found))
	for _, address := range found {
		values = append(values, address.Unmap().String())
	}
	addresses, err := physical.Addresses(strings.Join(values, ","))
	if err != nil {
		return nil, errors.New("rivet: endpoint DNS failed")
	}
	candidates := make([]ClientConfig, 0, len(addresses))
	for _, address := range addresses {
		candidate := c
		candidate.Endpoint = net.JoinHostPort(address, port)
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

// DialDiagnostic is the explicit, unprotected diagnostic path for `rivet
// probe`. It resolves the configured hostname through the operating system
// resolver (bounded), then attempts the numeric candidates sequentially inside
// one overall deadline, keeping ServerName and the inner pin unchanged.
//
// The protected VPN path must not call this function: it uses DialWithTimeout
// with numeric candidates from the platform resolver and cannot fall back to
// system DNS.
func DialDiagnostic(ctx context.Context, c ClientConfig, timeout time.Duration) (*Session, error) {
	dial := func(ctx context.Context, candidate ClientConfig, budget time.Duration) (*Session, error) {
		return DialWithTimeout(ctx, candidate, nil, budget)
	}
	return dialDiagnosticWith(ctx, c, timeout, systemEndpointLookup, dial)
}

func dialDiagnosticWith(ctx context.Context, c ClientConfig, timeout time.Duration, lookup endpointLookup, dial func(context.Context, ClientConfig, time.Duration) (*Session, error)) (*Session, error) {
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	// The lookup gets its own bounded context. The dial candidates use the
	// caller's context (and a per-attempt budget) so the returned session keeps
	// the lifecycle of the caller instead of dying when fallback state is
	// discarded.
	deadline := time.Now().Add(timeout)
	lookupCtx, cancelLookup := context.WithTimeout(ctx, min(timeout, 5*time.Second))
	candidates, err := resolveEndpointCandidates(lookupCtx, c, min(timeout, 5*time.Second), lookup)
	cancelLookup()
	if err != nil {
		return nil, err
	}
	var last error
	for i, candidate := range candidates {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		budget := remaining
		if i+1 < len(candidates) {
			budget = min(5*time.Second, remaining/time.Duration(len(candidates)-i))
		}
		session, e := dial(ctx, candidate, budget)
		if e == nil {
			return session, nil
		}
		last = e
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if last == nil {
		return nil, errors.New("rivet: endpoint DNS failed")
	}
	return nil, last
}
