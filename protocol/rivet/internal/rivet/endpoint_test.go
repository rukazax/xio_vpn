package rivet

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func fakeLookup(table map[string][]string, calls *[]string, block chan struct{}) endpointLookup {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		if calls != nil {
			*calls = append(*calls, host)
		}
		if block != nil {
			select {
			case <-block:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		values, ok := table[host]
		if !ok {
			return nil, errors.New("fixture: no such host")
		}
		addresses := make([]netip.Addr, 0, len(values))
		for _, value := range values {
			addresses = append(addresses, netip.MustParseAddr(value))
		}
		return addresses, nil
	}
}

func endpointConfig(host string) ClientConfig {
	return hostnameClientConfig("rivet-s1", host+":8443", host)
}

func candidateEndpoints(candidates []ClientConfig) []string {
	endpoints := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		endpoints = append(endpoints, candidate.Endpoint)
	}
	return endpoints
}

func TestResolveEndpointCandidatesFamiliesAndOrder(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		answers    []string
		want       []string
	}{
		{"a-only", "fr-host.fr", []string{"203.0.113.112"}, []string{"203.0.113.112:8443"}},
		{"aaaa-only", "fr-host.fr", []string{"2a0c:b641:1a0:800::1"}, []string{"[2a0c:b641:1a0:800::1]:8443"}},
		{"dual-v4-first", "fr-host.fr", []string{"203.0.113.112", "2a0c:b641:1a0:800::1"}, []string{"203.0.113.112:8443", "[2a0c:b641:1a0:800::1]:8443"}},
		{"dual-v6-first", "vpn.example.com", []string{"2a0c:b641:1a0:800::1", "203.0.113.112"}, []string{"[2a0c:b641:1a0:800::1]:8443", "203.0.113.112:8443"}},
		{"multiple-interleaved", "fr-host.fr.", []string{"203.0.113.1", "2a0c:b641:1a0:800::1", "203.0.113.2", "203.0.113.1"}, []string{"203.0.113.1:8443", "[2a0c:b641:1a0:800::1]:8443", "203.0.113.2:8443"}},
		{"punycode", "xn--bcher-kva.example", []string{"203.0.113.112"}, []string{"203.0.113.112:8443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			original := endpointConfig(tc.host)
			candidates, err := resolveEndpointCandidates(context.Background(), original, time.Second, fakeLookup(map[string][]string{tc.host: tc.answers}, &calls, nil))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(candidateEndpoints(candidates), tc.want) {
				t.Fatalf("candidates = %v, want %v", candidateEndpoints(candidates), tc.want)
			}
			if len(calls) != 1 || calls[0] != tc.host {
				t.Fatalf("lookup calls = %v", calls)
			}
			for _, candidate := range candidates {
				if candidate.ServerName != original.ServerName || candidate.Pin != original.Pin || candidate.Secret != original.Secret {
					t.Fatal("identity fields changed between candidates")
				}
			}
		})
	}
}

func TestResolveEndpointCandidatesLiteralAndMalformed(t *testing.T) {
	for _, endpoint := range []string{"203.0.113.112:8443", "[2a0c:b641:1a0:800::1]:8443"} {
		var calls []string
		original := hostnameClientConfig("rivet-s1", endpoint, "fr-host.fr")
		candidates, err := resolveEndpointCandidates(context.Background(), original, time.Second, fakeLookup(nil, &calls, nil))
		if err != nil || len(candidates) != 1 || candidates[0].Endpoint != endpoint {
			t.Fatalf("literal %q: %v %v", endpoint, candidates, err)
		}
		if len(calls) != 0 {
			t.Fatalf("literal %q reached the resolver", endpoint)
		}
	}
	for _, endpoint := range []string{"[fr-host.fr]:8443", "https://fr-host.fr:8443", "bad host:8443", "fr-host..fr:8443", "fr-host.fr:https"} {
		var calls []string
		original := hostnameClientConfig("rivet-s1", endpoint, "fr-host.fr")
		if _, err := resolveEndpointCandidates(context.Background(), original, time.Second, fakeLookup(nil, &calls, nil)); err == nil {
			t.Errorf("accepted malformed endpoint %q", endpoint)
		}
		if len(calls) != 0 {
			t.Errorf("malformed endpoint %q reached the resolver", endpoint)
		}
	}
}

func TestResolveEndpointCandidatesCancellationAndDNSErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls []string
	if _, err := resolveEndpointCandidates(ctx, endpointConfig("fr-host.fr"), time.Second, fakeLookup(nil, &calls, nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	if len(calls) != 0 {
		t.Fatal("canceled resolution invoked the resolver")
	}

	block := make(chan struct{})
	defer close(block)
	started := time.Now()
	if _, err := resolveEndpointCandidates(context.Background(), endpointConfig("fr-host.fr"), 30*time.Millisecond, fakeLookup(nil, nil, block)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked resolver: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("blocked resolver ignored the lookup deadline")
	}

	for _, table := range []map[string][]string{{}, {"fr-host.fr": {}}} {
		if _, err := resolveEndpointCandidates(context.Background(), endpointConfig("fr-host.fr"), time.Second, fakeLookup(table, nil, nil)); err == nil || !strings.Contains(err.Error(), "DNS failed") {
			t.Fatalf("DNS failure %v", err)
		}
	}
}

func TestProtectedDialRejectsHostnameBeforeDNS(t *testing.T) {
	protector := &familyOnly{allow: true}
	cfg := endpointConfig("fr-host.fr")
	session, err := DialWithTimeout(context.Background(), cfg, protector, time.Second)
	if session != nil || err == nil || !strings.Contains(err.Error(), "resolved before dialing") {
		t.Fatalf("protected dial accepted a hostname: session=%v err=%v", session, err)
	}
	if protector.calls != 0 {
		t.Fatalf("protected domain dial touched a socket: calls=%d", protector.calls)
	}
	// The high-level unprotected API is the explicit diagnostic path. It must
	// still reject malformed hostnames before any lookup.
	if session, err := Dial(context.Background(), endpointConfig("bad host"), nil); session != nil || err == nil {
		t.Fatalf("diagnostic Dial accepted a malformed host: session=%v err=%v", session, err)
	}
}

func TestDialDiagnosticFallbackPreservesIdentity(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	var attempted []ClientConfig
	original := endpointConfig("fr-host.fr")
	dial := func(_ context.Context, candidate ClientConfig, _ time.Duration) (*Session, error) {
		mu.Lock()
		defer mu.Unlock()
		attempted = append(attempted, candidate)
		if len(attempted) < 3 {
			return nil, errors.New("fixture: candidate unreachable")
		}
		return &Session{}, nil
	}
	session, err := dialDiagnosticWith(context.Background(), original, 2*time.Second, fakeLookup(map[string][]string{
		"fr-host.fr": {"203.0.113.1", "203.0.113.2", "2a0c:b641:1a0:800::1"},
	}, &calls, nil), dial)
	if err != nil || session == nil {
		t.Fatalf("diagnostic fallback: session=%v err=%v", session, err)
	}
	want := []string{"203.0.113.1:8443", "[2a0c:b641:1a0:800::1]:8443", "203.0.113.2:8443"}
	if got := candidateEndpoints(attempted); !reflect.DeepEqual(got, want) {
		t.Fatalf("attempted = %v, want %v", got, want)
	}
	for _, candidate := range attempted {
		if candidate.ServerName != original.ServerName || candidate.Pin != original.Pin {
			t.Fatal("diagnostic fallback changed TLS identity")
		}
	}
}

func TestDialDiagnosticKeepsSessionContextAlive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	canceled := make(chan struct{}, 1)
	dial := func(dialCtx context.Context, _ ClientConfig, _ time.Duration) (*Session, error) {
		go func() {
			<-dialCtx.Done()
			canceled <- struct{}{}
		}()
		return &Session{}, nil
	}
	if _, err := dialDiagnosticWith(ctx, endpointConfig("fr-host.fr"), time.Second, fakeLookup(map[string][]string{"fr-host.fr": {"203.0.113.112"}}, nil, nil), dial); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
		t.Fatal("diagnostic dial canceled the context used by the returned session")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestDialDiagnosticFailuresAndCancellation(t *testing.T) {
	base := endpointConfig("fr-host.fr")
	lookup := fakeLookup(map[string][]string{"fr-host.fr": {"203.0.113.1", "203.0.113.2"}}, nil, nil)
	last := errors.New("fixture: all unreachable")
	dial := func(context.Context, ClientConfig, time.Duration) (*Session, error) { return nil, last }
	if session, err := dialDiagnosticWith(context.Background(), base, time.Second, lookup, dial); session != nil || !errors.Is(err, last) {
		t.Fatalf("all candidates failed: session=%v err=%v", session, err)
	}
	if session, err := dialDiagnosticWith(context.Background(), base, time.Second, fakeLookup(nil, nil, nil), dial); session != nil || err == nil || !strings.Contains(err.Error(), "DNS failed") {
		t.Fatalf("DNS failure: session=%v err=%v", session, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var attempted int
	dialCancel := func(_ context.Context, _ ClientConfig, _ time.Duration) (*Session, error) {
		attempted++
		cancel()
		return nil, context.Canceled
	}
	if session, err := dialDiagnosticWith(ctx, base, time.Second, lookup, dialCancel); session != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled diagnostic: session=%v err=%v", session, err)
	}
	if attempted != 1 {
		t.Fatalf("canceled diagnostic kept dialing: attempts=%d", attempted)
	}
}

func TestOuterCertificateIdentitySANs(t *testing.T) {
	for _, tc := range []struct {
		name, identity string
		dns            []string
		ips            []string
		verify         []string
	}{
		{"domain", "fr-host.fr", []string{"fr-host.fr"}, nil, []string{"fr-host.fr", "FR-HOST.FR"}},
		{"trailing-dot", "fr-host.fr.", []string{"fr-host.fr."}, nil, []string{"fr-host.fr."}},
		{"ipv4", "203.0.113.112", nil, []string{"203.0.113.112"}, []string{"203.0.113.112"}},
		{"ipv6", "2a0c:b641:1a0:800::1", nil, []string{"2a0c:b641:1a0:800::1"}, []string{"2a0c:b641:1a0:800::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := GenerateOuter(dir, tc.identity); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "outer.crt"))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(raw)
			if block == nil {
				t.Fatal("outer certificate is not PEM")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(certificate.DNSNames, tc.dns) {
				t.Fatalf("DNS SANs = %v, want %v", certificate.DNSNames, tc.dns)
			}
			ips := make([]string, 0, len(certificate.IPAddresses))
			for _, ip := range certificate.IPAddresses {
				ips = append(ips, ip.String())
			}
			if strings.Join(ips, ",") != strings.Join(tc.ips, ",") {
				t.Fatalf("IP SANs = %v, want %v", ips, tc.ips)
			}
			for _, host := range tc.verify {
				if err := certificate.VerifyHostname(host); err != nil {
					t.Fatalf("VerifyHostname(%q): %v", host, err)
				}
			}
			if net.ParseIP(tc.identity) != nil {
				if err := certificate.VerifyHostname(tc.identity); err != nil {
					t.Fatalf("IP identity does not verify: %v", err)
				}
			}
		})
	}
}

func TestDiagnosticBudgetIncludesLookup(t *testing.T) {
	const total = time.Second
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		time.Sleep(30 * time.Millisecond)
		return []netip.Addr{netip.MustParseAddr("203.0.113.112")}, nil
	}
	called := false
	dial := func(_ context.Context, _ ClientConfig, budget time.Duration) (*Session, error) {
		called = true
		if budget > total-25*time.Millisecond {
			t.Fatalf("DNS time was not subtracted from overall budget: %v", budget)
		}
		return &Session{}, nil
	}
	if _, err := dialDiagnosticWith(context.Background(), endpointConfig("fr-host.fr"), total, lookup, dial); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("numeric candidate not dialed")
	}
}

func TestCanceledLiteralDoesNotBypassCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := hostnameClientConfig("rivet-s1", "203.0.113.112:8443", "fr-host.fr")
	called := false
	lookup := func(context.Context, string) ([]netip.Addr, error) { called = true; return nil, nil }
	if _, err := resolveEndpointCandidates(ctx, cfg, time.Second, lookup); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled literal: %v", err)
	}
	if called {
		t.Fatal("canceled literal invoked DNS")
	}
}
