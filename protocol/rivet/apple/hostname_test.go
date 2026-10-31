package apple

import (
	"context"
	"testing"

	"xio.local/rivet/internal/rivet"
)

type domainAppleProtector struct {
	answer string
	hosts  []string
}

func (p *domainAppleProtector) Protect(int64) bool { return true }
func (p *domainAppleProtector) Resolve(host string) string {
	p.hosts = append(p.hosts, host)
	return p.answer
}

func TestAppleResolveDomainKeepsIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, host, answer, endpoint string
	}{
		{"a-only", "fr-host.fr", "203.0.113.112", "203.0.113.112:8443"},
		{"aaaa-only", "fr-host.fr", "2a0c:b641:1a0:800::1", "[2a0c:b641:1a0:800::1]:8443"},
		{"trailing-dot", "fr-host.fr.", "203.0.113.112", "203.0.113.112:8443"},
		{"punycode", "xn--bcher-kva.example", "203.0.113.112", "203.0.113.112:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &domainAppleProtector{answer: tc.answer}
			c := rivet.ClientConfig{Endpoint: tc.host + ":8443", ServerName: tc.host}
			resolved, err := resolve(context.Background(), c, p)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.Endpoint != tc.endpoint || resolved.ServerName != tc.host {
				t.Fatalf("resolved = %q %q", resolved.Endpoint, resolved.ServerName)
			}
			if len(p.hosts) != 1 || p.hosts[0] != tc.host {
				t.Fatalf("resolver hosts = %v", p.hosts)
			}
		})
	}
}

func TestAppleResolveLiteralBypassesPhysicalDNS(t *testing.T) {
	for _, endpoint := range []string{"203.0.113.112:8443", "[2a0c:b641:1a0:800::1]:8443"} {
		p := &domainAppleProtector{answer: "192.0.2.1"}
		c := rivet.ClientConfig{Endpoint: endpoint, ServerName: "fr-host.fr"}
		resolved, err := resolve(context.Background(), c, p)
		if err != nil || resolved.Endpoint != endpoint {
			t.Fatalf("literal %q changed: %v %v", endpoint, resolved.Endpoint, err)
		}
		if len(p.hosts) != 0 {
			t.Fatalf("literal %q reached physical DNS", endpoint)
		}
	}
}

func TestAppleResolveSingleNumericABIAndMalformedInput(t *testing.T) {
	for _, endpoint := range []string{
		"[fr-host.fr]:8443",
		"https://fr-host.fr:8443",
		"bad host:8443",
		"fr-host..fr:8443",
	} {
		p := &domainAppleProtector{answer: "203.0.113.112"}
		if _, err := resolve(context.Background(), rivet.ClientConfig{Endpoint: endpoint}, p); err == nil {
			t.Errorf("accepted malformed endpoint %q", endpoint)
		}
		if len(p.hosts) != 0 {
			t.Errorf("malformed endpoint %q reached physical DNS", endpoint)
		}
	}
	for _, answer := range []string{"", "203.0.113.112,2a0c:b641:1a0:800::1"} {
		p := &domainAppleProtector{answer: answer}
		if _, err := resolve(context.Background(), rivet.ClientConfig{Endpoint: "fr-host.fr:8443"}, p); err == nil {
			t.Errorf("accepted non-single numeric answer %q", answer)
		}
		if len(p.hosts) != 1 {
			t.Errorf("answer %q callbacks = %v", answer, p.hosts)
		}
	}
}
