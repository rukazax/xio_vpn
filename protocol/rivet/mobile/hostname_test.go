package mobile

import (
	"context"
	"strings"
	"testing"
	"time"

	"xio.local/rivet/internal/rivet"
)

type domainResolver struct {
	answer string
	hosts  []string
}

func (p *domainResolver) Protect(int64) bool { return true }
func (p *domainResolver) Resolve(host string) string {
	p.hosts = append(p.hosts, host)
	return p.answer
}

func TestResolveDomainKeepsServerNameAndFirstPhysicalCandidate(t *testing.T) {
	for _, tc := range []struct {
		name, host, answer, endpoint string
	}{
		{"a-only", "fr-host.fr", "203.0.113.112", "203.0.113.112:8443"},
		{"aaaa-only", "fr-host.fr", "2a0c:b641:1a0:800::1", "[2a0c:b641:1a0:800::1]:8443"},
		{"dual", "vpn.example.com", "203.0.113.112,2a0c:b641:1a0:800::1", "203.0.113.112:8443"},
		{"multi", "fr-host.fr.", "2a0c:b641:1a0:800::1,203.0.113.1,2a0c:b641:1a0:800::2", "[2a0c:b641:1a0:800::1]:8443"},
		{"punycode", "xn--bcher-kva.example", "203.0.113.112", "203.0.113.112:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &domainResolver{answer: tc.answer}
			c := rivet.ClientConfig{Endpoint: tc.host + ":8443", ServerName: tc.host}
			resolved, err := resolve(c, p)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.Endpoint != tc.endpoint {
				t.Fatalf("endpoint = %q, want %q", resolved.Endpoint, tc.endpoint)
			}
			if resolved.ServerName != tc.host {
				t.Fatalf("server name = %q, want %q", resolved.ServerName, tc.host)
			}
			if len(p.hosts) != 1 || p.hosts[0] != tc.host {
				t.Fatalf("resolver hosts = %v", p.hosts)
			}
		})
	}
}

func TestResolveLiteralDoesNotUsePhysicalDNS(t *testing.T) {
	for _, endpoint := range []string{"203.0.113.112:8443", "[2a0c:b641:1a0:800::1]:8443"} {
		p := &domainResolver{answer: "192.0.2.1"}
		resolved, err := resolve(rivet.ClientConfig{Endpoint: endpoint, ServerName: "fr-host.fr"}, p)
		if err != nil || resolved.Endpoint != endpoint {
			t.Fatalf("literal %q changed: %v %v", endpoint, resolved.Endpoint, err)
		}
		if len(p.hosts) != 0 {
			t.Fatalf("literal %q reached physical DNS", endpoint)
		}
	}
}

func TestResolveRejectsMalformedDomainBeforeDNS(t *testing.T) {
	for _, endpoint := range []string{
		"[fr-host.fr]:8443",
		"https://fr-host.fr:8443",
		"bad host:8443",
		"fr-host..fr:8443",
		"fr-host.fr:https",
	} {
		p := &domainResolver{answer: "203.0.113.112"}
		if _, err := resolve(rivet.ClientConfig{Endpoint: endpoint}, p); err == nil {
			t.Errorf("accepted malformed endpoint %q", endpoint)
		}
		if len(p.hosts) != 0 {
			t.Errorf("malformed endpoint %q reached physical DNS", endpoint)
		}
	}
}

func TestResolveTimedDomainUsesBoundedResult(t *testing.T) {
	p := &domainResolver{answer: "203.0.113.112,2a0c:b641:1a0:800::1"}
	resolved, err := resolveTimed(context.Background(), rivet.ClientConfig{Endpoint: "fr-host.fr:8443", ServerName: "fr-host.fr"}, p, time.Second)
	if err != nil || resolved.Endpoint != "203.0.113.112:8443" || resolved.ServerName != "fr-host.fr" {
		t.Fatalf("resolveTimed: %#v %v", resolved, err)
	}
	if len(p.hosts) != 1 || p.hosts[0] != "fr-host.fr" {
		t.Fatalf("resolver hosts = %v", p.hosts)
	}
}

func TestResolveEmptyAnswerFailsClosed(t *testing.T) {
	p := &domainResolver{answer: ""}
	_, err := resolve(rivet.ClientConfig{Endpoint: "fr-host.fr:8443"}, p)
	if err == nil || !strings.Contains(err.Error(), "DNS failed") {
		t.Fatalf("empty answer error = %v", err)
	}
}
