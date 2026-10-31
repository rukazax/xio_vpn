package desktop

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"xio.local/rivet/internal/rivet"
)

type recordingEndpointNetwork struct {
	result   string
	hosts    []string
	bypassed []netip.Addr
}

const domainAWG = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.77.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = fr-host.fr:51820\nAllowedIPs = 0.0.0.0/0\n"

func (n *recordingEndpointNetwork) Resolve(host string) string {
	n.hosts = append(n.hosts, host)
	return n.result
}
func (n *recordingEndpointNetwork) bypass(address netip.Addr) error {
	n.bypassed = append(n.bypassed, address)
	return nil
}

func TestPrepareEndpointsDomainFamiliesAndCandidates(t *testing.T) {
	for _, tc := range []struct {
		name, host, result, endpoint string
		candidates                   []string
	}{
		{"a-only", "fr-host.fr", "203.0.113.112", "203.0.113.112:8443", []string{"203.0.113.112:8443"}},
		{"aaaa-only", "fr-host.fr", "2a0c:b641:1a0:800::1", "[2a0c:b641:1a0:800::1]:8443", []string{"[2a0c:b641:1a0:800::1]:8443"}},
		{"dual", "vpn.example.com", "203.0.113.112,2a0c:b641:1a0:800::1", "203.0.113.112:8443", []string{"203.0.113.112:8443", "[2a0c:b641:1a0:800::1]:8443"}},
		{"multi-family-order", "fr-host.fr.", "2a0c:b641:1a0:800::1,203.0.113.1,2a0c:b641:1a0:800::2,203.0.113.2", "[2a0c:b641:1a0:800::1]:8443", []string{"[2a0c:b641:1a0:800::1]:8443", "203.0.113.1:8443", "[2a0c:b641:1a0:800::2]:8443", "203.0.113.2:8443"}},
		{"punycode", "xn--bcher-kva.example", "2001:db8::1,192.0.2.1", "[2001:db8::1]:8443", []string{"[2001:db8::1]:8443", "192.0.2.1:8443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Profile{Endpoints: []string{tc.host + ":8443"}}
			n := &recordingEndpointNetwork{result: tc.result}
			if err := prepareEndpoints(&p, n); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(n.hosts, []string{tc.host}) {
				t.Fatalf("resolved hosts = %v", n.hosts)
			}
			if p.Endpoints[0] != tc.endpoint {
				t.Fatalf("endpoint = %q, want %q", p.Endpoints[0], tc.endpoint)
			}
			if !reflect.DeepEqual(p.EndpointCandidates[0], tc.candidates) {
				t.Fatalf("candidates = %v, want %v", p.EndpointCandidates[0], tc.candidates)
			}
			if len(n.bypassed) != len(tc.candidates) {
				t.Fatalf("bypass addresses = %v", n.bypassed)
			}
		})
	}
}

func TestPrepareEndpointsRejectsMalformedDomainBeforeDNS(t *testing.T) {
	for _, endpoint := range []string{
		"[fr-host.fr]:8443",
		"[203.0.113.112]:8443",
		"https://fr-host.fr:8443",
		"fr-host.fr/path:8443",
		"fr-host.fr:https",
		"fr-host.fr:0",
		"fr-host.fr:65536",
		"fr-host..fr:8443",
		"bad host:8443",
		"fr_host.fr:8443",
	} {
		p := Profile{Endpoints: []string{endpoint}}
		n := &recordingEndpointNetwork{result: "203.0.113.112"}
		if err := prepareEndpoints(&p, n); err == nil {
			t.Errorf("accepted malformed endpoint %q", endpoint)
		}
		if len(n.hosts) != 0 || len(n.bypassed) != 0 {
			t.Errorf("malformed endpoint %q reached DNS/bypass", endpoint)
		}
	}
}

func TestAWGProfileAcceptsDomainEndpoint(t *testing.T) {
	raw := domainAWG
	p, err := ParseProfile("awg", raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Endpoints[0] != "fr-host.fr:51820" || !strings.Contains(p.IPC, "endpoint=fr-host.fr:51820\n") {
		t.Fatalf("domain endpoint lost: %q %q", p.Endpoints[0], p.IPC)
	}
	n := &recordingEndpointNetwork{result: "203.0.113.112,2a0c:b641:1a0:800::1"}
	if err := prepareEndpoints(&p, n); err != nil {
		t.Fatal(err)
	}
	if p.Endpoints[0] != "203.0.113.112:51820" || len(p.EndpointCandidates[0]) != 2 {
		t.Fatalf("AWG candidates = %v %v", p.Endpoints, p.EndpointCandidates)
	}
}

func TestAWGProfileRejectsMalformedDomainEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"fr-host.fr:0",
		"fr-host.fr:65536",
		"fr-host.fr:https",
		"fr-host..fr:51820",
		"bad host:51820",
		"fr_host.fr:51820",
		"[fr-host.fr]:51820",
		"https://fr-host.fr:51820",
	} {
		raw := strings.Replace(domainAWG, "Endpoint = fr-host.fr:51820", "Endpoint = "+endpoint, 1)
		if _, err := ParseProfile("awg", raw); err == nil {
			t.Errorf("accepted malformed AWG endpoint %q", endpoint)
		}
	}
}

func TestRivetProfileKeepsDomainEndpointForPlatformResolution(t *testing.T) {
	config := rivet.ClientConfig{
		Protocol:   "rivet-s1",
		Endpoint:   "fr-host.fr:8443",
		ServerName: "fr-host.fr",
		Pin:        base64.StdEncoding.EncodeToString(make([]byte, 32)),
		GatewayID:  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		ID:         strings.Repeat("01", 16),
		Secret:     base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))),
		EntryToken: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))),
		IP:         "10.79.0.2",
	}
	raw, _ := json.Marshal(config)
	p, err := ParseProfile(config.Protocol, string(raw))
	if err != nil || p.Endpoints[0] != "fr-host.fr:8443" {
		t.Fatalf("domain profile changed: %v %v", p.Endpoints, err)
	}
	n := &recordingEndpointNetwork{result: "203.0.113.112"}
	if err := prepareEndpoints(&p, n); err != nil || p.Endpoints[0] != "203.0.113.112:8443" {
		t.Fatalf("domain profile not resolved: %v %v", p.Endpoints, err)
	}
}
