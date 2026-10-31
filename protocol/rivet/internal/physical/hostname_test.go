package physical

import (
	"context"
	"strings"
	"testing"
)

func TestValidHostAcceptsAddressesAndDomains(t *testing.T) {
	for _, host := range []string{
		"fr-host.fr",
		"vpn.example.com",
		"localhost",
		"XN--BCHER-KVA.example",
		"fr-host.fr.",
		"203.0.113.112",
		"2a0c:b641:1a0:800::1",
		"::ffff:192.0.2.1",
	} {
		if !ValidHost(host) {
			t.Errorf("valid host rejected: %q", host)
		}
	}
}

func TestValidHostRejectsMalformedNames(t *testing.T) {
	for _, host := range []string{
		"",
		" fr-host.fr",
		"fr-host.fr ",
		"fr-host..fr",
		".fr-host.fr",
		"fr-host.fr..",
		"-fr-host.fr",
		"fr-host-.fr",
		"fr_host.fr",
		"fr-host.fr:8443",
		"[fr-host.fr]",
		"[2001:db8::1]",
		"https://fr-host.fr",
		"fr-host.fr/path",
		"user@fr-host.fr",
		"bad host",
		"256.256.256.256",
		"1.2.3",
		"fe80::1%eth0",
		"0.0.0.0",
		"::",
		"ff02::1",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 127) + "example",
	} {
		if ValidHost(host) {
			t.Errorf("malformed host accepted: %q", host)
		}
	}
}

func TestValidHostLengthBoundary(t *testing.T) {
	valid := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")
	if len(valid) != 253 || !ValidHost(valid) {
		t.Fatalf("253-byte name rejected: len=%d", len(valid))
	}
	if ValidHost(valid + "a") {
		t.Fatal("254-byte name accepted")
	}
	if !ValidHost("fr-host.fr.") || ValidHost("fr-host.fr..") {
		t.Fatal("trailing-dot boundary changed")
	}
}

func TestParseEndpointKeepsBracketIdentity(t *testing.T) {
	for _, tc := range []struct {
		endpoint, host, port string
	}{
		{"fr-host.fr:8443", "fr-host.fr", "8443"},
		{"vpn.example.com:443", "vpn.example.com", "443"},
		{"xn--bcher-kva.example:8443", "xn--bcher-kva.example", "8443"},
		{"fr-host.fr.:8443", "fr-host.fr.", "8443"},
		{"localhost:8443", "localhost", "8443"},
		{"203.0.113.112:8443", "203.0.113.112", "8443"},
		{"[2a0c:b641:1a0:800::1]:8443", "2a0c:b641:1a0:800::1", "8443"},
	} {
		host, port, err := ParseEndpoint(tc.endpoint)
		if err != nil || host != tc.host || port != tc.port {
			t.Errorf("ParseEndpoint(%q) = %q, %q, %v", tc.endpoint, host, port, err)
		}
	}
	for _, endpoint := range []string{
		"",
		"fr-host.fr",
		"fr-host.fr:",
		":8443",
		"fr-host.fr:0",
		"fr-host.fr:65536",
		"fr-host.fr:https",
		"fr-host.fr:-1",
		"[fr-host.fr]:8443",
		"[203.0.113.112]:8443",
		"[2a0c:b641:1a0:800::1]:8443:extra",
		"[2a0c:b641:1a0:800::1]8443",
		"https://fr-host.fr:8443",
		"bad host:8443",
		"fr-host..fr:8443",
	} {
		if _, _, err := ParseEndpoint(endpoint); err == nil {
			t.Errorf("malformed endpoint accepted: %q", endpoint)
		}
	}
}

func TestResolveRejectsMalformedNameBeforeResolver(t *testing.T) {
	called := false
	_, err := Resolve(context.Background(), "fr_host.fr", func(string) string {
		called = true
		return "203.0.113.112"
	})
	if err == nil || called {
		t.Fatalf("malformed name reached resolver: called=%v err=%v", called, err)
	}
}
