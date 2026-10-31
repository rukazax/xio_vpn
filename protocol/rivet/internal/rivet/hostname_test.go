package rivet

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hostnameClientConfig(protocol, endpoint, serverName string) ClientConfig {
	return ClientConfig{
		Protocol:   protocol,
		Endpoint:   endpoint,
		ServerName: serverName,
		Pin:        base64.StdEncoding.EncodeToString(make([]byte, 32)),
		GatewayID:  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		ID:         strings.Repeat("01", 16),
		Secret:     base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))),
		EntryToken: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))),
		IP:         "10.79.0.2",
	}
}

func TestClientConfigAcceptsDomainEndpoints(t *testing.T) {
	for _, protocol := range []string{"rivet-s1", "rivet-h3"} {
		for _, tc := range []struct{ endpoint, serverName string }{
			{"fr-host.fr:8443", "fr-host.fr"},
			{"vpn.example.com:443", "vpn.example.com"},
			{"fr-host.fr.:8443", "fr-host.fr."},
			{"xn--bcher-kva.example:8443", "xn--bcher-kva.example"},
			{"localhost:8443", "localhost"},
			{"203.0.113.112:8443", "fr-host.fr"},
			{"[2a0c:b641:1a0:800::1]:8443", "fr-host.fr"},
			{"[2a0c:b641:1a0:800::1]:8443", "2a0c:b641:1a0:800::1"},
		} {
			c := hostnameClientConfig(protocol, tc.endpoint, tc.serverName)
			if err := c.Validate(); err != nil {
				t.Errorf("%s %q %q rejected: %v", protocol, tc.endpoint, tc.serverName, err)
			}
		}
	}
}

func TestClientConfigRejectsMalformedDomainInput(t *testing.T) {
	for _, protocol := range []string{"rivet-s1", "rivet-h3"} {
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
			"[2a0c:b641:1a0:800::1]8443",
		} {
			c := hostnameClientConfig(protocol, endpoint, "fr-host.fr")
			if err := c.Validate(); err == nil {
				t.Errorf("%s accepted malformed endpoint %q", protocol, endpoint)
			}
		}
		for _, serverName := range []string{
			"",
			"https://fr-host.fr",
			"fr-host.fr:8443",
			"bad host",
			"[fr-host.fr]",
			"fr_host.fr",
			"-fr-host.fr",
			"fr-host..fr",
			strings.Repeat("a", 64) + ".example",
		} {
			c := hostnameClientConfig(protocol, "fr-host.fr:8443", serverName)
			if err := c.Validate(); err == nil {
				t.Errorf("%s accepted malformed server name %q", protocol, serverName)
			}
		}
	}
}

func TestOuterTLSKeepsDomainIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, certificate, serverName, endpoint, wantSNI string
	}{
		{"domain", "fr-host.fr", "fr-host.fr", "203.0.113.112:8443", "fr-host.fr"},
		{"trailing-dot", "fr-host.fr.", "fr-host.fr.", "203.0.113.112:8443", "fr-host.fr"},
		{"punycode-case", "XN--BCHER-KVA.example", "xn--bcher-kva.example", "203.0.113.112:8443", "xn--bcher-kva.example"},
		{"ipv4-identity", "203.0.113.112", "203.0.113.112", "203.0.113.112:8443", ""},
		{"ipv6-identity", "2a0c:b641:1a0:800::1", "2a0c:b641:1a0:800::1", "[2a0c:b641:1a0:800::1]:8443", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ca, err := GenerateOuter(dir, tc.certificate)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "outer.crt"), filepath.Join(dir, "outer.key"))
			if err != nil {
				t.Fatal(err)
			}
			clientConfig, err := outerTLSConfig(ClientConfig{Endpoint: tc.endpoint, ServerName: tc.serverName, OuterCA: ca})
			if err != nil {
				t.Fatal(err)
			}
			observed := make(chan string, 1)
			serverConfig := &tls.Config{
				Certificates: []tls.Certificate{pair},
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					observed <- hello.ServerName
					return nil, nil
				},
			}
			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			defer serverRaw.Close()
			client := tls.Client(clientRaw, clientConfig)
			server := tls.Server(serverRaw, serverConfig)
			client.SetDeadline(time.Now().Add(3 * time.Second))
			server.SetDeadline(time.Now().Add(3 * time.Second))
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-observed:
				if got != tc.wantSNI {
					t.Fatalf("SNI = %q, want %q", got, tc.wantSNI)
				}
			case <-time.After(time.Second):
				t.Fatal("server did not observe ClientHello")
			}
		})
	}
}

func TestGenerateOuterRejectsMalformedServerName(t *testing.T) {
	for _, name := range []string{"", "fr-host..fr", "[fr-host.fr]", "[2a0c:b641:1a0:800::1]", "bad host", "fr-host.fr:8443", "fr_host.fr", strings.Repeat("a", 64) + ".fr"} {
		if _, err := GenerateOuter(t.TempDir(), name); err == nil {
			t.Errorf("accepted malformed server identity %q", name)
		}
	}
}

func TestDialRejectsUnresolvedDomainBeforeSockets(t *testing.T) {
	for _, protocol := range []string{"rivet-s1", "rivet-h3"} {
		c := hostnameClientConfig(protocol, "fr-host.fr:8443", "fr-host.fr")
		session, err := DialWithTimeout(context.Background(), c, nil, 100*time.Millisecond)
		if session != nil || err == nil || !strings.Contains(err.Error(), "resolved before dialing") {
			t.Fatalf("%s did not reject an unresolved endpoint: session=%v err=%v", protocol, session, err)
		}
	}
}
