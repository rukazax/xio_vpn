package xrayclient

import (
	"encoding/json"
	"testing"
)

func xrayDomainConfig(address string) string {
	raw, _ := json.Marshal(map[string]any{
		"protocol": "xray",
		"outbound": map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": address,
				"port":    443,
				"users":   []any{map[string]any{"id": "b3b2eb49-e41f-41df-9761-0956785a236b", "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "fr-host.fr"}},
		},
	})
	return string(raw)
}

func TestXrayAcceptsDomainAddress(t *testing.T) {
	for _, address := range []string{"fr-host.fr", "vpn.example.com", "fr-host.fr.", "xn--bcher-kva.example", "203.0.113.112", "2a0c:b641:1a0:800::1"} {
		if _, err := Parse(xrayDomainConfig(address)); err != nil {
			t.Errorf("domain address rejected: %q: %v", address, err)
		}
	}
}

func TestXrayRejectsMalformedDomainAddress(t *testing.T) {
	for _, address := range []string{"", "[fr-host.fr]", "bad host", "fr_host.fr", "fr-host..fr", "-fr-host.fr", "https://fr-host.fr", "fr-host.fr:443"} {
		if _, err := Parse(xrayDomainConfig(address)); err == nil {
			t.Errorf("malformed address accepted: %q", address)
		}
	}
}
