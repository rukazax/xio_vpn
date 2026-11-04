package xrayclient

// Live smoke for the default (protobuf) config path: profiles in exactly the
// shape app/lib/extended_profile.dart produces are parsed and started through
// the real helper entry points. Starting an instance builds and validates the
// whole config (apps, dispatcher, outbound, transports, TLS/REALITY); the
// tunnel itself is exercised by TestProtectedVLESSTLSRoundTrip and
// TestXHTTPModesWithVLESSEncryption, which dial a local echo server.

import (
	"strings"
	"testing"
	"time"
)

func TestStartAppShapedProfiles(t *testing.T) {
	realityPK := "MZb4wq3Z9jV7kY1nR2tP6xL8cD5hG0sA4eF7uJ2mQ9o"
	profiles := map[string]string{
		"vless/tcp/tls":         `{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"B3B2EB49-E41F-41DF-9761-0956785A236B","encryption":"none","flow":""}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com","fingerprint":"chrome"}}}}`,
		"vless/tcp/reality":     `{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","fingerprint":"chrome","publicKey":"` + realityPK + `","shortId":"0123456789abcdef","spiderX":"/"}}}}`,
		"vless/xhttp/reality":   `{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","encryption":"none","flow":""}]}]},"streamSettings":{"network":"xhttp","security":"reality","xhttpSettings":{"path":"/x","host":"cdn.example.com","mode":"auto"},"realitySettings":{"serverName":"www.example.com","fingerprint":"chrome","publicKey":"` + realityPK + `","shortId":"0123456789abcdef","spiderX":"/"}}}}`,
		"vless/ws/tls":          `{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","encryption":"none","flow":""}]}]},"streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}},"tlsSettings":{"serverName":"vpn.example.com","fingerprint":"chrome"}}}}`,
		"vless/grpc/tls":        `{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","encryption":"none","flow":""}]}]},"streamSettings":{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"svc"},"tlsSettings":{"serverName":"vpn.example.com","fingerprint":"chrome"}}}}`,
		"vless/httpupgrade/tls": `{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","encryption":"none","flow":""}]}]},"streamSettings":{"network":"httpupgrade","security":"tls","httpupgradeSettings":{"path":"/hu","host":"cdn.example.com"},"tlsSettings":{"serverName":"vpn.example.com","fingerprint":"chrome"}}}}`,
		"vmess/ws/none":         `{"protocol":"xray","outbound":{"protocol":"vmess","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","alterId":0,"security":"auto"}]}]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vm","headers":{"Host":"cdn.example.com"}}}}}`,
		"vmess/tcp/tls":         `{"protocol":"xray","outbound":{"protocol":"vmess","tag":"proxy","settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","alterId":0,"security":"aes-128-gcm"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com","fingerprint":"chrome"}}}}`,
		"trojan/tls":            `{"protocol":"xray","outbound":{"protocol":"trojan","tag":"proxy","settings":{"servers":[{"address":"vpn.example.com","port":443,"password":"s3cret"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com","fingerprint":"chrome"}}}}`,
		"trojan/xhttp/tls":      `{"protocol":"xray","outbound":{"protocol":"trojan","tag":"proxy","settings":{"servers":[{"address":"vpn.example.com","port":443,"password":"s3cret"}]},"streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{"path":"/x","host":"cdn.example.com","mode":"auto"},"tlsSettings":{"serverName":"vpn.example.com","fingerprint":"chrome"}}}}`,
	}
	if xrayLegacyConfig {
		t.Log("xrayjson build: the same profiles go through the legacy JSON loader")
	}
	for name, raw := range profiles {
		name, raw := name, raw
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			s, err := Start(raw, protect(true), 5*time.Second)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer s.Close()
			status := s.Status()
			if !strings.Contains(status, `"active":false`) {
				t.Fatalf("unexpected status: %s", status)
			}
		})
	}
}
