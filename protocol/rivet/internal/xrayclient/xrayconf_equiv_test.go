package xrayclient

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/core"
	// The legacy loader must stay available to the test binary so every case
	// can be compared against the code path this change replaced. Importing it
	// here does not link it into the helper: test files never reach the binary.
	_ "github.com/xtls/xray-core/main/json"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func legacyConfig(c Config) (*core.Config, error) {
	return core.LoadConfig("json", bytes.NewReader(configBytes(c)))
}

const (
	uuidLower = "b3b2eb49-e41f-41df-9761-0956785a236b"
	shortID   = "0123456789abcdef"
)

func outboundProfile(protocol, settings, stream string) string {
	if stream == "" {
		return fmt.Sprintf(`{"protocol":"xray","outbound":{"protocol":%q,"settings":%s}}`, protocol, settings)
	}
	return fmt.Sprintf(`{"protocol":"xray","outbound":{"protocol":%q,"settings":%s,"streamSettings":%s}}`, protocol, settings, stream)
}

func vlessSettings(address string, port int, user string) string {
	return fmt.Sprintf(`{"vnext":[{"address":%q,"port":%d,"users":[%s]}]}`, address, port, user)
}

func vlessUser(extra string) string {
	if extra == "" {
		return fmt.Sprintf(`{"id":%q,"encryption":"none"}`, uuidLower)
	}
	return fmt.Sprintf(`{"id":%q,"encryption":"none",%s}`, uuidLower, extra)
}

func trojanSettings(address string, port int, password, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"servers":[{"address":%q,"port":%d,"password":%q%s}]}`, address, port, password, extra)
}

func vmessSettings(address string, port int, user string) string {
	return fmt.Sprintf(`{"vnext":[{"address":%q,"port":%d,"users":[%s]}]}`, address, port, user)
}

// mlkemEncryption builds a VLESS "encryption" value of the
// mlkem768x25519plus.<mode>.<rtt>[.<padding>].<key> form that the profile
// grammar accepts.
func mlkemEncryption(t *testing.T, mode, rtt, padding string) string {
	t.Helper()
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	parts := []string{"mlkem768x25519plus", mode, rtt}
	if padding != "" {
		parts = append(parts, padding)
	}
	parts = append(parts, base64.RawURLEncoding.EncodeToString(key.EncapsulationKey().Bytes()))
	return strings.Join(parts, ".")
}

func tlsStream(network, settingsKey, settings, tls string) string {
	if settingsKey == "" {
		return fmt.Sprintf(`{"network":%q,"security":"tls","tlsSettings":%s}`, network, tls)
	}
	return fmt.Sprintf(`{"network":%q,"security":"tls",%q:%s,"tlsSettings":%s}`, network, settingsKey, settings, tls)
}

func realityStream(network, settingsKey, settings, reality string) string {
	if settingsKey == "" {
		return fmt.Sprintf(`{"network":%q,"security":"reality","realitySettings":%s}`, network, reality)
	}
	return fmt.Sprintf(`{"network":%q,"security":"reality",%q:%s,"realitySettings":%s}`, network, settingsKey, settings, reality)
}

// equivalenceCorpus covers every protocol, transport and security combination
// the XIO profile grammar accepts (internal/xrayclient.Parse), plus the
// optional knobs a hand-written profile can still reach.
func equivalenceCorpus(t *testing.T) []struct{ name, profile string } {
	t.Helper()
	certJSON, err := json.Marshal(fixtureCert)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.Marshal(fixtureKey)
	if err != nil {
		t.Fatal(err)
	}
	vless := func(user string) string { return vlessSettings("vpn.example.com", 443, user) }
	wsSettings := `{"path":"/ws","headers":{"Host":"cdn.example.com"}}`
	xhttpApp := `{"path":"/x","host":"cdn.example.com","mode":"auto"}`
	realityPK := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	realityBase := fmt.Sprintf(`{"serverName":"www.example.com","fingerprint":"chrome","publicKey":%q,"shortId":%q}`, realityPK, shortID)

	return []struct{ name, profile string }{
		{"vless/tcp/tls minimal", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com"}`))},
		{"vless/raw/tls (raw transport name)", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("raw", "", "", `{"serverName":"vpn.example.com"}`))},
		{"vless/tcp/tls with tcpSettings.header=http", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("tcp", "tcpSettings", `{"header":{"type":"http","request":{"path":["/"],"headers":{"Host":["www.example.com"]}},"response":{"status":"200","reason":"OK","headers":{"Content-Type":["text/html"]}}}}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/tcp/tls with tcpSettings.header=none", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("tcp", "tcpSettings", `{"header":{"type":"none"}}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/tcp/tls with rawSettings alias", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("tcp", "rawSettings", `{"acceptProxyProtocol":true}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/ws/tls (headers Host)", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("ws", "wsSettings", wsSettings, `{"serverName":"vpn.example.com"}`))},
		{"vless/ws/tls path with ed", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("ws", "wsSettings", `{"path":"/ws?ed=2048","host":"cdn.example.com","heartbeatPeriod":10}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/grpc/tls full", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("grpc", "grpcSettings", `{"serviceName":"svc","authority":"auth.example.com","multiMode":true,"idle_timeout":60,"health_check_timeout":10,"permit_without_stream":true,"initial_windows_size":65535,"user_agent":"ua"}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/httpupgrade/tls", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("httpupgrade", "httpupgradeSettings", `{"path":"/hu","host":"cdn.example.com"}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/httpupgrade/tls path with ed", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("httpupgrade", "httpupgradeSettings", `{"path":"/hu?ed=1024","host":"cdn.example.com"}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/xhttp/tls app shape", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("xhttp", "xhttpSettings", xhttpApp, `{"serverName":"vpn.example.com"}`))},
		{"vless/xhttp/tls splithttpSettings alias", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("splithttp", "splithttpSettings", `{"path":"/sp","host":"cdn.example.com","mode":"stream-one"}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/xhttp/tls extra block", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("xhttp", "xhttpSettings", `{"path":"/x","host":"cdn.example.com","mode":"packet-up","extra":{"xPaddingBytes":"100-1000","scMaxEachPostBytes":1000000,"noGRPCHeader":true,"mode":"packet-up","headers":{"X-Test":"1"}}}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/xhttp/tls xmux custom", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("xhttp", "xhttpSettings", `{"path":"/x","mode":"auto","xmux":{"maxConcurrency":16,"cMaxReuseTimes":100,"hKeepAlivePeriod":30}}`, `{"serverName":"vpn.example.com"}`))},
		{"vless/tcp/reality minimal", outboundProfile("vless", vless(vlessUser("")),
			realityStream("tcp", "", "", realityBase))},
		{"vless/tcp/reality flow vision", outboundProfile("vless", vless(vlessUser(`"flow":"xtls-rprx-vision"`)),
			realityStream("tcp", "", "", realityBase))},
		{"vless/tcp/reality flow vision-udp443", outboundProfile("vless", vless(vlessUser(`"flow":"xtls-rprx-vision-udp443"`)),
			realityStream("tcp", "", "", realityBase))},
		{"vless/tcp/reality spiderX params", outboundProfile("vless", vless(vlessUser("")),
			realityStream("tcp", "", "", fmt.Sprintf(`{"serverName":"www.example.com","fingerprint":"firefox","publicKey":%q,"shortId":%q,"spiderX":"/p?p=100-200&c=3&t=5&i=10&r=3"}`, realityPK, shortID)))},
		{"vless/grpc/reality", outboundProfile("vless", vless(vlessUser("")),
			realityStream("grpc", "grpcSettings", `{"serviceName":"svc"}`, realityBase))},
		{"vless/xhttp/reality", outboundProfile("vless", vless(vlessUser("")),
			realityStream("xhttp", "xhttpSettings", xhttpApp, realityBase))},
		{"vless/tcp/tls fingerprint+alpn+versions", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com","fingerprint":"chrome","alpn":["h2","http/1.1"],"minVersion":"1.2","maxVersion":"1.3","cipherSuites":"TLS_AES_128_GCM_SHA256","enableSessionResumption":true,"disableSystemRoot":true,"rejectUnknownSni":false,"curvePreferences":["X25519","P-256"]}`))},
		{"vless/tcp/tls pinned+vcn+masterKeyLog", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com","masterKeyLog":"/tmp/keys.log","pinnedPeerCertSha256":"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99","verifyPeerCertByName":"a.example,b.example","echConfigList":"AEn+DQBF"}`))},
		{"vless/tcp/tls inline certificate+key", outboundProfile("vless", vless(vlessUser("")),
			tlsStream("tcp", "", "", fmt.Sprintf(`{"certificates":[{"certificate":%s,"key":%s,"usage":"verify","ocspStapling":60,"oneTimeLoading":false,"buildChain":true}],"serverName":"localhost","disableSystemRoot":true}`, certJSON, keyJSON)))},
		{"vless/tcp/tls + mux + tag", fmt.Sprintf(`{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy","settings":%s,"streamSettings":%s,"mux":{"enabled":true,"concurrency":8,"xudpConcurrency":16,"xudpProxyUDP443":"allow"}}}`, vless(vlessUser("")), tlsStream("tcp", "", "", `{"serverName":"vpn.example.com"}`))},
		{"vless/tcp/tls mux defaults", fmt.Sprintf(`{"protocol":"xray","outbound":{"protocol":"vless","settings":%s,"streamSettings":%s,"mux":{"enabled":true}}}`, vless(vlessUser("")), tlsStream("tcp", "", "", `{"serverName":"vpn.example.com"}`))},
		{"vless/tcp/tls default network (no network key)", outboundProfile("vless", vless(vlessUser("")),
			`{"security":"tls","tlsSettings":{"serverName":"vpn.example.com"}}`)},
		{"vless/tcp/tls override via streamSettings.port+address", outboundProfile("vless", vless(vlessUser("")),
			`{"network":"tcp","security":"tls","address":"vpn.example.com","port":8443,"tlsSettings":{"serverName":"vpn.example.com"}}`)},
		{"vless/tcp/tls IPv4 endpoint", outboundProfile("vless", vlessSettings("203.0.113.9", 8443, vlessUser("")),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com"}`))},
		{"vless/tcp/tls vnext level/email", outboundProfile("vless", vlessSettings("vpn.example.com", 443, vlessUser(`"level":1,"email":"u@example.com"`)),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com"}`))},
		{"vless/xhttp/tls vless encryption mlkem 1rtt", outboundProfile("vless", vless(vlessUser(fmt.Sprintf(`"encryption":%q`, mlkemEncryption(t, "native", "1rtt", "")))),
			tlsStream("xhttp", "xhttpSettings", xhttpApp, `{"serverName":"vpn.example.com"}`))},
		{"vless/xhttp/tls vless encryption mlkem 0rtt xorpub padded", outboundProfile("vless", vless(vlessUser(fmt.Sprintf(`"encryption":%q`, mlkemEncryption(t, "xorpub", "0rtt", "100-200")))),
			tlsStream("xhttp", "xhttpSettings", xhttpApp, `{"serverName":"vpn.example.com"}`))},
		{"vmess/ws/none", outboundProfile("vmess", vmessSettings("vpn.example.com", 443, fmt.Sprintf(`{"id":%q,"alterId":0,"security":"auto"}`, uuidLower)),
			`{"network":"ws","security":"none","wsSettings":{"path":"/vm","headers":{"Host":"cdn.example.com"}}}`)},
		{"vmess/tcp/tls aes-128-gcm", outboundProfile("vmess", vmessSettings("vpn.example.com", 443, fmt.Sprintf(`{"id":%q,"security":"aes-128-gcm","experiments":"test"}`, uuidLower)),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com","fingerprint":"chrome"}`))},
		{"vmess/grpc/none chacha20", outboundProfile("vmess", vmessSettings("vpn.example.com", 443, fmt.Sprintf(`{"id":%q,"security":"chacha20-poly1305"}`, uuidLower)),
			`{"network":"grpc","security":"none","grpcSettings":{"serviceName":"svc"}}`)},
		{"vmess/tcp/tls bogus security falls back to auto", outboundProfile("vmess", vmessSettings("vpn.example.com", 443, fmt.Sprintf(`{"id":%q,"security":"bogus"}`, uuidLower)),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com"}`))},
		{"trojan/tls minimal", outboundProfile("trojan", trojanSettings("vpn.example.com", 443, "s3cret", ""),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com"}`))},
		{"trojan/ws/tls", outboundProfile("trojan", trojanSettings("vpn.example.com", 443, "s3cret", ""),
			tlsStream("ws", "wsSettings", wsSettings, `{"serverName":"vpn.example.com"}`))},
		{"trojan/grpc/tls", outboundProfile("trojan", trojanSettings("vpn.example.com", 443, "s3cret", ""),
			tlsStream("grpc", "grpcSettings", `{"serviceName":"svc","multiMode":true}`, `{"serverName":"vpn.example.com"}`))},
		{"trojan/httpupgrade/tls", outboundProfile("trojan", trojanSettings("vpn.example.com", 443, "s3cret", ""),
			tlsStream("httpupgrade", "httpupgradeSettings", `{"path":"/hu","host":"cdn.example.com"}`, `{"serverName":"vpn.example.com"}`))},
		{"trojan/xhttp/tls level+email", outboundProfile("trojan", trojanSettings("vpn.example.com", 443, "s3cret", `"level":1,"email":"t@example.com"`),
			tlsStream("xhttp", "xhttpSettings", xhttpApp, `{"serverName":"vpn.example.com"}`))},
	}
}

func TestConfigEquivalenceWithJSONLoader(t *testing.T) {
	corpus := equivalenceCorpus(t)
	if len(corpus) < 30 {
		t.Fatalf("corpus must cover at least 30 profiles, have %d", len(corpus))
	}
	for _, tc := range corpus {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse(tc.profile)
			if err != nil {
				t.Fatalf("Parse rejected a supported profile: %v", err)
			}
			reference, err := legacyConfig(c)
			if err != nil {
				t.Fatalf("legacy loader rejected the profile: %v", err)
			}
			built, err := buildConfig(c)
			if err != nil {
				t.Fatalf("protobuf builder rejected the profile: %v", err)
			}
			// Re-marshal both so the comparison is on wire form as well as on
			// in-memory field values.
			refBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(reference)
			if err != nil {
				t.Fatal(err)
			}
			builtBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(built)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(refBytes, builtBytes) || !proto.Equal(reference, built) {
				t.Fatalf("config mismatch\n--- legacy (json/infra-conf)\n%s\n--- builder (protobuf)\n%s",
					prototext.Format(reference), prototext.Format(built))
			}
		})
	}
}

// TestVlessUUIDCanonicalisation pins the one transformation the legacy path
// applied to user identifiers.
func TestVlessUUIDCanonicalisation(t *testing.T) {
	for _, in := range []string{
		"B3B2EB49-E41F-41DF-9761-0956785A236B",
		"b3b2eb49e41f41df97610956785a236b",
	} {
		raw := outboundProfile("vless", vlessSettings("vpn.example.com", 443, fmt.Sprintf(`{"id":%q,"encryption":"none"}`, in)),
			tlsStream("tcp", "", "", `{"serverName":"vpn.example.com"}`))
		c, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		built, err := buildConfig(c)
		if err != nil {
			t.Fatalf("build(%q): %v", in, err)
		}
		if !strings.Contains(prototext.Format(built), uuidLower) {
			t.Fatalf("uuid %q was not canonicalised to %q:\n%s", in, uuidLower, prototext.Format(built))
		}
		reference, err := legacyConfig(c)
		if err != nil {
			t.Fatalf("legacy(%q): %v", in, err)
		}
		if !proto.Equal(reference, built) {
			t.Fatalf("uuid %q mismatch:\n--- legacy\n%s\n--- builder\n%s", in, prototext.Format(reference), prototext.Format(built))
		}
	}
}

// TestKnownBehaviourDeltas documents, and pins, every profile the legacy JSON
// path accepts but the protobuf builder refuses. These features are not part
// of the XIO profile grammar (app/lib/extended_profile.dart never emits them);
// the legacy path is still reachable with `-tags xrayjson`. The test fails if
// any case stops being a delta (builder accepted it after all, which would
// make the entry stale) and also fails if the builder accepts a profile the
// legacy path rejects.
//
// It decodes profiles with encoding/json instead of Parse, because Parse runs
// the builder and would hide the difference.
func TestKnownBehaviourDeltas(t *testing.T) {
	if xrayLegacyConfig {
		t.Skip("xrayjson build: buildConfig is the legacy JSON loader, so there is no delta to pin")
	}
	type delta struct {
		name    string
		profile string
	}
	base := func(stream string) string {
		return outboundProfile("vless", vlessSettings("vpn.example.com", 443, vlessUser("")), stream)
	}
	cases := []delta{
		{"finalmask tcp fragment", base(`{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com"},"finalmask":{"tcp":[{"type":"fragment","settings":{"length":"10-20","delay":"1-2"}}]}}`)},
		{"finalmask udp salamander", base(`{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com"},"finalmask":{"tcp":[{"type":"fragment","settings":{"length":"10-20"}}],"udp":[{"type":"salamander","settings":{"password":"p"}}]}}`)},
		{"kcpSettings stray", base(`{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com"},"kcpSettings":{"mtu":1350}}`)},
		{"hysteriaSettings stray", base(`{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com"},"hysteriaSettings":{"version":2,"auth":"a"}}`)},
		{"tls echSockopt", base(`{"network":"tcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com","echSockopt":{"mark":1}}}`)},
		{"method kcp alias", base(`{"method":"kcp","security":"tls","tlsSettings":{"serverName":"vpn.example.com"}}`)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			if err := json.Unmarshal([]byte(tc.profile), &c); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_, legacyErr := legacyConfig(c)
			_, buildErr := buildConfig(c)
			switch {
			case legacyErr == nil && buildErr != nil:
				t.Logf("expected delta: legacy accepts, builder refuses")
			case legacyErr != nil && buildErr != nil:
				t.Fatalf("both paths refuse the profile (%v); it is not a delta", legacyErr)
			case legacyErr != nil && buildErr == nil:
				t.Fatalf("builder accepts a profile the legacy path refuses (%v)", legacyErr)
			default:
				t.Fatalf("both paths accept the profile; the delta entry is stale")
			}
		})
	}
}
