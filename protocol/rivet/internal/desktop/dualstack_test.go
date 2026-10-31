package desktop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
	"xio.local/rivet/internal/rivet"
)

const dualstackAWG = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.77.0.2/32, fd77::2/128\nDNS = 1.1.1.1, 2606:4700:4700::1111\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = [2001:db8::42]:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"

func TestAWGPayloadAndDNSFamilies(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		v4, v6    bool
	}{
		{"dual", dualstackAWG, true, true},
		{"v4", strings.ReplaceAll(strings.ReplaceAll(dualstackAWG, ", fd77::2/128", ""), ", 2606:4700:4700::1111", ""), true, false},
		{"v6", strings.ReplaceAll(strings.ReplaceAll(dualstackAWG, "10.77.0.2/32, ", ""), "1.1.1.1, ", ""), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseProfile("awg", tc.raw)
			if err != nil || p.hasFamily(false) != tc.v4 || p.hasFamily(true) != tc.v6 {
				t.Fatalf("families rejected: %v", err)
			}
			if p.Endpoints[0] != "[2001:db8::42]:51820" || !strings.Contains(p.IPC, "endpoint=[2001:db8::42]:51820\n") {
				t.Fatal("IPv6 endpoint lost")
			}
		})
	}
	for _, raw := range []string{
		strings.Replace(dualstackAWG, "0.0.0.0/0, ::/0", "0.0.0.0/0", 1),
		strings.Replace(dualstackAWG, "0.0.0.0/0, ::/0", "::/0", 1),
		strings.Replace(dualstackAWG, "10.77.0.2/32, fd77::2/128", "10.77.0.2/32", 1),
		strings.Replace(dualstackAWG, "fd77::2/128", "::ffff:10.77.0.2/128", 1),
		strings.Replace(dualstackAWG, "2606:4700:4700::1111", "fe80::1", 1),
	} {
		if _, err := ParseProfile("awg", raw); err == nil {
			t.Fatal("accepted unsafe payload/DNS family mismatch")
		}
	}
	only6 := strings.ReplaceAll(strings.ReplaceAll(dualstackAWG, "10.77.0.2/32, ", ""), "DNS = 1.1.1.1, 2606:4700:4700::1111\n", "")
	p, err := ParseProfile("awg", only6)
	if err != nil || len(p.DNS) != 1 || !p.DNS[0].Is6() {
		t.Fatal("IPv6-only default DNS missing")
	}
}

func TestRivetIPv6RequiresAdvertisedLease(t *testing.T) {
	for _, protocol := range []string{"rivet-h3", "rivet-s1"} {
		c := rivet.ClientConfig{Protocol: protocol, Endpoint: "[2001:db8::42]:443", ServerName: "vpn.example", Pin: base64.StdEncoding.EncodeToString(make([]byte, 32)), GatewayID: base64.StdEncoding.EncodeToString(make([]byte, 16)), ID: strings.Repeat("01", 16), Secret: base64.StdEncoding.EncodeToString(make([]byte, 32)), EntryToken: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), IP: "10.79.0.2"}
		for _, v6 := range []bool{false, true} {
			if v6 {
				c.IP6 = "fd79:1::2"
			}
			raw, _ := json.Marshal(c)
			p, err := ParseProfile(protocol, string(raw))
			if err != nil || !p.hasFamily(false) || p.hasFamily(true) != v6 {
				t.Fatalf("lease: %v", err)
			}
		}
		c.IP6 = "fd79:1::3"
		raw, _ := json.Marshal(c)
		if _, err := ParseProfile(protocol, string(raw)); err == nil {
			t.Fatal("spoofed IPv6 lease accepted")
		}
	}
}

type fakeEndpointNetwork struct {
	result   string
	bypassed []netip.Addr
	fail     bool
}

func (n *fakeEndpointNetwork) Resolve(string) string { return n.result }
func (n *fakeEndpointNetwork) bypass(a netip.Addr) error {
	n.bypassed = append(n.bypassed, a)
	if n.fail {
		return errors.New("injected bypass failure")
	}
	return nil
}
func TestEndpointCandidatesHaveFamilyCorrectBypass(t *testing.T) {
	for _, result := range []string{"2001:db8::42", "203.0.113.42", "2001:db8::42,203.0.113.42"} {
		p := Profile{Endpoints: []string{"vpn.example:443"}}
		n := &fakeEndpointNetwork{result: result}
		if err := prepareEndpoints(&p, n); err != nil {
			t.Fatal(err)
		}
		if len(n.bypassed) != len(strings.Split(result, ",")) {
			t.Fatal("a fallback endpoint was not bypassed")
		}
		if strings.Contains(result, "2001:") && p.Endpoints[0] != "[2001:db8::42]:443" {
			t.Fatal("missing IPv6 brackets")
		}
		if !strings.Contains(resolvedIPC("endpoint=vpn.example:443\n", p.Endpoints[0]), "endpoint="+p.Endpoints[0]+"\n") {
			t.Fatal("AWG endpoint not pinned")
		}
	}
	for _, n := range []*fakeEndpointNetwork{{result: "not-an-ip"}, {result: "2001:db8::42", fail: true}} {
		p := Profile{Endpoints: []string{"vpn.example:443"}}
		if err := prepareEndpoints(&p, n); err == nil {
			t.Fatal("endpoint setup did not fail closed")
		}
	}
}

func TestPhysicalDNSBothFamiliesAndTransportFallback(t *testing.T) {
	var calls []string
	lookup := func(ctx context.Context, network, host, server string) ([]netip.Addr, error) {
		if network != "ip" || host != "vpn.example" {
			t.Fatal("not an A+AAAA query")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 1600*time.Millisecond {
			t.Fatal("DNS query is unbounded")
		}
		calls = append(calls, server)
		if server == "1.1.1.1:53" {
			return nil, errors.New("injected IPv4 transport unavailable")
		}
		return []netip.Addr{netip.MustParseAddr("2001:db8::42"), netip.MustParseAddr("203.0.113.42"), netip.MustParseAddr("2001:db8::42")}, nil
	}
	servers := []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"}
	got := resolvePhysicalWith("vpn.example", servers, lookup)
	if got != "2001:db8::42,203.0.113.42" || !reflect.DeepEqual(calls, servers) {
		t.Fatalf("DNS contract: %q %v", got, calls)
	}
	got = resolvePhysicalWith("2001:db8::42", nil, func(context.Context, string, string, string) ([]netip.Addr, error) {
		t.Fatal("numeric address used DNS")
		return nil, nil
	})
	if got != "2001:db8::42" {
		t.Fatal("numeric IPv6 changed")
	}
}

func TestXrayProfileUsesDualstackLocalTUN(t *testing.T) {
	raw := "{\"protocol\":\"xray\",\"outbound\":{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"2001:db8::42\",\"port\":443,\"users\":[{\"id\":\"b3b2eb49-e41f-41df-9761-0956785a236b\",\"encryption\":\"none\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"vpn.example\"}}}}"
	p, err := ParseProfile("xray", raw)
	if err != nil || !p.hasFamily(false) || !p.hasFamily(true) || p.Endpoints[0] != "[2001:db8::42]:443" {
		t.Fatalf("Xray dualstack: %v", err)
	}
}

func TestPhysicalDNSKeepsLinkLocalInterfaceScope(t *testing.T) {
	output := "Global: 1.1.1.1 fe80::bad\nLink 2 (ethernet): fe80::1\n  2606:4700:4700::1111\nLink 7 (wifi): fe80::1 192.0.2.53\nLink 9 (other): fe80::1%other\n"
	want := []string{"1.1.1.1:53", "[fe80::1%2]:53", "[2606:4700:4700::1111]:53", "[fe80::1%7]:53", "192.0.2.53:53", "[fe80::1%other]:53"}
	if got := physicalDNSServers(output); !reflect.DeepEqual(got, want) {
		t.Fatalf("lost DNS interface scope: %v", got)
	}
}

func TestPhysicalDNSCapInterleavesBeforeTruncation(t *testing.T) {
	var v4, v6, mapped4 []netip.Addr
	next6 := netip.MustParseAddr("2001:db8::1")
	for i := 0; i < 16; i++ {
		a4 := netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
		v4 = append(v4, a4)
		mapped4 = append(mapped4, netip.AddrFrom16(a4.As16()))
		v6 = append(v6, next6)
		next6 = next6.Next()
	}
	for _, tc := range []struct {
		name      string
		answers   []netip.Addr
		alternate netip.Addr
		count     int
	}{
		{"16A_then_1AAAA", append(append([]netip.Addr{}, v4...), v6[0]), v6[0], 16},
		{"16AAAA_then_1A", append(append([]netip.Addr{}, v6...), v4[0]), v4[0], 16},
		{"16A_then_16AAAA", append(append([]netip.Addr{}, v4...), v6...), v6[0], 16},
		{"16AAAA_then_16A", append(append([]netip.Addr{}, v6...), v4...), v4[0], 16},
		{"mapped_A_then_AAAA", append(append([]netip.Addr{}, mapped4...), v6[0]), v6[0], 16},
		{"duplicate_A_then_AAAA", append(append([]netip.Addr{}, makeRepeatedAddr(v4[0], 16)...), v6[0]), v6[0], 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolvePhysicalWith("vpn.example", []string{"[2606:4700:4700::1111]:53"}, func(context.Context, string, string, string) ([]netip.Addr, error) { return tc.answers, nil })
			values := strings.Split(got, ",")
			if len(values) != tc.count || values[0] != tc.answers[0].Unmap().String() || values[1] != tc.alternate.String() {
				t.Fatalf("family lost by DNS cap/interleaving: %q", got)
			}
			if reachableAddresses(got, true, false) == "" || reachableAddresses(got, false, true) == "" {
				t.Fatal("single-family outer link lost its only candidate")
			}
			p := Profile{Endpoints: []string{"vpn.example:443"}}
			n := &fakeEndpointNetwork{result: got}
			if err := prepareEndpoints(&p, n); err != nil || len(n.bypassed) != tc.count {
				t.Fatalf("bounded candidates not all bypassed: %v", err)
			}
			seen := map[string]bool{}
			for _, value := range values {
				if seen[value] {
					t.Fatal("duplicate consumed bounded slot")
				}
				seen[value] = true
			}
		})
	}
}
func makeRepeatedAddr(a netip.Addr, count int) []netip.Addr {
	result := make([]netip.Addr, count)
	for i := range result {
		result[i] = a
	}
	return result
}
