package rivet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func packet6(src, dst string) []byte {
	b := make([]byte, 48)
	b[0] = 0x60
	b[6] = 17
	b[7] = 64
	binary.BigEndian.PutUint16(b[4:], 8)
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	return b
}
func TestIPv6UserBindingAndPublicPolicy(t *testing.T) {
	if IPv6For("10.79.0.31") != "fd79:1::1f" {
		t.Fatal("slot binding")
	}
	b := packet6("fd79:1::2", "2001:4860:4860::8888")
	if CheckIP(b, "10.79.0.2", true) != nil || Destination(b) != "2001:4860:4860::8888" {
		t.Fatal("IPv6 rejected")
	}
	if CheckIP(b, "10.79.0.3", true) == nil {
		t.Fatal("source spoof accepted")
	}
	for _, dst := range []string{"::1", "fd79:1::1", "fe80::1", "ff02::1", "2001:db8::1", "64:ff9b::7f00:1", "::ffff:127.0.0.1"} {
		if CheckIP(packet6("fd79:1::2", dst), "10.79.0.2", true) == nil {
			t.Fatal(dst)
		}
	}
	for _, next := range []byte{0, 43, 44, 60} {
		bad := append([]byte{}, b...)
		bad[6] = next
		if CheckIP(bad, "10.79.0.2", true) == nil {
			t.Fatal("extension accepted", next)
		}
	}
	b[4] = 1
	if CheckIP(b, "", false) == nil {
		t.Fatal("bad length accepted")
	}
}

func TestNAT64DoesNotBypassLocalGatewayDestinationPolicy(t *testing.T) {
	gateway := &Gateway{locals: map[string]bool{"81.177.142.37": true}}
	if !gateway.localDestination("64:ff9b::51b1:8e25") {
		t.Fatal("NAT64 bypass of local gateway policy")
	}
	if gateway.localDestination("64:ff9b::101:101") {
		t.Fatal("public remote misclassified as local")
	}
}
