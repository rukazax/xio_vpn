package desktop

import (
	"fmt"
	"strings"
	"testing"
)

// Run only after the independent reviewer's in-flight matrix has completed.
// This calls the production ParseProfile; it does not resolve or activate.
func TestDNSSettingNativeLinkLocalBoundaries(t *testing.T) {
	raw := "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.77.0.2/32, fd77:1::2/128\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.4:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	check := func(t *testing.T, value string, accepted bool) {
		t.Helper()
		_, err := ParseProfile("awg", strings.Replace(raw, "DNS = 1.1.1.1", "DNS = "+value, 1))
		if (err == nil) != accepted {
			t.Fatalf("DNS %s: accepted=%t want=%t", value, err == nil, accepted)
		}
	}
	for second := 0; second < 256; second++ {
		value := fmt.Sprintf("fe%02x::53", second)
		t.Run(value, func(t *testing.T) {
			check(t, value, second < 0x80 || second > 0xbf)
		})
	}
	for _, c := range []struct {
		value    string
		accepted bool
	}{
		{"169.253.1.53", true},
		{"169.254.1.53", false},
		{"169.255.1.53", true},
	} {
		t.Run(c.value, func(t *testing.T) { check(t, c.value, c.accepted) })
	}
}
