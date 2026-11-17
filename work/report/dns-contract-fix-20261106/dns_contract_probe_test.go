package desktop

import (
	"strings"
	"testing"
)

// Runs against the unmodified actual desktop ParseProfile, never a substitute.
func TestDNSSettingNativeContract(t *testing.T) {
	raw := "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.77.0.2/32, fd77:1::2/128\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.4:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	for _, value := range []string{"1.1.1.1", "192.0.2.53", "10.0.0.53", "172.16.0.53", "192.168.1.53", "2606:4700:4700::1111", "2001:db8::53", "fd00::53", "192.0.2.53, fd00::53"} {
		t.Run("accept/"+value, func(t *testing.T) {
			p, err := ParseProfile("awg", strings.Replace(raw, "DNS = 1.1.1.1", "DNS = "+value, 1))
			if err != nil {
				t.Fatalf("valid DNS rejected: %v", err)
			}
			if len(p.DNS) != len(strings.Split(value, ",")) {
				t.Fatal("DNS entries lost")
			}
		})
	}
	for _, value := range []string{"dns.example.org", "0.0.0.0", "::", "127.0.0.1", "::1", "169.254.1.53", "fe80::53", "224.0.0.53", "ff02::53", "255.255.255.255", "::ffff:192.0.2.53", "::ffff:c000:235", "01.1.1.1", "fe80::1%eth0", "https://dns.example.org/dns-query"} {
		t.Run("reject/"+value, func(t *testing.T) {
			if _, err := ParseProfile("awg", strings.Replace(raw, "DNS = 1.1.1.1", "DNS = "+value, 1)); err == nil {
				t.Fatal("invalid DNS accepted")
			}
		})
	}
}
