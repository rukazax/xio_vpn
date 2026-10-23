package desktop

import (
	"strings"
	"testing"
)

func TestPrivilegedProfileRejectsScriptsAndUnsafeAWG(t *testing.T) {
	base := "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.77.0.2/32\nDNS = 1.1.1.1\n%s\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.4:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	good := strings.Replace(base, "%s", "", 1)
	if _, e := ParseProfile("awg", good); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"PostUp = touch /tmp/xio", "PreDown = true", "Jc = 99999999", "Jmin = -1", "H1 = 4294967296", "H1 = 20-10", "Jmin = 200\nJmax = 100"} {
		if _, e := ParseProfile("awg", strings.Replace(base, "%s", field, 1)); e == nil {
			t.Fatalf("accepted unsafe field %q", field)
		}
	}
	for _, field := range []string{"Jc = 4\nJmin = 40\nJmax = 70", "H1 = 100-200", "S1 = 0\nS2 = 1280"} {
		if _, e := ParseProfile("awg", strings.Replace(base, "%s", field, 1)); e != nil {
			t.Fatalf("safe profile rejected: %s", field)
		}
	}
}

func TestAWG31ExtensionsAndLimits(t *testing.T) {
	raw := "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.78.0.2/32\nDNS = 1.1.1.1\nListenPort = 0\nHeaderProtectionKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nContentPaddingAddition = 0-32\nRekeyAfterTime = 90-120\nRekeyTimeout = 4-6\nRejectAfterTime = 180\nKeepaliveTimeout = 10\nMaxHandshakeAttempts = 5\nRandomTrailers = true\nDisableCookies = false\n[Peer]\nPublicKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\nEndpoint = 203.0.113.4:51821\nAllowedIPs = 0.0.0.0/0\n"
	p, e := ParseProfile("awg", raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"header_protection_key=", "content_padding_addition=0-32", "rekey_after_time=90-120", "random_trailers=true", "listen_port=0"} {
		if !strings.Contains(p.IPC, key) {
			t.Fatalf("missing expected field %s", key)
		}
	}
	for _, v := range []string{"0", "999999999", "120-90"} {
		if _, e := ParseProfile("awg", strings.Replace(raw, "RekeyAfterTime = 90-120", "RekeyAfterTime = "+v, 1)); e == nil {
			t.Fatal("unsafe timer range accepted")
		}
	}
}
