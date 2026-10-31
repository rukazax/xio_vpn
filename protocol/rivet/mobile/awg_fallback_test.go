package mobile

import (
	"strings"
	"testing"
)

const awgTestKey = "1111111111111111111111111111111111111111111111111111111111111111"

func TestAwgFallbackValidation(t *testing.T) {
	_, a, e := awgCandidates(awgTestKey, "192.0.2.1:51820,[2001:db8::1]:51820,192.0.2.1:51820", 1000)
	if e != nil || len(a) != 2 || !a[1].Addr().Is6() {
		t.Fatal("numeric family order/dedup", e)
	}
	for _, raw := range []string{
		"vpn.invalid:443", "[::]:443", "[ff02::1]:443", "[fe80::1%eth0]:443",
		"192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:443\nprivate_key=bad",
		strings.Repeat("192.0.2.1:443,", 17),
	} {
		if _, _, e := awgCandidates(awgTestKey, raw, 1000); e == nil {
			t.Errorf("unsafe endpoint accepted: %q", raw)
		}
	}
	for _, key := range []string{"", strings.Repeat("0", 64), awgTestKey + "\n", strings.Repeat("g", 64)} {
		if _, _, e := awgCandidates(key, "192.0.2.1:443", 1000); e == nil {
			t.Error("bad public key")
		}
	}
	for _, n := range []int64{0, -1, 60001} {
		if _, _, e := awgCandidates(awgTestKey, "192.0.2.1:443", n); e == nil {
			t.Error("bad timeout")
		}
	}
}
