package xrayclient

import (
	"context"
	"net"
	"syscall"
	"testing"

	"xio.local/rivet/internal/physical"
)

type fakeEndpoint struct {
	addresses []string
	allow     bool
	fallbacks int
}

func (p *fakeEndpoint) Protect(int64) bool {
	p.fallbacks++
	return true
}
func (p *fakeEndpoint) ProtectAddr(_ int64, address string) bool {
	p.addresses = append(p.addresses, address)
	return p.allow
}
func (p *fakeEndpoint) Resolve(string) string { return "" }

type fakeFamily struct {
	allow bool
	calls int
}

func (p *fakeFamily) Protect(int64) bool {
	p.calls++
	return p.allow
}
func (p *fakeFamily) Resolve(string) string { return "" }

// The Xray dialer must hand the numeric destination to ProtectAddr so the
// endpoint's own route is used, and must never silently accept a socket that
// the platform refused.
func TestProtectedDialerUsesEndpointProtection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		protect Protector
		want    bool
		check   func(*testing.T, Protector)
	}{
		{"endpoint-allows", &fakeEndpoint{allow: true}, true, func(t *testing.T, p Protector) {
			fp := p.(*fakeEndpoint)
			if len(fp.addresses) != 1 || fp.addresses[0] != "127.0.0.1:443" {
				t.Fatalf("ProtectAddr saw %v", fp.addresses)
			}
			if fp.fallbacks != 0 {
				t.Fatal("family fallback used despite endpoint support")
			}
		}},
		{"endpoint-refuses", &fakeEndpoint{allow: false}, false, nil},
		{"family-allows", &fakeFamily{allow: true}, true, func(t *testing.T, p Protector) {
			if p.(*fakeFamily).calls != 1 {
				t.Fatal("family fallback not called")
			}
		}},
		{"family-refuses", &fakeFamily{allow: false}, false, nil},
	} {
		got := protectSocket(tc.protect, 5, "127.0.0.1:443")
		if got != tc.want {
			t.Fatalf("%s: protectSocket=%v want %v", tc.name, got, tc.want)
		}
		if tc.check != nil {
			tc.check(t, tc.protect)
		}
	}
}

// physical.Dial hands the numeric candidate to Control, so the Xray dialer's
// ProtectAddr receives the address it is actually about to connect to.
func TestPhysicalDialPassesNumericCandidate(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, e := l.Accept(); e == nil {
			c.Close()
		}
	}()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	p := &fakeEndpoint{allow: true}
	control := func(_, address string, c syscall.RawConn) error {
		ok := false
		if e := c.Control(func(fd uintptr) { ok = protectSocket(p, int64(fd), address) }); e != nil {
			return e
		}
		if !ok {
			return ErrProtect
		}
		return nil
	}
	conn, err := physical.Dial(context.Background(), "tcp4", []string{"127.0.0.1"}, port, control)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.Close()
	seen = p.addresses
	if len(seen) != 1 {
		t.Fatalf("ProtectAddr saw %v", seen)
	}
	host, _, err := net.SplitHostPort(seen[0])
	if err != nil || net.ParseIP(host) == nil {
		t.Fatalf("non-numeric target %q", seen[0])
	}
	if seen[0] != net.JoinHostPort("127.0.0.1", port) {
		t.Fatalf("target %q does not match the dialed candidate", seen[0])
	}
}
