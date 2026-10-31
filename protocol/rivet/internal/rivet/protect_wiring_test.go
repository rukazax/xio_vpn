package rivet

import (
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// familyOnly implements Protector alone, like the Android/mobile bridge.
type familyOnly struct {
	mu    sync.Mutex
	calls int
	allow bool
}

func (p *familyOnly) Protect(int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.allow
}

// endpointAware implements the optional EndpointProtector. Its Protect returns
// false so any fallback would be observed as a failure.
type endpointAware struct {
	mu        sync.Mutex
	addresses []string
	allow     bool
}

func (p *endpointAware) Protect(int64) bool { return false }
func (p *endpointAware) ProtectAddr(_ int64, address string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addresses = append(p.addresses, address)
	return p.allow
}

func (p *endpointAware) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.addresses...)
}

func loopback(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().String()
}

func dialWith(t *testing.T, p Protector, target string) error {
	t.Helper()
	d := net.Dialer{Timeout: 3 * time.Second, Control: socketControl(p)}
	c, err := d.Dial("tcp", target)
	if err != nil {
		return err
	}
	return c.Close()
}

// The optional interface must receive the numeric destination Go passes to
// Control, never a hostname, so endpoint-route selection has real input.
func TestSocketControlPassesNumericTargetToProtectAddr(t *testing.T) {
	target := loopback(t)
	p := &endpointAware{allow: true}
	if err := dialWith(t, p, target); err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	seen := p.seen()
	if len(seen) == 0 {
		t.Fatal("ProtectAddr never called")
	}
	for _, address := range seen {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatalf("ProtectAddr got %q: %v", address, err)
		}
		if net.ParseIP(host) == nil {
			t.Fatalf("ProtectAddr got non-numeric target %q", address)
		}
		if address != target {
			t.Fatalf("ProtectAddr got %q, want %q", address, target)
		}
	}
}

// A platform that only implements Protect keeps working through the fallback.
func TestSocketControlFallsBackToFamilyProtect(t *testing.T) {
	target := loopback(t)
	p := &familyOnly{allow: true}
	if err := dialWith(t, p, target); err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if p.calls == 0 {
		t.Fatal("fallback Protect never called")
	}
}

// Both contracts stay fail-closed: a refusal must abort the dial.
func TestSocketControlRefusalFailsClosed(t *testing.T) {
	target := loopback(t)
	for _, tc := range []struct {
		name string
		p    Protector
	}{{"endpoint", &endpointAware{allow: false}}, {"family", &familyOnly{allow: false}}} {
		err := dialWith(t, tc.p, target)
		if err == nil {
			t.Fatalf("%s: unprotected dial succeeded", tc.name)
		}
		if !strings.Contains(err.Error(), "socket protection failed") {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
	}
}

type rawConn struct{ fd uintptr }

func (r rawConn) Control(fn func(fd uintptr)) error              { fn(r.fd); return nil }
func (r rawConn) Read(fn func(fd uintptr) (done bool)) error  { return nil }
func (r rawConn) Write(fn func(fd uintptr) (done bool)) error { return nil }

var _ syscall.RawConn = rawConn{}

// The QUIC path binds a local address first, so the explicit numeric endpoint
// must be forwarded instead of the unusable "0.0.0.0:0" bind address.
func TestSocketControlForUsesExplicitTarget(t *testing.T) {
	target := loopback(t)
	p := &endpointAware{allow: true}
	control := socketControlFor(p, target)
	if err := control("udp4", "0.0.0.0:0", rawConn{fd: 7}); err != nil {
		t.Fatalf("explicit-target protection failed: %v", err)
	}
	if seen := p.seen(); len(seen) != 1 || seen[0] != target {
		t.Fatalf("ProtectAddr saw %v, want [%s]", seen, target)
	}
}

