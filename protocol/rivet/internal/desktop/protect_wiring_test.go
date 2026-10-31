package desktop

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"xio.local/rivet/internal/physical"
)

// The DNS lookup must hand the resolver's numeric server address to the
// endpoint-aware protector, and a refusal must abort the lookup (fail closed).
func TestProtectedLookupPassesNumericServer(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	lookup := protectedLookup(func(_ int64, address string) bool {
		mu.Lock()
		seen = append(seen, address)
		mu.Unlock()
		return false
	})
	_, err := lookup(context.Background(), "ip", "example.test", "192.0.2.53:53")
	if err == nil {
		t.Fatal("lookup succeeded although protection was refused")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("protector never called")
	}
	host, _, e := net.SplitHostPort(seen[0])
	if e != nil || net.ParseIP(host) == nil {
		t.Fatalf("protector got non-numeric server %q", seen[0])
	}
}

// A platform without endpoint routing keeps working through familyProtect.
func TestFamilyProtectAdapter(t *testing.T) {
	calls := 0
	protect := familyProtect(func(fd int64) bool {
		calls++
		return fd > 0
	})
	if !protect(9, "192.0.2.53:53") || calls != 1 {
		t.Fatal("adapter did not delegate")
	}
	if protect(-1, "") {
		t.Fatal("adapter ignored refusal")
	}
}

// resolvePhysical's contract is unchanged apart from the protector shape; the
// numeric fast path must not touch DNS at all.
func TestResolvePhysicalNumericShortcut(t *testing.T) {
	called := false
	got := resolvePhysicalWith("2001:db8::42", nil, func(context.Context, string, string, string) ([]netip.Addr, error) {
		called = true
		return nil, nil
	})
	if got != "2001:db8::42" || called {
		t.Fatalf("numeric shortcut broken: %q called=%v", got, called)
	}
	_ = physical.Addresses
}
