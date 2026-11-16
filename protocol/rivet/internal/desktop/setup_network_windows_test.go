package desktop

import (
	"context"
	"errors"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net/netip"
	"testing"
)

// Cross-compiled here only; requires a permitted Windows test runner for execution.
func TestSetupWindowsNativeConfigureStopsBeforeNextEffect(t *testing.T) {
	r, s := fixtureSetup(t)
	p, err := ParseProfile("awg", dualstackAWG)
	if err != nil {
		t.Fatal(err)
	}
	m := newWindowsMock(t)
	n := mockedWindowsState(t, m)
	n.setup = s
	original := m.ops.settings
	m.ops.settings = func(l winipcfg.LUID, f winipcfg.AddressFamily, mtu int) error {
		err := original(l, f, mtu)
		revokeFixture(r)
		return err
	}
	if err := n.configure(p); !errors.Is(err, context.Canceled) || m.calls != 1 {
		t.Fatalf("post-revoke native effect admitted: %v calls=%d", err, m.calls)
	}
}
func TestSetupWindowsOwnedCleanupIgnoresRevokedSetup(t *testing.T) {
	r, s := fixtureSetup(t)
	m := newWindowsMock(t)
	n := mockedWindowsState(t, m)
	n.setup = s
	if err := n.bypass(netip.MustParseAddr("203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	revokeFixture(r)
	n.close()
	if len(m.routes) != 0 || len(n.routes) != 0 {
		t.Fatal("owned cleanup inherited revoked setup")
	}
}
