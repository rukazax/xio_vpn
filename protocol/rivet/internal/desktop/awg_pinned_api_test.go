package desktop

import (
	"net/netip"
	"testing"
	"time"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdev "github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// API-CONSTRAINT FIXTURES ONLY. These are not a shipped fallback controller,
// an authenticated AWG exchange, or an OS / no-leak acceptance test.
// See work/dualstack-20261029/desktop-awg-fallback-report.ru.md.

// Compile against the ACTUAL pinned public API; never construct a device, open
// a bind, create a TUN, initiate a handshake, or change host state in these tests.
var _ interface {
	IpcGet() (string, error)
	IpcSet(string) error
	LookupPeer(awgdev.NoisePublicKey) *awgdev.Peer
} = (*awgdev.Device)(nil)
var _ interface{ SendHandshakeInitiation(bool) error } = (*awgdev.Peer)(nil)

func TestAWGPinnedPublicAPISignatures(t *testing.T) {
	// The declarations above are the check. Runtime calls deliberately absent.
}

func TestAWGPinnedIPCCannotAttributeFallbackHandshake(t *testing.T) {
	for _, pair := range [][2]string{
		{"203.0.113.42:51820", "[2001:db8::42]:51820"},
		{"[2001:db8::42]:51820", "203.0.113.42:51820"},
	} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) {
			a := netip.MustParseAddrPort(pair[0])
			b := netip.MustParseAddrPort(pair[1])
			started := time.Now()
			// Model the EXACT ordering of separate fields in pinned uapi.go:198-209:
			// 1. Endpoint B installed; IpcGet samples it and releases endpoint lock.
			endpoint := b
			observedEndpoint := endpoint
			// 2. Already queued authenticated A response completes: receive.go:453-473
			//    updates the endpoint, derives keys, then records lastHandshakeNano.
			endpoint = a
			actualAuthenticatedSource := a
			handshake := started.Add(time.Millisecond)
			// 3. IpcGet now samples that timestamp independently of the endpoint field.
			observedHandshake := handshake
			naiveConnected := observedEndpoint == b && observedHandshake.After(started)
			if !naiveConnected || endpoint != a || actualAuthenticatedSource == b {
				t.Fatal("fixture no longer demonstrates the torn-IPC counterexample")
			}
			// Proposed additive immutable completion event carries ACTUAL source; the
			// same sequence must be rejected for attempt B, regardless of IPC contents.
			authenticatedEventMatches := actualAuthenticatedSource == b && handshake.After(started)
			if authenticatedEventMatches {
				t.Fatal("late A completion accepted for B")
			}
		})
	}
}

type awgConstraintBindWrapper struct{ awgconn.Bind }

func TestAWGPinnedBindWrapperLosesLinuxStickyListenerIdentity(t *testing.T) {
	// Pure constructors, NO Open / network IO. sticky_linux.go:31 uses a concrete
	// *conn.StdNetBind assertion, not a capability interface. An apparently
	// transparent receive-filter wrapper silently bypasses that route listener.
	native := awgconn.NewStdNetBind()
	if _, ok := native.(*awgconn.StdNetBind); !ok {
		t.Fatal("review pinned implementation: constructor changed")
	}
	var wrapped awgconn.Bind = &awgConstraintBindWrapper{Bind: native}
	if _, ok := wrapped.(*awgconn.StdNetBind); ok {
		t.Fatal("fixture does not model the pinned concrete type gate")
	}
}
