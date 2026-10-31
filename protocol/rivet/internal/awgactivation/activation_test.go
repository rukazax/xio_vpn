package awgactivation

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

func TestValidateRejectsUnsafeCandidates(t *testing.T) {
	key := strings.Repeat("11", 32)
	if _, list, err := Validate(key, "192.0.2.1:51820,[2001:db8::1]:51820,192.0.2.1:51820", 5000); err != nil || len(list) != 2 || !list[1].Addr().Is6() {
		t.Fatalf("numeric order/dedup: %v %v", list, err)
	}
	bad := []string{
		"", "vpn.invalid:443", "[::]:443", "[ff02::1]:443", "[fe80::1%eth0]:443",
		"192.0.2.1:0", "192.0.2.1:65536", "[::ffff:0.0.0.0]:1", "[::ffff:169.254.1.1]:1", "255.255.255.255:1", "192.0.2.1:443\nprivate_key=bad",
		strings.Repeat("192.0.2.1:443,", 17),
	}
	for _, raw := range bad {
		if _, _, err := Validate(key, raw, 1000); !errors.Is(err, ErrInvalid) {
			t.Errorf("unsafe endpoint accepted: %q", raw)
		}
	}
	for _, k := range []string{"", strings.Repeat("0", 64), key + "\n", strings.Repeat("g", 64)} {
		if _, _, err := Validate(k, "192.0.2.1:443", 1000); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad key accepted: %q", k)
		}
	}
	for _, n := range []int64{0, -1, MaxTimeoutMillis + 1} {
		if _, _, err := Validate(key, "192.0.2.1:443", n); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad timeout accepted: %d", n)
		}
	}
}

func TestRunRequiresOwnedDeviceAndDeadline(t *testing.T) {
	key := device.NoisePublicKey{1}
	list := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820")}
	if err := Run(context.Background(), nil, key, list); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil device: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, nil, key, list); err == nil {
		t.Fatal("cancelled context accepted")
	}
	if err := Run(context.Background(), nil, key, list); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing deadline: %v", err)
	}
}

func TestRunAuthenticatesActualSourceFallback(t *testing.T) {
	a, _, key := testPair(t)
	// Candidate 1 is rejected by the fixture bind and never reaches the peer.
	// Candidate 2 is the exact numeric source of authenticated responses.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	started := time.Now()
	if err := Run(ctx, a, key, []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:9"),
		netip.MustParseAddrPort("127.0.0.1:3"),
	}); err != nil {
		t.Fatalf("actual-source fallback: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 12*time.Second {
		t.Fatalf("fallback missed the deadline: %s", elapsed)
	}
	config, err := a.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "endpoint=127.0.0.1:3\n") {
		t.Fatal("winning endpoint not installed")
	}
}

func TestRunRejectsCompletionFromOtherSource(t *testing.T) {
	a, _, key := testPair(t)
	// Endpoint 1 is reachable and produces authenticated responses, but they
	// arrive from 127.0.0.1:3. A single candidate 1 must fail.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := Run(ctx, a, key, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong-source completion accepted: %v", err)
	}
}

func TestRunCancellationClosesAttempt(t *testing.T) {
	a, _, key := testPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, a, key, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")})
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation not reported: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func testPair(t *testing.T) (*device.Device, *device.Device, device.NoisePublicKey) {
	return testPairWithBind(t, nil)
}
func testPairWithBind(t *testing.T, wrap func(conn.Bind) conn.Bind) (*device.Device, *device.Device, device.NoisePublicKey) {
	t.Helper()
	binds := bindtest.NewChannelBinds()
	if wrap != nil {
		binds[0] = wrap(binds[0])
	}
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	a := device.NewDevice(tuntest.NewChannelTUN().TUN(), binds[0], logger)
	b := device.NewDevice(tuntest.NewChannelTUN().TUN(), binds[1], logger)
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	ka, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicA := hex.EncodeToString(ka.PublicKey().Bytes())
	publicB := hex.EncodeToString(kb.PublicKey().Bytes())
	if err := a.IpcSet("private_key=" + hex.EncodeToString(ka.Bytes()) + "\nrekey_timeout=1\npublic_key=" + publicB + "\nallowed_ip=0.0.0.0/0\nendpoint=127.0.0.1:1\n"); err != nil {
		t.Fatal(err)
	}
	if err := b.IpcSet("private_key=" + hex.EncodeToString(kb.Bytes()) + "\npublic_key=" + publicA + "\nallowed_ip=0.0.0.0/0\nendpoint=127.0.0.1:2\n"); err != nil {
		t.Fatal(err)
	}
	if err := a.Up(); err != nil {
		t.Fatal(err)
	}
	if err := b.Up(); err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(publicB)
	if err != nil {
		t.Fatal(err)
	}
	var key device.NoisePublicKey
	copy(key[:], decoded)
	return a, b, key
}

// Test-only memory bind wrapper. Shipping consumers keep StdNetBind unchanged.
type blockedSendBind struct {
	conn.Bind
	entered, closed, sent          chan struct{}
	enterOnce, closeOnce, sentOnce sync.Once
	opened                         atomic.Bool
}

func (b *blockedSendBind) Send(_ [][]byte, _ conn.Endpoint) error {
	b.enterOnce.Do(func() { close(b.entered) })
	<-b.closed
	b.sentOnce.Do(func() { close(b.sent) })
	return net.ErrClosed
}
func (b *blockedSendBind) Close() error {
	if b.opened.Load() {
		b.closeOnce.Do(func() { close(b.closed) })
	}
	return b.Bind.Close()
}
func TestRunCancellationJoinsBlockedNativeSend(t *testing.T) {
	var bind *blockedSendBind
	a, _, key := testPairWithBind(t, func(base conn.Bind) conn.Bind {
		bind = &blockedSendBind{Bind: base, entered: make(chan struct{}), closed: make(chan struct{}), sent: make(chan struct{})}
		return bind
	})
	t.Cleanup(func() { _ = bind.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, a, key, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3")}) }()
	select {
	case <-bind.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("send not entered")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked send survived cancellation")
	}
	select {
	case <-bind.sent:
	default:
		t.Fatal("Run returned with send still blocked")
	}
	select {
	case <-a.Wait():
	default:
		t.Fatal("failed attempt device not closed before return")
	}
}
func TestRunDirectValidationRejectsUnsafeAddresses(t *testing.T) {
	a, _, key := testPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, raw := range []string{"[::ffff:0.0.0.0]:1", "[::ffff:169.254.1.1]:1", "255.255.255.255:1", "[fe80::1]:1", "[ff00::1]:1"} {
		if err := Run(ctx, a, key, []netip.AddrPort{netip.MustParseAddrPort(raw)}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("direct Run accepted %s: %v", raw, err)
		}
	}
	if err := Run(context.Background(), a, key, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3")}); !errors.Is(err, ErrInvalid) {
		t.Fatal("unbounded context accepted")
	}
	if a.LookupPeer(key) == nil {
		t.Fatal("validation mutated device")
	}
}

func (b *blockedSendBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err == nil {
		b.opened.Store(true)
	}
	return fns, actual, err
}
