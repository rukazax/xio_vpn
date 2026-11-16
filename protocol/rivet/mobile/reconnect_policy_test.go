package mobile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"xio.local/rivet/internal/rivet"
)

type fakeRecoveryClock struct {
	mu     sync.Mutex
	at     time.Time
	timers []struct {
		at     time.Time
		cancel context.CancelFunc
		done   <-chan struct{}
	}
}

func newFakeClock() *fakeRecoveryClock      { return &fakeRecoveryClock{at: time.Unix(1000, 0)} }
func (c *fakeRecoveryClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *fakeRecoveryClock) advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	var due []context.CancelFunc
	for _, timer := range c.timers {
		select {
		case <-timer.done:
			continue
		default:
		}
		if !timer.at.After(c.at) {
			due = append(due, timer.cancel)
		}
	}
	c.mu.Unlock()
	for _, cancel := range due {
		cancel()
	}
}
func (c *fakeRecoveryClock) timeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	c.timers = append(c.timers, struct {
		at     time.Time
		cancel context.CancelFunc
		done   <-chan struct{}
	}{c.at.Add(d), cancel, ctx.Done()})
	c.mu.Unlock()
	return ctx, cancel
}
func (c *fakeRecoveryClock) hooks() recoveryHooks {
	h := realRecoveryHooks()
	h.now = c.now
	h.timeout = c.timeout
	h.wait = func(ctx context.Context, d time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.advance(d)
		return ctx.Err()
	}
	return h
}

type fakeNativeSession struct {
	once   sync.Once
	done   chan struct{}
	closes atomic.Int32
}

func fakeSession() *fakeNativeSession                        { return &fakeNativeSession{done: make(chan struct{})} }
func (s *fakeNativeSession) Close()                          { s.once.Do(func() { s.closes.Add(1); close(s.done) }) }
func (s *fakeNativeSession) ReadPacket() ([]byte, error)     { <-s.done; return nil, io.EOF }
func (s *fakeNativeSession) SendPacket([]byte) error         { return nil }
func (s *fakeNativeSession) Counts() (uint64, uint64, int64) { return 1, 2, 123 }

func TestRecoveryExplicitPolicyValidation(t *testing.T) {
	for _, raw := range []string{`{"mode":"manual"}`, `{"mode":"selectedOnly","roundMillis":30001}`, `{"mode":"selectedOnly","unknown":true}`, `null`, `{}`, `{"mode":"automatic"} {}`} {
		if _, err := parseReconnectPolicy(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"", `{"mode":"automatic"}`, `{"mode":"selectedOnly","roundMillis":30000}`} {
		if _, err := parseReconnectPolicy(raw); err != nil {
			t.Fatalf("rejected %q: %v", raw, err)
		}
	}
}

func TestRecoverySelectedFirstAndStrictNeverSwitches(t *testing.T) {
	for _, mode := range []string{"automatic", "selectedOnly"} {
		for _, preferred := range []string{"rivet-h3", "rivet-s1"} {
			c := newFakeClock()
			h := c.hooks()
			var protocols []string
			winner := fakeSession()
			h.dial = func(_, _ context.Context, cfg rivet.ClientConfig, _ Protector, _ time.Duration) (nativeSession, error) {
				protocols = append(protocols, cfg.Protocol)
				if len(protocols) == 1 {
					return nil, io.EOF
				}
				return winner, nil
			}
			s, actual, err := recoveryRound(context.Background(), rivet.ClientConfig{}, preferred, nil, reconnectPolicy{mode, 30000}, h)
			if err != nil || s != winner || len(protocols) != 2 || protocols[0] != preferred {
				t.Fatalf("first selected not honored: %v %v", protocols, err)
			}
			want := preferred
			if mode == "automatic" {
				if preferred == "rivet-h3" {
					want = "rivet-s1"
				} else {
					want = "rivet-h3"
				}
			}
			if protocols[1] != want || actual.Protocol != want {
				t.Fatalf("policy ignored: %s %v", mode, protocols)
			}
			winner.Close()
		}
	}
}

func TestRecoveryOneThirtySecondRoundClosesLateSessions(t *testing.T) {
	c := newFakeClock()
	started := c.now()
	h := c.hooks()
	var sessions []*fakeNativeSession
	h.dial = func(_ context.Context, ctx context.Context, _ rivet.ClientConfig, _ Protector, budget time.Duration) (nativeSession, error) {
		if budget > 10*time.Second {
			t.Fatal("per phase exceeds remaining ceiling")
		}
		s := fakeSession()
		sessions = append(sessions, s)
		c.advance(budget)
		return s, ctx.Err()
	}
	_, _, err := recoveryRound(context.Background(), rivet.ClientConfig{}, "rivet-h3", nil, reconnectPolicy{"automatic", 30000}, h)
	if err == nil || c.now().Sub(started) != 30*time.Second || len(sessions) != 3 {
		t.Fatalf("round reset: %v %v %d", err, c.now().Sub(started), len(sessions))
	}
	for _, s := range sessions {
		if s.closes.Load() != 1 {
			t.Fatal("timeout leaked a returned dial session")
		}
	}
}

func installFakeState(t *testing.T, h recoveryHooks, session nativeSession) *state {
	t.Helper()
	if err := StopWithTimeout(1000); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	activation := make(chan struct{})
	close(activation)
	s := &state{ctx: ctx, cancel: cancel, cfg: rivet.ClientConfig{Protocol: "rivet-h3", IP: "10.79.0.2"}, preferred: "rivet-h3", policy: reconnectPolicy{"automatic", 30000}, hooks: h, session: session, phase: "connected", activateDone: activation, stopDone: make(chan struct{})}
	global.Lock()
	global.current = s
	global.Unlock()
	t.Cleanup(func() {
		if err := StopWithTimeout(1000); err != nil {
			t.Error(err)
		}
	})
	return s
}
func awaitRecovery(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owner did not join")
	}
}

type testPacketSink struct{ closes atomic.Int32 }

func (s *testPacketSink) WritePacket([]byte) bool { return true }
func (s *testPacketSink) Close()                  { s.closes.Add(1) } // Not owned by the packet bridge.

func TestRecoveryAttachPacketFlowStopJoinsAndDoesNotCloseCallerSink(t *testing.T) {
	session := fakeSession()
	s := installFakeState(t, realRecoveryHooks(), session)
	sink := &testPacketSink{}
	if err := AttachPacketFlow(sink); err != nil {
		t.Fatal(err)
	}
	if err := StopWithTimeout(1000); err != nil {
		t.Fatal(err)
	}
	awaitRecovery(t, s.readDone)
	awaitRecovery(t, s.monitorDone)
	if session.closes.Load() != 1 || sink.closes.Load() != 0 {
		t.Fatal("resource ownership violated")
	}
	if PacketInput(make([]byte, 20)) {
		t.Fatal("accepted packet after teardown")
	}
}

func TestRecoveryAttachTunTransfersOnlyAcceptedDescriptor(t *testing.T) {
	session := fakeSession()
	s := installFakeState(t, realRecoveryHooks(), session)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	fd, err := unix.Dup(int(reader.Fd()))
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = AttachTun(int64(fd)); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if err = StopWithTimeout(1000); err != nil {
		t.Fatal(err)
	}
	awaitRecovery(t, s.readDone)
	awaitRecovery(t, s.monitorDone)
	if _, err = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("accepted descriptor not closed")
	}
	reader, writer2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer2.Close()
	defer reader.Close()
	if err = AttachTun(int64(reader.Fd())); err == nil {
		t.Fatal("attached without a session")
	}
	if _, err = unix.FcntlInt(reader.Fd(), unix.F_GETFD, 0); err != nil {
		t.Fatal("rejected descriptor was caller-owned")
	}
}

func TestRecoveryMonitorBoundedExhaustionAndInactivePhases(t *testing.T) {
	c := newFakeClock()
	started := c.now()
	h := c.hooks()
	var phases []string
	var rounds []uint64
	dials := 0
	h.dial = func(_ context.Context, ctx context.Context, _ rivet.ClientConfig, _ Protector, budget time.Duration) (nativeSession, error) {
		dials++
		var status map[string]any
		json.Unmarshal([]byte(Status()), &status)
		if status["active"] == true || status["recoveryPending"] != true {
			t.Fatalf("failed path advertised active: %v", status)
		}
		phases = append(phases, status["phase"].(string))
		rounds = append(rounds, uint64(status["recoveryId"].(float64)))
		c.advance(budget)
		return nil, ctx.Err()
	}
	old := fakeSession()
	s := installFakeState(t, h, old)
	if err := AttachPacketFlow(&testPacketSink{}); err != nil {
		t.Fatal(err)
	}
	old.Close()
	awaitRecovery(t, s.stopDone)
	if dials != 9 || c.now().Sub(started) != 110*time.Second {
		t.Fatalf("unbounded rounds/cooldown: %d %v", dials, c.now().Sub(started))
	}
	if rounds[0] == rounds[3] || rounds[3] == rounds[6] {
		t.Fatal("round identifier did not progress")
	}
	var status map[string]any
	json.Unmarshal([]byte(Status()), &status)
	if status["active"] == true || status["phase"] != "failed" {
		t.Fatalf("exhaustion not failed: %v %v", status, phases)
	}
}

func validRecoveryProfile() string {
	cfg := rivet.ClientConfig{Protocol: "rivet-h3", Endpoint: "192.0.2.1:443", ServerName: "fixture.invalid", IP: "10.79.0.2", ID: strings.Repeat("01", 16)}
	encode := func(n int, b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, n)) }
	cfg.Secret = encode(32, 1)
	cfg.EntryToken = encode(32, 2)
	cfg.Pin = encode(32, 3)
	cfg.GatewayID = encode(16, 4)
	raw, _ := json.Marshal(cfg)
	return string(raw)
}

func TestRecoveryLateStartupDialCannotCommitAndUnjoinedCleanupReservesOwner(t *testing.T) {
	if err := StopWithTimeout(1000); err != nil {
		t.Fatal(err)
	}
	h := realRecoveryHooks()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	late := fakeSession()
	h.dial = func(context.Context, context.Context, rivet.ClientConfig, Protector, time.Duration) (nativeSession, error) {
		close(entered)
		<-release
		return late, nil
	}
	go func() {
		defer close(done)
		if _, err := connectPolicyTimeout(validRecoveryProfile(), nil, 30000, `{"mode":"selectedOnly"}`, h); err == nil {
			t.Error("late cancellation committed")
		}
	}()
	awaitRecovery(t, entered)
	if err := StopWithTimeout(1); !errors.Is(err, errCleanupPending) {
		t.Fatal("unjoined teardown not reported")
	}
	noDial := realRecoveryHooks()
	noDial.dial = func(context.Context, context.Context, rivet.ClientConfig, Protector, time.Duration) (nativeSession, error) {
		t.Error("competing activation reached dial")
		return nil, io.EOF
	}
	if _, err := connectPolicyTimeout(validRecoveryProfile(), nil, 1, `{"mode":"selectedOnly"}`, noDial); !errors.Is(err, errCleanupPending) {
		t.Fatalf("reservation lost: %v", err)
	}
	close(release)
	awaitRecovery(t, done)
	if err := StopWithTimeout(1000); err != nil {
		t.Fatal(err)
	}
	if late.closes.Load() != 1 {
		t.Fatal("late session leaked")
	}
}
