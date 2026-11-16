package desktop

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureSetup(t *testing.T) (*Runtime, *setupLease) {
	t.Helper()
	r := &Runtime{}
	s := newSetupLease(&r.pendingMu, time.Now().Add(time.Second), time.Now, func() bool { return r.generation.Load() == 0 })
	r.pendingSetup = s
	t.Cleanup(s.cancel)
	return r, s
}
func revokeFixture(r *Runtime) {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	r.generation.Add(1)
	r.pendingSetup.cancel()
}
func fixturePlan() []networkCommand {
	return linuxNetworkPlan(Profile{MTU: 1280, Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}, DNS: []netip.Addr{netip.MustParseAddr("9.9.9.9")}})
}
func TestSetupPlanStopsAfterRevoke(t *testing.T) {
	r, s := fixtureSetup(t)
	calls := 0
	var applied []networkCommand
	err := applyNetworkPlan(fixturePlan(), func(string, ...string) ([]byte, error) { calls++; revokeFixture(r); return nil, nil }, &applied, s)
	if !errors.Is(err, context.Canceled) || calls != 1 || len(applied) != 1 {
		t.Fatalf("new post-revoke effect admitted: err=%v calls=%d ownership=%d", err, calls, len(applied))
	}
	// Rollback must still run, against recorded ownership, without setup admission.
	undone := 0
	undoNetworkPlan(applied, func(string, ...string) ([]byte, error) { undone++; return nil, nil })
	if undone != 1 {
		t.Fatalf("canceled setup suppressed cleanup: %d", undone)
	}
}
func TestSetupPlanDeadlineDuringSteps(t *testing.T) {
	var gate sync.Mutex
	now := time.Unix(1000, 0)
	s := newSetupLease(&gate, now.Add(time.Second), func() time.Time { return now }, func() bool { return true })
	defer s.cancel()
	calls := 0
	var applied []networkCommand
	err := applyNetworkPlan(fixturePlan(), func(string, ...string) ([]byte, error) { calls++; now = now.Add(2 * time.Second); return nil, nil }, &applied, s)
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("deadline reset per command: %v %d", err, calls)
	}
}
func TestSetupBlockingCallReceivesRemainingCapAndCancellation(t *testing.T) {
	r, s := fixtureSetup(t)
	ctx, done, err := s.admit(30 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	d, ok := ctx.Deadline()
	if !ok || d.After(s.deadline.Add(time.Millisecond)) {
		t.Fatalf("fresh timeout exceeds setup: %v", d)
	}
	revokeFixture(r)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("in-flight context did not receive cancellation")
	}
	if _, done, err := s.admit(time.Second); err == nil {
		done()
		t.Fatal("new effect admitted after revoke")
	}
}

type canceledEndpointResolver struct {
	entered chan struct{}
	routes  atomic.Int32
}

func (n *canceledEndpointResolver) Resolve(string) string {
	panic("production setup must use context-aware DNS")
}
func (n *canceledEndpointResolver) ResolveContext(ctx context.Context, _ string) string {
	close(n.entered)
	<-ctx.Done()
	return "192.0.2.1"
}
func (n *canceledEndpointResolver) bypass(netip.Addr) error { n.routes.Add(1); return nil }
func TestSetupCanceledEndpointDNSReturnsWithoutRelease(t *testing.T) {
	r, s := fixtureSetup(t)
	n := &canceledEndpointResolver{entered: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		p := Profile{Endpoints: []string{"fixture.invalid:443"}}
		result <- prepareEndpointsBudget(&p, n, s.check, s.ctx)
	}()
	<-n.entered
	revokeFixture(r)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || n.routes.Load() != 0 {
			t.Fatalf("late DNS published routes: %v %d", err, n.routes.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("DNS did not receive setup cancel")
	}
}
func TestSetupPhysicalDNSCannotAdmitAnotherQueryAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	value := resolvePhysicalContext(ctx, "fixture.invalid", []string{"192.0.2.1:53", "192.0.2.2:53"}, func(q context.Context, _, _, _ string) ([]netip.Addr, error) {
		calls++
		cancel()
		return []netip.Addr{netip.MustParseAddr("192.0.2.3")}, nil
	})
	if value != "" || calls != 1 {
		t.Fatalf("canceled DNS result/query accepted: %q %d", value, calls)
	}
}
func TestSetupCommitDetachesWinningNetworkLifetime(t *testing.T) {
	r, s := fixtureSetup(t)
	published := false
	if err := s.commit(func() { published = true; r.pendingSetup = nil }); err != nil {
		t.Fatal(err)
	}
	s.cancel() // Deferred setup cleanup must not poison future winner operations.
	r.pendingMu.Lock()
	r.generation.Add(1)
	r.pendingMu.Unlock()
	ctx, done, err := s.admit(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if !published || ctx.Err() != nil {
		t.Fatal("winning lifetime inherited canceled setup")
	}
}
func TestSetupRevokedCannotCommitStaleCallback(t *testing.T) {
	r, s := fixtureSetup(t)
	revokeFixture(r)
	called := false
	if err := s.commit(func() { called = true }); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("obsolete publication: %v %v", err, called)
	}
}
func TestSetupInflightOwnerRetainsReservationUntilJoinedCleanup(t *testing.T) {
	r, s := fixtureSetup(t)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	r.mu.Lock()
	go func() { defer r.mu.Unlock(); done <- s.effect(func() error { close(entered); <-release; return nil }) }()
	<-entered
	revokeFixture(r)
	if r.mu.TryLock() {
		r.mu.Unlock()
		t.Fatal("unjoined effect lost its original owner")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !r.lockUntil(time.Now().Add(time.Second)) {
		t.Fatal("joined effect never released its owner")
	}
	r.mu.Unlock()
}
func TestSetupSharingStepsStopAndCleanupUsesIndependentContext(t *testing.T) {
	r, s := fixtureSetup(t)
	setupCalls, cleanupCalls := 0, 0
	err := runSharingSteps(s, "prefix:", []string{"one", "two", "three"}, func(created bool) string {
		if !created {
			t.Fatal("lost first-step ownership")
		}
		return "rollback"
	}, func(ctx context.Context, script string) ([]byte, error) {
		if script == "rollback" {
			cleanupCalls++
			if ctx.Err() != nil {
				t.Fatal("cleanup inherited setup cancellation")
			}
			return nil, nil
		}
		setupCalls++
		revokeFixture(r)
		return []byte("CREATED"), nil
	})
	if !errors.Is(err, context.Canceled) || setupCalls != 1 || cleanupCalls != 1 {
		t.Fatalf("sharing admitted post-DOWN effects/skipped cleanup: %v %d %d", err, setupCalls, cleanupCalls)
	}
}
func TestSetupSharingDeadlineDoesNotResetBetweenSteps(t *testing.T) {
	var gate sync.Mutex
	now := time.Unix(1000, 0)
	s := newSetupLease(&gate, now.Add(time.Second), func() time.Time { return now }, func() bool { return true })
	defer s.cancel()
	calls := 0
	err := runSharingSteps(s, "", []string{"one", "two"}, func(bool) string { return "cleanup" }, func(ctx context.Context, script string) ([]byte, error) {
		if script != "cleanup" {
			calls++
			now = now.Add(2 * time.Second)
		}
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("sharing reset deadline: %v %d", err, calls)
	}
}
func TestSetupFailedCleanupKeepsIncompleteReservation(t *testing.T) {
	r, s := fixtureSetup(t)
	err := runSharingSteps(s, "", []string{"one", "two"}, func(bool) string { return "cleanup" }, func(ctx context.Context, script string) ([]byte, error) {
		if script == "cleanup" {
			return nil, errors.New("fixture cleanup failed")
		}
		revokeFixture(r)
		return nil, nil
	})
	if !errors.Is(err, errSetupCleanupIncomplete) {
		t.Fatalf("failed cleanup fabricated success: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopUntilLocked(time.Now().Add(time.Second), func() { r.cleanupFailure.Store(true) }) || !r.cleanupPending.Load() {
		t.Fatal("joined-but-failed cleanup released incomplete reservation")
	}
}
func TestSetupAWGHandshakeUsesSetupCancellation(t *testing.T) {
	r, s := fixtureSetup(t)
	entered, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- r.withAWGContext(30000, func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }, s)
	}()
	<-entered
	revokeFixture(r)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("AWG reset/shared cancel lost")
	}
}
