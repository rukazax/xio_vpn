package desktop

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSetupActualLinuxConfigureAndIndependentCleanup(t *testing.T) {
	r, s := fixtureSetup(t)
	journal, err := os.CreateTemp(t.TempDir(), "owned-journal-")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	setupCalls, cleanupCalls := 0, 0
	n := &networkState{setup: s, lock: -1, journal: journal, run: func(string, ...string) ([]byte, error) {
		setupCalls++
		revokeFixture(r)
		return nil, nil
	}}
	if err := n.configure(Profile{MTU: 1280, Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}}); err == nil || setupCalls != 1 || len(n.applied) != 1 {
		t.Fatalf("actual configure admitted late steps: %v %d %d", err, setupCalls, len(n.applied))
	}
	n.run = func(string, ...string) ([]byte, error) { cleanupCalls++; return nil, nil }
	n.close()
	if cleanupCalls != 1 {
		t.Fatalf("canceled setup suppressed owned rollback: %d", cleanupCalls)
	}
}
func TestSetupRuntimePipelineDisconnectFencesActualCommandsAndJoins(t *testing.T) {
	r := &Runtime{}
	entered, release := make(chan struct{}), make(chan struct{})
	var calls, stops atomic.Int32
	journal, err := os.CreateTemp(t.TempDir(), "runtime-journal-")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	r.setupOps = &runtimeSetupOps{
		admin: func() bool { return true },
		prepare: func(s *setupLease) (*networkState, error) {
			return &networkState{setup: s, lock: -1, journal: journal, physical4: true, cache: map[string]string{}, lookup: func(context.Context, string, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}, resolvers: []string{"192.0.2.2:53"}, run: func(string, ...string) ([]byte, error) {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
				}
				return nil, nil
			}}, nil
		},
		start: func(*setupLease, Profile, *networkState) (func(), func() string, error) {
			return func() { stops.Add(1) }, func() string { return `{"active":true}` }, nil
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := r.ConnectWithPolicy("fixture", "awg", domainAWG, 1000, 1000, `{"mode":"selectedOnly"}`)
		done <- err
	}()
	<-entered
	// The real entrypoint revokes before waiting for the setup owner.
	if err := r.DisconnectTimeout(3); err == nil {
		t.Fatal("unjoined in-flight command acknowledged clean")
	}
	if r.mu.TryLock() {
		r.mu.Unlock()
		t.Fatal("disconnect timeout released setup's original reservation")
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stale setup completed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pipeline did not join cleanup")
	}
	// One admitted setup command + its one owned rollback; no later setup steps.
	if calls.Load() != 2 || stops.Load() != 1 {
		t.Fatalf("post-revoke effects or missed cleanup: commands=%d stops=%d", calls.Load(), stops.Load())
	}
	if r.current != nil {
		t.Fatal("revoked pipeline installed current session")
	}
}
func TestSetupRuntimeWinnerSurvivesDeferredSetupCancellation(t *testing.T) {
	r := &Runtime{}
	var stops atomic.Int32
	journal, err := os.CreateTemp(t.TempDir(), "winner-journal-")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	var network *networkState
	r.setupOps = &runtimeSetupOps{
		admin: func() bool { return true },
		prepare: func(s *setupLease) (*networkState, error) {
			network = &networkState{setup: s, lock: -1, journal: journal, physical4: true, cache: map[string]string{}, run: func(string, ...string) ([]byte, error) { return nil, nil }}
			return network, nil
		},
		start: func(*setupLease, Profile, *networkState) (func(), func() string, error) {
			return func() { stops.Add(1) }, func() string { return `{"active":true}` }, nil
		},
	}
	numeric := strings.Replace(domainAWG, "fr-host.fr", "192.0.2.1", 1)
	if _, err := r.ConnectWithPolicy("fixture", "awg", numeric, 1000, 1000, `{"mode":"selectedOnly"}`); err != nil {
		t.Fatal(err)
	}
	if stops.Load() != 0 || r.current == nil || r.Status()["active"] != true {
		t.Fatal("deferred setup cancel killed winning transport")
	}
	if got := network.Resolve("192.0.2.1"); got != "192.0.2.1" {
		t.Fatalf("winning network inherited canceled setup: %q", got)
	}
	if err := r.DisconnectTimeout(1000); err != nil {
		t.Fatal(err)
	}
	if stops.Load() != 1 {
		t.Fatal("winning owner not stopped exactly once by explicit DOWN")
	}
}
func TestSetupActualLinuxResolveReceivesCanceledRound(t *testing.T) {
	r, s := fixtureSetup(t)
	entered := make(chan struct{})
	n := &networkState{setup: s, physical4: true, cache: map[string]string{}, resolvers: []string{"192.0.2.1:53"}, lookup: func(ctx context.Context, _, _, _ string) ([]netip.Addr, error) {
		close(entered)
		<-ctx.Done()
		return []netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil
	}}
	done := make(chan error, 1)
	go func() {
		p := Profile{Endpoints: []string{"fixture.invalid:443"}}
		done <- prepareEndpointsBudget(&p, n, s.check, s.ctx)
	}()
	<-entered
	revokeFixture(r)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("actual networkState.Resolve reset setup cancellation")
	}
	if len(n.cache) != 0 {
		t.Fatal("late physical DNS result entered winner cache")
	}
}
