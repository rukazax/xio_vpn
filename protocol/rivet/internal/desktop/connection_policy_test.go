package desktop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests expire/revoke admission BEFORE any admin/device/route operation.
func TestDesktopPolicyRejectsMalformedIntentBeforeNetworking(t *testing.T) {
	for _, policy := range []string{`{"mode":"manual"}`, `{"mode":"selectedOnly","roundMillis":30001}`, `{"mode":"selectedOnly","extra":true}`, `null`} {
		r := &Runtime{}
		if _, err := r.ConnectWithPolicy("fixture", "rivet-h3", "", 15000, 30000, policy); err == nil || errors.Is(err, ErrProfile) {
			t.Fatalf("explicit invalid policy reached profile/device path: %s %v", policy, err)
		}
	}
}

func TestDesktopPolicyQueueTimeConsumesSameRound(t *testing.T) {
	for _, mode := range []string{"automatic", "selectedOnly"} {
		t.Run(mode, func(t *testing.T) {
			var now atomic.Int64
			var once sync.Once
			entered, done := make(chan struct{}), make(chan error, 1)
			r := &Runtime{now: func() time.Time {
				at := now.Load()
				once.Do(func() { close(entered) })
				return time.Unix(1000, 0).Add(time.Duration(at))
			}}
			r.mu.Lock()
			go func() {
				_, err := r.ConnectWithPolicy("fixture", "rivet-h3", "", 15000, 30000, `{"mode":"`+mode+`"}`)
				done <- err
			}()
			<-entered
			now.Store(int64(31 * time.Second))
			r.mu.Unlock()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("queue renewed budget: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("expired admission did not finish")
			}
		})
	}
}

func TestDesktopPolicyRevokedQueuedActivationCannotStart(t *testing.T) {
	var once sync.Once
	entered, done := make(chan struct{}), make(chan error, 1)
	r := &Runtime{now: func() time.Time { once.Do(func() { close(entered) }); return time.Unix(1000, 0) }}
	r.mu.Lock()
	go func() {
		_, err := r.ConnectWithPolicy("fixture", "rivet-h3", "", 15000, 30000, `{"mode":"selectedOnly"}`)
		done <- err
	}()
	<-entered
	// Same admission epoch invalidation as DisconnectTimeout, without touching OS.
	r.generation.Add(1)
	r.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("revoked admission started: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("revoked admission did not finish")
	}
}

func TestDesktopPolicyLateDNSCannotAddRoutes(t *testing.T) {
	p := Profile{Endpoints: []string{"fixture.invalid:443"}}
	n := &fakeEndpointNetwork{result: "192.0.2.1"}
	checks := 0
	err := prepareEndpointsBudget(&p, n, func() error {
		checks++
		if checks > 1 {
			return context.Canceled
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || len(n.bypassed) != 0 {
		t.Fatalf("late DNS added routes: %v %v", err, n.bypassed)
	}
}

func TestDesktopPolicyAdmissionWaitItselfIsBounded(t *testing.T) {
	r := &Runtime{}
	r.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := r.ConnectWithPolicy("fixture", "rivet-h3", "", 2, 2, `{"mode":"selectedOnly"}`)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expired admission reached OS path: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("admission waited indefinitely for old owner")
	}
	r.mu.Unlock()
}

func TestDesktopPolicyTimedOutCleanupRetainsLockUntilJoin(t *testing.T) {
	r := &Runtime{}
	entered, release := make(chan struct{}), make(chan struct{})
	r.mu.Lock()
	if r.stopUntilLocked(time.Now().Add(2*time.Millisecond), func() { close(entered); <-release }) {
		t.Fatal("unjoined teardown accepted")
	}
	<-entered
	if !r.cleanupPending.Load() {
		t.Fatal("cleanup reservation disappeared")
	}
	if r.mu.TryLock() {
		r.mu.Unlock()
		t.Fatal("competing owner admitted before cleanup joined")
	}
	status := r.Status()
	if status["active"] != false || status["cleanupPending"] != true {
		t.Fatalf("pending teardown published active: %v", status)
	}
	close(release)
	if !r.lockUntil(time.Now().Add(time.Second)) {
		t.Fatal("joined cleanup did not release reservation")
	}
	defer r.mu.Unlock()
	if r.cleanupPending.Load() {
		t.Fatal("joined teardown still pending")
	}
}

func TestDesktopPolicyReportsActualRecoveredTransport(t *testing.T) {
	r := &Runtime{current: &session{id: "rvh1", protocol: "rivet-h3", status: func() string { return `{"active":true,"protocol":"rivet-s1","phase":"connected"}` }}}
	status := r.Status()
	if status["protocol"] != "rivet-s1" {
		t.Fatalf("successful automatic fallback masked: %v", status)
	}
}

func TestDesktopPolicyUnjoinedDisconnectReportsIncomplete(t *testing.T) {
	var now atomic.Int64
	var once sync.Once
	entered, done := make(chan struct{}), make(chan error, 1)
	r := &Runtime{now: func() time.Time {
		at := now.Load()
		once.Do(func() { close(entered) })
		return time.Unix(1000, 0).Add(time.Duration(at))
	}}
	r.mu.Lock()
	go func() { done <- r.DisconnectTimeout(30000) }()
	<-entered
	now.Store(int64(31 * time.Second))
	r.mu.Unlock()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("expired cleanup acknowledged: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup owner did not return")
	}
}
