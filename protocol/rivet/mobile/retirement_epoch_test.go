package mobile

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xio.local/rivet/internal/rivet"
)

// Adapted from H's confirmed a01a052 regression after reading the original.
// Delay only observer scheduling before its real stdlib Done receive; context
// cancellation itself occurs normally. No network/device or fake clock needed.
type scheduledRetirementLease struct {
	context.Context
	entered, resume chan struct{}
	once            sync.Once
}

func (c *scheduledRetirementLease) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	<-c.resume
	return c.Context.Done()
}

type secondRetiringSession struct {
	*fakeNativeSession
	readEntered, readFail, closeEntered, closeRelease chan struct{}
	readOnce, closeOnce                               sync.Once
}

func (s *secondRetiringSession) ReadPacket() ([]byte, error) {
	s.readOnce.Do(func() { close(s.readEntered) })
	<-s.readFail
	return nil, io.EOF
}
func (s *secondRetiringSession) Close() {
	s.closeOnce.Do(func() { close(s.closeEntered); <-s.closeRelease; s.fakeNativeSession.Close() })
}

func TestRecoveryOldRetirementObserverCannotFailNewerLease(t *testing.T) {
	h := realRecoveryHooks()
	entered, resumeObserver := make(chan struct{}), make(chan struct{})
	var resumeOnce, failOnce, releaseOnce sync.Once
	resume := func() { resumeOnce.Do(func() { close(resumeObserver) }) }
	winner := &secondRetiringSession{fakeNativeSession: fakeSession(), readEntered: make(chan struct{}), readFail: make(chan struct{}), closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}
	fail := func() { failOnce.Do(func() { close(winner.readFail) }) }
	release := func() { releaseOnce.Do(func() { close(winner.closeRelease) }) }
	defer func() { resume(); fail(); release() }()
	var leases atomic.Int32
	h.timeout = func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithTimeout(parent, d)
		if leases.Add(1) == 1 {
			return &scheduledRetirementLease{Context: ctx, entered: entered, resume: resumeObserver}, cancel
		}
		return ctx, cancel
	}
	h.dial = func(context.Context, context.Context, rivet.ClientConfig, Protector, time.Duration) (nativeSession, error) {
		return winner, nil
	}
	old := fakeSession()
	s := installFakeState(t, h, old)
	if err := AttachPacketFlow(&testPacketSink{}); err != nil {
		t.Fatal(err)
	}
	old.Close()
	awaitRecovery(t, entered)
	awaitRecovery(t, winner.readEntered)
	fail()
	awaitRecovery(t, winner.closeEntered)
	s.mu.Lock()
	newID := s.recoveryID
	s.mu.Unlock()
	resume()
	select {
	case <-s.ctx.Done():
		t.Errorf("old canceled retirement observer revoked newer lease id=%d", newID)
	case <-time.After(200 * time.Millisecond):
	}
	release()
	if err := StopWithTimeout(1000); err != nil {
		t.Error(err)
	}
}
