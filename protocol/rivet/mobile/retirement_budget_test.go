package mobile

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"xio.local/rivet/internal/rivet"
)

type retiringSession struct {
	*fakeNativeSession
	once      sync.Once
	closeWork func()
	readError bool
	sendError bool
}

func (s *retiringSession) Close() {
	s.once.Do(func() {
		if s.closeWork != nil {
			s.closeWork()
		}
		s.fakeNativeSession.Close()
	})
}
func (s *retiringSession) ReadPacket() ([]byte, error) {
	if s.readError {
		return nil, io.EOF
	}
	return s.fakeNativeSession.ReadPacket()
}
func (s *retiringSession) SendPacket([]byte) error {
	if s.sendError {
		return io.EOF
	}
	return nil
}

func TestRecoveryUnjoinedRetiredCarrierConsumesLeaseAndReservesOwner(t *testing.T) {
	for _, source := range []string{"read", "send"} {
		t.Run(source, func(t *testing.T) {
			clock := newFakeClock()
			h := clock.hooks()
			h.dial = func(context.Context, context.Context, rivet.ClientConfig, Protector, time.Duration) (nativeSession, error) {
				t.Error("unjoined retirement admitted a competing carrier")
				return nil, io.EOF
			}
			entered, release := make(chan struct{}), make(chan struct{})
			old := &retiringSession{fakeNativeSession: fakeSession(), readError: source == "read", sendError: source == "send", closeWork: func() { close(entered); <-release }}
			s := installFakeState(t, h, old)
			if err := AttachPacketFlow(&testPacketSink{}); err != nil {
				t.Fatal(err)
			}
			if source == "send" {
				packet := fixtureInbound(t)
				copy(packet[12:16], []byte{10, 79, 0, 2})
				copy(packet[16:20], []byte{8, 8, 8, 8})
				if !PacketInput(packet) {
					t.Fatal("fixture packet rejected")
				}
			}
			awaitRecovery(t, entered)
			var status map[string]any
			json.Unmarshal([]byte(Status()), &status)
			if status["active"] == true || status["secure"] == true || status["recoveryPending"] != true {
				t.Fatalf("retiring carrier still live: %v", status)
			}
			clock.advance(30 * time.Second)
			awaitRecovery(t, s.ctx.Done())
			assertTerminalInactive(t)
			if err := StopWithTimeout(1); err != errCleanupPending {
				t.Fatalf("unjoined old close lost reservation: %v", err)
			}
			close(release)
			awaitRecovery(t, s.stopDone)
		})
	}
}

func TestRecoveryRetirementTimeIsInsideFirstThirtySecondRound(t *testing.T) {
	clock := newFakeClock()
	started := clock.now()
	h := clock.hooks()
	dials := 0
	h.dial = func(_ context.Context, ctx context.Context, _ rivet.ClientConfig, _ Protector, budget time.Duration) (nativeSession, error) {
		dials++
		clock.advance(budget)
		return nil, ctx.Err()
	}
	old := &retiringSession{fakeNativeSession: fakeSession(), readError: true, closeWork: func() { clock.advance(20 * time.Second) }}
	s := installFakeState(t, h, old)
	if err := AttachPacketFlow(&testPacketSink{}); err != nil {
		t.Fatal(err)
	}
	awaitRecovery(t, s.stopDone)
	if elapsed := clock.now().Sub(started); elapsed != 110*time.Second || dials != 7 {
		t.Fatalf("cleanup received free time outside rounds: elapsed=%v dials=%d", elapsed, dials)
	}
	assertTerminalInactive(t)
}
