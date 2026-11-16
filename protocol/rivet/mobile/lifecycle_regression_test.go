package mobile

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
	"time"

	"xio.local/rivet/internal/rivet"
)

// Adapted from independent H's four failing no-network repros. Unlike the old
// fake, this models a retained carrier's dependence on its lifetime context.
type lifetimeSession struct {
	*fakeNativeSession
	life context.Context
}

func (s *lifetimeSession) SendPacket(p []byte) error { return s.life.Err() }

func TestRecoveryStartupWinnerSurvivesLeaseReturnAndStopCancelsLifetime(t *testing.T) {
	if err := StopWithTimeout(1000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := StopWithTimeout(1000); err != nil {
			t.Error(err)
		}
	})
	h := realRecoveryHooks()
	var winner *lifetimeSession
	var lease context.Context
	h.dial = func(life, setup context.Context, _ rivet.ClientConfig, _ Protector, _ time.Duration) (nativeSession, error) {
		lease = setup
		winner = &lifetimeSession{fakeSession(), life}
		return winner, nil
	}
	if _, err := connectPolicyTimeout(validRecoveryProfile(), nil, 30000, `{"mode":"selectedOnly"}`, h); err != nil {
		t.Fatal(err)
	}
	if lease.Err() == nil {
		t.Fatal("establishment lease was not revoked on return")
	}
	if err := winner.SendPacket(nil); err != nil {
		t.Fatalf("winner died with lease: %v", err)
	}
	if err := StopWithTimeout(1000); err != nil {
		t.Fatal(err)
	}
	if winner.life.Err() == nil || winner.closes.Load() != 1 {
		t.Fatal("Stop failed to cancel lifetime and close winner")
	}
}

func TestRecoveryRecoveredWinnerSurvivesRoundAndStopJoins(t *testing.T) {
	h := realRecoveryHooks()
	var winner *lifetimeSession
	var lease context.Context
	h.dial = func(life, setup context.Context, _ rivet.ClientConfig, _ Protector, _ time.Duration) (nativeSession, error) {
		lease = setup
		winner = &lifetimeSession{fakeSession(), life}
		return winner, nil
	}
	s := installFakeState(t, h, fakeSession())
	if !s.recoverSession() {
		t.Fatal("recovery failed")
	}
	if lease.Err() == nil {
		t.Fatal("establishment lease was not revoked")
	}
	if err := winner.SendPacket(nil); err != nil {
		t.Fatalf("recovery winner died on return: %v", err)
	}
	if err := AttachPacketFlow(&testPacketSink{}); err != nil {
		t.Fatal(err)
	}
	if err := StopWithTimeout(1000); err != nil {
		t.Fatal(err)
	}
	awaitRecovery(t, s.monitorDone)
	awaitRecovery(t, s.readDone)
	if winner.life.Err() == nil || winner.closes.Load() != 1 {
		t.Fatal("Stop did not revoke retained lifetime")
	}
}

type onePacketSession struct {
	*fakeNativeSession
	packet []byte
}

func (s *onePacketSession) ReadPacket() ([]byte, error) {
	if s.packet != nil {
		p := s.packet
		s.packet = nil
		return p, nil
	}
	return s.fakeNativeSession.ReadPacket()
}

type rejectingSink struct{}

func (rejectingSink) WritePacket([]byte) bool { return false }
func fixtureInbound(t *testing.T) []byte {
	t.Helper()
	p := make([]byte, 20)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], 20)
	copy(p[12:16], []byte{8, 8, 8, 8})
	copy(p[16:20], []byte{10, 79, 0, 2})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	if err := rivet.CheckIP(p, "", false); err != nil {
		t.Fatal(err)
	}
	return p
}
func assertTerminalInactive(t *testing.T) {
	t.Helper()
	var status map[string]any
	if err := json.Unmarshal([]byte(Status()), &status); err != nil {
		t.Fatal(err)
	}
	if status["active"] == true || status["secure"] == true || status["phase"] != "failed" {
		t.Fatalf("terminal owner still advertises live session: %v", status)
	}
}
func TestRecoveryTerminalPacketSinkFailureRevokesAndJoins(t *testing.T) {
	s := installFakeState(t, realRecoveryHooks(), &onePacketSession{fakeSession(), fixtureInbound(t)})
	if err := AttachPacketFlow(rejectingSink{}); err != nil {
		t.Fatal(err)
	}
	awaitRecovery(t, s.monitorDone)
	assertTerminalInactive(t)
	awaitRecovery(t, s.stopDone)
	assertTerminalInactive(t)
}

type eofTun struct{}

func (eofTun) Read([]byte) (int, error)    { return 0, io.EOF }
func (eofTun) Write(p []byte) (int, error) { return len(p), nil }
func (eofTun) Close() error                { return nil }
func TestRecoveryTerminalTunEOFRevokesAndJoins(t *testing.T) {
	s := installFakeState(t, realRecoveryHooks(), fakeSession())
	s.mu.Lock()
	s.tun = eofTun{}
	s.mu.Unlock()
	s.startIO()
	awaitRecovery(t, s.readDone)
	assertTerminalInactive(t)
	awaitRecovery(t, s.stopDone)
	assertTerminalInactive(t)
}

type blockedSink struct{ entered, release chan struct{} }

func (s *blockedSink) WritePacket([]byte) bool { close(s.entered); <-s.release; return false }
func TestRecoveryBlockedCallerSinkRetainsCleanupReservation(t *testing.T) {
	s := installFakeState(t, realRecoveryHooks(), &onePacketSession{fakeSession(), fixtureInbound(t)})
	sink := &blockedSink{make(chan struct{}), make(chan struct{})}
	if err := AttachPacketFlow(sink); err != nil {
		t.Fatal(err)
	}
	awaitRecovery(t, sink.entered)
	if err := StopWithTimeout(1); err != errCleanupPending {
		t.Fatalf("blocked caller callback lost reservation: %v", err)
	}
	var status map[string]any
	json.Unmarshal([]byte(Status()), &status)
	if status["active"] == true || status["cleanupPending"] != true {
		t.Fatalf("bad pending status: %v", status)
	}
	close(sink.release)
	awaitRecovery(t, s.stopDone)
}
