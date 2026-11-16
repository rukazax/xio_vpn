package mobile

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

var recoverySerial atomic.Uint64
var errCleanupPending = errors.New("rivet: teardown incomplete")

// Close only resources whose ownership AttachTun/AttachPacketFlow transferred.
// The reservation is retained until the activation, dial and IO owners join.
func beginStop(s *state, phase string) { beginStopWhen(s, phase, nil) }

// Validate an observer's ownership and revoke publication in the SAME critical
// section. Checking an old epoch before an unconditional beginStop has a TOCTOU.
func beginStopWhen(s *state, phase string, current func() bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current != nil && !current() {
		return
	}
	s.stopOnce.Do(func() {
		s.closed = true
		s.phase = phase
		s.cancel()
		session, tun := s.session, s.tun
		s.session = nil
		activation, reader, monitor := s.activateDone, s.readDone, s.monitorDone
		retired := s.retiredDone
		if s.retiredCancel != nil {
			s.retiredCancel()
			s.retiredCancel = nil
		}
		go func() {
			if tun != nil {
				tun.Close()
			}
			if session != nil {
				session.Close()
			}
			if retired != nil {
				<-retired
			}
			if activation != nil {
				<-activation
			}
			if reader != nil {
				<-reader
			}
			if monitor != nil {
				<-monitor
			}
			reclaimAfterTeardown()
			global.Lock()
			if global.current == s {
				global.current = nil
				global.lastPhase = phase
			}
			global.Unlock()
			close(s.stopDone)
		}()
	})
}

// CancelConnect revokes publication immediately without blocking the caller's UI.
// StopWithTimeout is still required to acknowledge joined teardown.
func CancelConnect() {
	global.Lock()
	s := global.current
	global.Unlock()
	if s != nil {
		beginStop(s, "disconnected")
	}
}

// StopWithTimeout bounds waiting, not physical OS cooperation. A timeout leaves
// the old reservation intact; ConnectPolicyTimeout must not compete with it.
func StopWithTimeout(timeoutMillis int64) error {
	if timeoutMillis < 1 || timeoutMillis > 30000 {
		return errCleanupPending
	}
	global.Lock()
	s := global.current
	global.Unlock()
	if s == nil {
		return nil
	}
	beginStop(s, "disconnected")
	timer := time.NewTimer(time.Duration(timeoutMillis) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.stopDone:
		return nil
	case <-timer.C:
		return errCleanupPending
	}
}

func (s *state) startIO() {
	s.mu.Lock()
	if s.closed || s.monitorDone != nil {
		s.mu.Unlock()
		return
	}
	s.readDone, s.monitorDone = make(chan struct{}), make(chan struct{})
	reader, monitor := s.readDone, s.monitorDone
	s.mu.Unlock()
	go func() { defer close(reader); s.readTun() }()
	go func() { defer close(monitor); s.monitor() }()
}

// retireSession revokes active evidence before closing the failed carrier. A
// blocked close/read owner consumes the FIRST recovery lease, not free extra
// time before it, and retains the global reservation until it actually joins.
func (s *state) retireSession(session nativeSession) <-chan struct{} {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if s.retiredSession == session {
		done := s.retiredDone
		s.mu.Unlock()
		return done
	}
	if s.session != session {
		s.mu.Unlock()
		return nil
	}
	s.session = nil
	s.phase = "reconnecting"
	s.recoveryID = recoverySerial.Add(1)
	budget := time.Duration(s.policy.RoundMillis) * time.Millisecond
	s.recoveryDeadline = s.hooks.now().Add(budget)
	s.retiredSession = session
	done := make(chan struct{})
	s.retiredDone = done
	s.retirementPending = true
	retirementID := s.recoveryID
	lease, cancel := s.hooks.timeout(s.ctx, budget)
	s.retiredCancel = cancel
	s.mu.Unlock()
	go func() { defer close(done); session.Close() }()
	go func() {
		<-lease.Done()
		beginStopWhen(s, "failed", func() bool {
			return !s.closed && s.retirementPending && s.retiredDone == done && s.retiredSession == session && s.recoveryID == retirementID
		})
	}()
	return done
}

func (s *state) recoverSession() bool {
	s.mu.Lock()
	firstDeadline := s.recoveryDeadline
	s.mu.Unlock()
	for round := 0; round < maxRecoveryRounds; round++ {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return false
		}
		cfg := s.cfg
		policy := s.policy
		if round == 0 && !firstDeadline.IsZero() {
			policy.RoundMillis = max(int64(0), firstDeadline.Sub(s.hooks.now()).Milliseconds())
		} else {
			s.recoveryID = recoverySerial.Add(1)
		}
		s.phase = "reconnecting"
		s.recoveryDeadline = s.hooks.now().Add(time.Duration(policy.RoundMillis) * time.Millisecond)
		s.mu.Unlock()
		var next nativeSession
		var actual = cfg
		var err error
		if policy.RoundMillis <= 0 {
			err = context.DeadlineExceeded
		} else {
			next, actual, err = recoveryRound(s.ctx, cfg, s.preferred, s.p, policy, s.hooks)
		}
		if err == nil {
			s.mu.Lock()
			if s.closed || s.ctx.Err() != nil {
				s.mu.Unlock()
				next.Close()
				return false
			}
			s.session = next
			s.cfg.Protocol = actual.Protocol
			s.phase = "connected"
			s.recoveryDeadline = time.Time{}
			_, _, s.handshake = next.Counts()
			s.mu.Unlock()
			return true
		}
		if s.ctx.Err() != nil {
			return false
		}
		if round+1 == maxRecoveryRounds {
			break
		}
		cooldown := 5 * time.Second
		if round > 0 {
			cooldown = 15 * time.Second
		}
		s.mu.Lock()
		s.phase = "cooldown"
		s.recoveryDeadline = s.hooks.now().Add(cooldown)
		s.mu.Unlock()
		if s.hooks.wait(s.ctx, cooldown) != nil {
			return false
		}
	}
	beginStop(s, "failed")
	return false
}
