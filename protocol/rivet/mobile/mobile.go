// Package mobile is the narrow Android binding. No keys are returned by Status.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"xio.local/rivet/internal/physical"
	"xio.local/rivet/internal/rivet"
)

type Protector interface {
	Protect(int64) bool
	Resolve(string) string
}
type state struct {
	mu                                            sync.Mutex
	cfg                                           rivet.ClientConfig
	p                                             Protector
	ctx                                           context.Context
	cancel                                        context.CancelFunc
	session                                       nativeSession
	policy                                        reconnectPolicy
	preferred                                     string
	hooks                                         recoveryHooks
	activateDone, readDone, monitorDone, stopDone chan struct{}
	stopOnce                                      sync.Once
	recoveryID                                    uint64
	recoveryDeadline                              time.Time
	retiredSession                                nativeSession
	retiredDone                                   chan struct{}
	retiredCancel                                 context.CancelFunc
	retirementPending                             bool
	tun                                           io.ReadWriteCloser
	pipe                                          *packetPipe
	phase                                         string
	rx, tx                                        uint64
	handshake                                     int64
	closed                                        bool
}

var global struct {
	sync.Mutex
	current   *state
	lastPhase string
}

func Connect(raw string, p Protector) (string, error) { return ConnectTimeout(raw, p, 10000) }
func ConnectTimeout(raw string, p Protector, timeoutMillis int64) (string, error) {
	return ConnectPolicyTimeout(raw, p, timeoutMillis, "")
}

// ConnectPolicyTimeout carries explicit runtime intent separately from profiles.
// Existing Connect/ConnectTimeout callers retain automatic recovery by default.
func ConnectPolicyTimeout(raw string, p Protector, timeoutMillis int64, policyJSON string) (string, error) {
	return connectPolicyTimeout(raw, p, timeoutMillis, policyJSON, realRecoveryHooks())
}
func connectPolicyTimeout(raw string, p Protector, timeoutMillis int64, policyJSON string, hooks recoveryHooks) (result string, resultErr error) {
	started := hooks.now()
	policy, err := parseReconnectPolicy(policyJSON)
	if err != nil {
		return "", err
	}
	if timeoutMillis < 1 || timeoutMillis > 60000 {
		return "", rivet.ErrProtocol
	}
	if len(raw) > 16384 {
		return "", rivet.ErrProtocol
	}
	var cfg rivet.ClientConfig
	if e := json.Unmarshal([]byte(raw), &cfg); e != nil {
		return "", rivet.ErrProtocol
	}
	if e := cfg.Validate(); e != nil {
		return "", e
	}
	timeout := min(time.Duration(timeoutMillis)*time.Millisecond, maxRound)
	if err := StopWithTimeout(max(int64(1), (timeout - hooks.now().Sub(started)).Milliseconds())); err != nil {
		return "", err
	}
	left := timeout - hooks.now().Sub(started)
	if left <= 0 {
		return "", context.DeadlineExceeded
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &state{cfg: cfg, p: p, ctx: ctx, cancel: cancel, phase: "connecting", policy: policy, preferred: cfg.Protocol, hooks: hooks, activateDone: make(chan struct{}), stopDone: make(chan struct{})}
	global.Lock()
	if global.current != nil {
		global.Unlock()
		cancel()
		return "", errCleanupPending
	}
	global.current = s
	global.Unlock()
	defer func() {
		close(s.activateDone)
		if resultErr != nil {
			beginStop(s, "failed")
		}
	}()
	dialCtx, dialCancel := hooks.timeout(ctx, left)
	defer dialCancel()
	session, e := s.hooks.dial(ctx, dialCtx, cfg, p, left)
	if e == nil {
		e = dialCtx.Err()
	}
	if e == nil && hooks.now().Sub(started) >= timeout {
		e = context.DeadlineExceeded
	}
	if e != nil && session != nil {
		session.Close()
	}
	if e != nil {
		cancel()
		s.mu.Lock()
		s.closed = true
		s.phase = "failed"
		s.mu.Unlock()
		return "", errors.New("rivet: secure connection failed")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		session.Close()
		return "", errors.New("rivet: cancelled")
	}
	s.session = session
	s.phase = "connected"
	_, _, s.handshake = session.Counts()
	s.mu.Unlock()
	return Status(), nil
}
func AttachTun(fd int64) error {
	global.Lock()
	s := global.current
	global.Unlock()
	if s == nil || fd < 0 {
		return rivet.ErrProtocol
	}
	s.mu.Lock()
	if s.closed || s.session == nil || s.tun != nil {
		s.mu.Unlock()
		return rivet.ErrProtocol
	}
	s.tun = os.NewFile(uintptr(fd), "xio-rivet-tun")
	if s.tun == nil {
		s.mu.Unlock()
		return rivet.ErrProtocol
	}
	_ = unix.SetNonblock(int(fd), true)
	s.mu.Unlock()
	s.startIO()
	return nil
}
func (s *state) readTun() {
	buf := make([]byte, 65536)
	for {
		n, e := s.tun.Read(buf)
		if e != nil {
			beginStop(s, "failed")
			return
		}
		if n == 0 || buf[0]>>4 == 6 && s.cfg.IP6 == "" || rivet.CheckIP(buf[:n], s.cfg.IP, true) != nil {
			continue
		}
		s.mu.Lock()
		session := s.session
		s.mu.Unlock()
		if session == nil {
			continue
		} // Keep TUN active and discard while reconnecting.
		if e = session.SendPacket(buf[:n]); e != nil {
			s.retireSession(session)
		} else {
			s.mu.Lock()
			s.tx += uint64(n)
			s.mu.Unlock()
		}
	}
}
func (s *state) monitor() {
	for {
		s.mu.Lock()
		session := s.session
		if session == nil && s.retirementPending && !s.closed {
			session = s.retiredSession
		}
		s.mu.Unlock()
		if session == nil {
			return
		}
		for {
			packet, e := session.ReadPacket()
			if e != nil {
				break
			}
			destination := rivet.Destination(packet)
			if rivet.CheckIP(packet, "", false) != nil || (destination != s.cfg.IP && (s.cfg.IP6 == "" || destination != s.cfg.IP6)) {
				break
			}
			if n, e := s.tun.Write(packet); e != nil || n != len(packet) {
				beginStop(s, "failed")
				return
			}
			s.mu.Lock()
			s.rx += uint64(len(packet))
			s.mu.Unlock()
		}
		retired := s.retireSession(session)
		if retired == nil {
			return
		}
		select {
		case <-retired:
		case <-s.ctx.Done():
			return
		}
		s.mu.Lock()
		s.retirementPending = false
		if s.retiredCancel != nil {
			s.retiredCancel()
			s.retiredCancel = nil
		}
		s.mu.Unlock()
		if !s.recoverSession() {
			return
		}
	}
}
func Stop() { _ = StopWithTimeout(5000) }
func Status() string {
	global.Lock()
	s, last := global.current, global.lastPhase
	global.Unlock()
	if s == nil {
		if last == "" {
			last = "disconnected"
		}
		b, _ := json.Marshal(map[string]any{"active": false, "secure": false, "phase": last, "recoveryPending": false, "cleanupPending": false})
		return string(b)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	phase := s.phase
	recovering := !s.closed && (phase == "reconnecting" || phase == "cooldown")
	left := int64(0)
	if recovering {
		left = max(int64(0), s.recoveryDeadline.Sub(s.hooks.now()).Milliseconds())
	}
	cleanup := s.closed
	if cleanup {
		select {
		case <-s.stopDone:
			cleanup = false
		default:
		}
	}
	if recovering && left == 0 {
		phase = "failed"
		recovering = false
		cleanup = true
	}
	secure := !s.closed && s.session != nil && s.phase == "connected"
	b, _ := json.Marshal(map[string]any{"active": secure && s.tun != nil, "interfaceUp": !s.closed && s.tun != nil, "secure": secure, "phase": phase, "protocol": s.cfg.Protocol, "ip": s.cfg.IP, "rx": s.rx, "tx": s.tx, "handshake": s.handshake, "policyMode": s.policy.Mode, "recoveryPending": recovering, "recoveryId": s.recoveryID, "recoveryRemainingMillis": left, "cleanupPending": cleanup})
	return string(b)
}

// Android's DNS callback can outlive a request; a bounded, buffered result
// releases the caller on timeout/cancellation without replacing its life context.
func resolveTimed(ctx context.Context, c rivet.ClientConfig, p Protector, timeout time.Duration) (rivet.ClientConfig, error) {
	host, _, e := physical.ParseEndpoint(c.Endpoint)
	if e != nil {
		return c, e
	}
	if net.ParseIP(host) != nil {
		return c, nil
	}
	wait, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		c rivet.ClientConfig
		e error
	}
	done := make(chan result, 1)
	go func() { cfg, e := resolve(c, p); done <- result{cfg, e} }()
	select {
	case <-wait.Done():
		return c, wait.Err()
	case r := <-done:
		return r.c, r.e
	}
}

func resolve(c rivet.ClientConfig, p Protector) (rivet.ClientConfig, error) {
	host, port, e := physical.ParseEndpoint(c.Endpoint)
	if e != nil {
		return c, e
	}
	if net.ParseIP(host) != nil {
		return c, nil
	}
	if p == nil {
		return c, errors.New("rivet: physical-network DNS unavailable")
	}
	addresses, err := physical.Addresses(p.Resolve(host))
	if err != nil {
		return c, errors.New("rivet: physical-network DNS failed")
	}
	c.Endpoint = net.JoinHostPort(addresses[0], port)
	return c, nil
}

func Validate(raw string) error {
	if len(raw) > 16384 {
		return rivet.ErrProtocol
	}
	var c rivet.ClientConfig
	if json.Unmarshal([]byte(raw), &c) != nil {
		return rivet.ErrProtocol
	}
	return c.Validate()
}

// Try alternate A/AAAA endpoints within one overall deadline. Attempts are
// sequential because two successful handshakes for one identity replace peers.
func dialPhysical(lifetime, establishment context.Context, c rivet.ClientConfig, p Protector, timeout time.Duration) (*rivet.Session, error) {
	attempt, cancel := context.WithTimeout(establishment, timeout)
	defer cancel()
	host, port, err := physical.ParseEndpoint(c.Endpoint)
	if err != nil {
		return nil, err
	}
	var resolver func(string) string
	if p != nil {
		resolver = p.Resolve
	}
	addresses, err := physical.Resolve(attempt, host, resolver)
	if err != nil {
		return nil, err
	}
	var last error
	deadline, _ := attempt.Deadline()
	for i, address := range addresses {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		budget := remaining
		if i+1 < len(addresses) {
			budget = min(3*time.Second, remaining/time.Duration(len(addresses)-i))
		}
		candidate := c
		candidate.Endpoint = net.JoinHostPort(address, port)
		session, e := rivet.DialWithLifetime(lifetime, attempt, candidate, p, budget)
		if e == nil {
			return session, nil
		}
		last = e
	}
	return nil, last
}
