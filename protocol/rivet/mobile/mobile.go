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

	"xio.local/rivet/internal/physical"
	"xio.local/rivet/internal/rivet"
)

type Protector interface {
	Protect(int64) bool
	Resolve(string) string
}
type state struct {
	mu        sync.Mutex
	cfg       rivet.ClientConfig
	p         Protector
	ctx       context.Context
	cancel    context.CancelFunc
	session   *rivet.Session
	tun       io.ReadWriteCloser
	pipe      *packetPipe
	phase     string
	rx, tx    uint64
	handshake int64
	closed    bool
}

var global struct {
	sync.Mutex
	current *state
}

func Connect(raw string, p Protector) (string, error) { return ConnectTimeout(raw, p, 10000) }
func ConnectTimeout(raw string, p Protector, timeoutMillis int64) (string, error) {
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
	Stop()
	ctx, cancel := context.WithCancel(context.Background())
	s := &state{cfg: cfg, p: p, ctx: ctx, cancel: cancel, phase: "connecting"}
	global.Lock()
	global.current = s
	global.Unlock()
	session, e := dialPhysical(ctx, cfg, p, time.Duration(timeoutMillis)*time.Millisecond)
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
	s.mu.Unlock()
	go s.readTun()
	go s.monitor()
	return nil
}
func (s *state) readTun() {
	buf := make([]byte, 65536)
	for {
		n, e := s.tun.Read(buf)
		if e != nil {
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
			session.Close()
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
		s.mu.Unlock()
		if session == nil {
			return
		}
		for {
			packet, e := session.ReadPacket()
			if e != nil {
				break
			}
			if rivet.CheckIP(packet, "", false) != nil || (rivet.Destination(packet) != s.cfg.IP && (s.cfg.IP6 == "" || rivet.Destination(packet) != s.cfg.IP6)) {
				break
			}
			if _, e = s.tun.Write(packet); e != nil {
				session.Close()
				return
			}
			s.mu.Lock()
			s.rx += uint64(len(packet))
			s.mu.Unlock()
		}
		session.Close()
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.session = nil
		s.phase = "reconnecting"
		cfg := s.cfg
		s.mu.Unlock()
		for attempt := 0; ; attempt++ {
			delay := time.Duration(min(1<<min(attempt, 3), 8)) * time.Second
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(delay):
			}
			if attempt%2 == 0 {
				if cfg.Protocol == "rivet-h3" {
					cfg.Protocol = "rivet-s1"
				} else {
					cfg.Protocol = "rivet-h3"
				}
			}
			next, e := dialPhysical(s.ctx, cfg, s.p, 10*time.Second)
			if e != nil {
				continue
			}

			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				next.Close()
				return
			}
			s.session = next
			s.cfg.Protocol = cfg.Protocol
			s.phase = "connected"
			_, _, s.handshake = next.Counts()
			s.mu.Unlock()
			break
		}
	}
}
func Stop() {
	global.Lock()
	s := global.current
	global.current = nil
	global.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.phase = "disconnected"
	s.cancel()
	session := s.session
	tun := s.tun
	s.mu.Unlock()
	if session != nil {
		session.Close()
	}
	if tun != nil {
		tun.Close()
	}
}
func Status() string {
	global.Lock()
	s := global.current
	global.Unlock()
	if s == nil {
		return `{"active":false,"phase":"disconnected"}`
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"active": !s.closed && s.tun != nil, "secure": s.session != nil && !s.closed, "phase": s.phase, "protocol": s.cfg.Protocol, "ip": s.cfg.IP, "rx": s.rx, "tx": s.tx, "handshake": s.handshake})
	return string(b)
}

// Android's DNS callback can outlive a request; a bounded, buffered result
// releases the caller on timeout/cancellation without replacing its life context.
func resolveTimed(ctx context.Context, c rivet.ClientConfig, p Protector, timeout time.Duration) (rivet.ClientConfig, error) {
	if host, _, e := net.SplitHostPort(c.Endpoint); e == nil && net.ParseIP(host) != nil {
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
	host, port, e := net.SplitHostPort(c.Endpoint)
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
func dialPhysical(ctx context.Context, c rivet.ClientConfig, p Protector, timeout time.Duration) (*rivet.Session, error) {
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	host, port, err := net.SplitHostPort(c.Endpoint)
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
		session, e := rivet.DialWithTimeout(ctx, candidate, p, budget)
		if e == nil {
			return session, nil
		}
		last = e
	}
	return nil, last
}
