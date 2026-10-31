// Package apple exposes only RIVET packet transport to NetworkExtension.
// No undocumented TUN FD extraction, Xray registry or mesh runtime is linked.
package apple

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"
	"xio.local/rivet/internal/physical"
	"xio.local/rivet/internal/rivet"
)

type Protector interface {
	Protect(int64) bool
	Resolve(string) string
}
type PacketSink interface{ WritePacket([]byte) bool }
type tunnel struct {
	mu        sync.Mutex
	cfg       rivet.ClientConfig
	p         Protector
	sink      PacketSink
	ctx       context.Context
	cancel    context.CancelFunc
	session   *rivet.Session
	rx, tx    uint64
	handshake int64
	phase     string
	packets   chan []byte
}

var global struct {
	sync.Mutex
	t *tunnel
}

func resolve(ctx context.Context, c rivet.ClientConfig, p Protector) (rivet.ClientConfig, error) {
	h, port, e := physical.ParseEndpoint(c.Endpoint)
	if e != nil {
		return c, e
	}
	if net.ParseIP(h) != nil {
		return c, nil
	}
	result := make(chan string, 1)
	go func() { result <- p.Resolve(h) }()
	select {
	case ip := <-result:
		addresses, e := physical.Addresses(ip)
		if e != nil || len(addresses) != 1 {
			return c, errors.New("physical endpoint resolution failed")
		}
		c.Endpoint = net.JoinHostPort(addresses[0], port)
		return c, nil
	case <-ctx.Done():
		return c, ctx.Err()
	}
}
func Start(raw string, p Protector, sink PacketSink, timeoutMillis int64) (string, error) {
	if len(raw) > 16384 || p == nil || sink == nil || timeoutMillis < 1000 || timeoutMillis > 60000 {
		return "", rivet.ErrProtocol
	}
	var c rivet.ClientConfig
	if json.Unmarshal([]byte(raw), &c) != nil || c.Validate() != nil {
		return "", rivet.ErrProtocol
	}
	Stop()
	started := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	t := &tunnel{cfg: c, p: p, sink: sink, ctx: ctx, cancel: cancel, phase: "connecting", packets: make(chan []byte, 64)}
	global.Lock()
	global.t = t
	global.Unlock()
	succeeded := false
	defer func() {
		if !succeeded {
			cancel()
			global.Lock()
			if global.t == t {
				global.t = nil
			}
			global.Unlock()
		}
	}()

	attempt, done := context.WithTimeout(ctx, time.Duration(timeoutMillis)*time.Millisecond)
	resolved, e := resolve(attempt, c, p)
	done()
	if e != nil {
		cancel()
		return "", e
	}
	session, e := dial(ctx, resolved, p, time.Duration(timeoutMillis)*time.Millisecond-time.Since(started))
	if e != nil {
		cancel()
		return "", errors.New("secure RIVET startup failed")
	}
	t.mu.Lock()
	if ctx.Err() != nil {
		t.mu.Unlock()
		session.Close()
		return "", ctx.Err()
	}
	t.session = session
	t.phase = "connected"
	_, _, t.handshake = session.Counts()
	t.mu.Unlock()
	go t.send()
	go t.receive()
	succeeded = true
	return Status(), nil
}
func dial(ctx context.Context, c rivet.ClientConfig, p Protector, budget time.Duration) (*rivet.Session, error) {
	return rivet.DialWithTimeout(ctx, c, p, budget)
}

// IPv6 is enabled only by the validated, bound profile; old IPv4-only profiles
// continue to reject it rather than permitting traffic outside the tunnel.
func (t *tunnel) outboundAllowed(packet []byte) bool {
	return len(packet) > 0 && (packet[0]>>4 != 6 || t.cfg.IP6 != "") && rivet.CheckIP(packet, t.cfg.IP, true) == nil
}
func (t *tunnel) inboundAllowed(packet []byte) bool {
	if rivet.CheckIP(packet, "", false) != nil {
		return false
	}
	destination := rivet.Destination(packet)
	return destination == t.cfg.IP || (t.cfg.IP6 != "" && destination == t.cfg.IP6)
}
func Input(packet []byte) bool {
	global.Lock()
	t := global.t
	global.Unlock()
	if t == nil || !t.outboundAllowed(packet) {
		return false
	}
	select {
	case <-t.ctx.Done():
		return false
	default:
	}
	select {
	case t.packets <- append([]byte(nil), packet...):
		return true
	default:
		return false
	}
}
func (t *tunnel) send() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case b := <-t.packets:
			t.mu.Lock()
			s := t.session
			t.mu.Unlock()
			if s != nil {
				if s.SendPacket(b) != nil {
					s.Close()
				} else {
					t.mu.Lock()
					t.tx += uint64(len(b))
					t.mu.Unlock()
				}
			}
		}
	}
}
func (t *tunnel) receive() {
	for {
		t.mu.Lock()
		s := t.session
		t.mu.Unlock()
		if s == nil {
			return
		}
		for {
			b, e := s.ReadPacket()
			if e != nil {
				break
			}
			if !t.inboundAllowed(b) {
				break
			}
			if !t.sink.WritePacket(b) {
				break
			}
			t.mu.Lock()
			t.rx += uint64(len(b))
			t.mu.Unlock()
		}
		s.Close()
		t.mu.Lock()
		t.session = nil
		t.phase = "reconnecting"
		cfg := t.cfg
		t.mu.Unlock()
		for i := 0; ; i++ {
			select {
			case <-t.ctx.Done():
				return
			case <-time.After(time.Duration(1<<min(i, 3)) * time.Second):
			}
			if i%2 == 0 {
				if cfg.Protocol == "rivet-h3" {
					cfg.Protocol = "rivet-s1"
				} else {
					cfg.Protocol = "rivet-h3"
				}
			}
			attempt, cancel := context.WithTimeout(t.ctx, 8*time.Second)
			resolved, e := resolve(attempt, cfg, t.p)
			cancel()
			if e != nil {
				continue
			}
			next, e := dial(t.ctx, resolved, t.p, 8*time.Second)
			if e != nil {
				continue
			}
			t.mu.Lock()
			if t.ctx.Err() != nil {
				t.mu.Unlock()
				next.Close()
				return
			}
			t.session = next
			t.cfg.Protocol = cfg.Protocol
			t.phase = "connected"
			_, _, t.handshake = next.Counts()
			t.mu.Unlock()
			break
		}
	}
}
func Stop() {
	global.Lock()
	t := global.t
	global.t = nil
	global.Unlock()
	if t == nil {
		return
	}
	t.cancel()
	t.mu.Lock()
	s := t.session
	t.session = nil
	t.mu.Unlock()
	if s != nil {
		s.Close()
	}
}
func Status() string {
	global.Lock()
	t := global.t
	global.Unlock()
	if t == nil {
		return `{"active":false}`
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"active": t.ctx.Err() == nil, "phase": t.phase, "protocol": t.cfg.Protocol, "rx": t.rx, "tx": t.tx, "handshake": t.handshake, "ipv6Payload": t.ctx.Err() == nil && t.cfg.IP6 != ""})
	return string(b)
}
