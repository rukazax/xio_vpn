package xrayclient

import (
	"context"
	"net"
	"os"
	"sync"
	"time"
)

// One bounded receive pump supplies deadlines missing from Xray's dispatcher.
type packet struct {
	b []byte
	a net.Addr
	e error
}
type packetConn struct {
	net.PacketConn
	s        *Session
	cancel   context.CancelFunc
	once     sync.Once
	done     chan struct{}
	packets  chan packet
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
}

func newPacketConn(pc net.PacketConn, s *Session, cancel context.CancelFunc) *packetConn {
	p := &packetConn{PacketConn: pc, s: s, cancel: cancel, done: make(chan struct{}), packets: make(chan packet, 8), changed: make(chan struct{})}
	go func() {
		for {
			b := make([]byte, 65535)
			n, a, e := pc.ReadFrom(b)
			r := packet{b[:n], a, e}
			select {
			case p.packets <- r:
			case <-p.done:
				return
			}
			if e != nil {
				return
			}
		}
	}()
	return p
}
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, changed := p.deadline, p.changed
		p.mu.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		select {
		case r := <-p.packets:
			if timer != nil {
				timer.Stop()
			}
			n := copy(b, r.b)
			if n > 0 {
				p.s.handshake.Store(time.Now().UnixMilli())
			}
			return n, r.a, r.e
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}
func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return nil
}
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.PacketConn.SetWriteDeadline(t) }
func (p *packetConn) SetDeadline(t time.Time) error {
	_ = p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}
func (p *packetConn) Close() (err error) {
	p.once.Do(func() { close(p.done); p.cancel(); err = p.PacketConn.Close() })
	return
}
