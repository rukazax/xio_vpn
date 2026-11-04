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
	// slot is the pooled 64 KiB read buffer, returned to datagramPool once the
	// payload has been copied out to the caller.
	slot *[]byte
}

// datagramPool recycles the pump's read buffers. Each pooled buffer is owned by
// exactly one in-flight packet: the pump hands it over, ReadFrom copies the
// payload out and returns it. Without the pool every UDP datagram allocated
// 64 KiB, which dominated garbage on UDP-heavy tunnels.
var datagramPool = sync.Pool{New: func() any {
	b := make([]byte, 65535)
	return &b
}}

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
			slot := datagramPool.Get().(*[]byte)
			n, a, e := pc.ReadFrom(*slot)
			r := packet{(*slot)[:n], a, e, slot}
			select {
			case p.packets <- r:
			case <-p.done:
				datagramPool.Put(slot)
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
			if r.slot != nil {
				datagramPool.Put(r.slot)
			}
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
