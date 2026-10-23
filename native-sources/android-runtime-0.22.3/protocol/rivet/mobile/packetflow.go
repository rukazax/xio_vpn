package mobile

import (
	"io"
	"net"
	"sync"
)

// PacketSink is the supported packet-flow bridge for iOS NetworkExtension.
// It does not inspect private NEPacketTunnelFlow fields or extract hidden FDs.
type PacketSink interface{ WritePacket([]byte) bool }
type packetPipe struct {
	sink    PacketSink
	packets chan []byte
	done    chan struct{}
	once    sync.Once
}

func newPacketPipe(sink PacketSink) *packetPipe {
	return &packetPipe{sink: sink, packets: make(chan []byte, 64), done: make(chan struct{})}
}
func (p *packetPipe) Read(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, io.EOF
	case v := <-p.packets:
		if len(v) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, v), nil
	}
}
func (p *packetPipe) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	if !p.sink.WritePacket(b) {
		return 0, io.ErrClosedPipe
	}
	return len(b), nil
}
func (p *packetPipe) Close() error { p.once.Do(func() { close(p.done) }); return nil }
func (p *packetPipe) input(b []byte) bool {
	if len(b) < 20 || len(b) > 65535 {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
	}
	select {
	case p.packets <- append([]byte(nil), b...):
		return true
	default:
		return false
	}
}
func AttachPacketFlow(sink PacketSink) error {
	if sink == nil {
		return io.ErrClosedPipe
	}
	global.Lock()
	s := global.current
	global.Unlock()
	if s == nil {
		return net.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.session == nil || s.tun != nil {
		return net.ErrClosed
	}
	s.pipe = newPacketPipe(sink)
	s.tun = s.pipe
	go s.readTun()
	go s.monitor()
	return nil
}
func PacketInput(packet []byte) bool {
	global.Lock()
	s := global.current
	global.Unlock()
	if s == nil {
		return false
	}
	s.mu.Lock()
	p := s.pipe
	s.mu.Unlock()
	return p != nil && p.input(packet)
}
