package tailclient

import (
	"errors"
	"github.com/tailscale/wireguard-go/tun"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// The engine starts before Android knows its overlay addresses. Until Attach,
// reads/writes wait; no traffic can fall through to the device's default route.
type Device struct {
	mu                sync.Mutex
	file              *os.File
	stream            io.ReadWriteCloser
	ready             chan struct{}
	done              chan struct{}
	events            chan tun.Event
	once              sync.Once
	rx, tx, handshake atomic.Int64
}

func NewDevice() *Device {
	return &Device{ready: make(chan struct{}), done: make(chan struct{}), events: make(chan tun.Event, 4)}
}
func (d *Device) wait() (io.ReadWriteCloser, error) {
	select {
	case <-d.done:
		return nil, os.ErrClosed
	case <-d.ready:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stream, nil
}
func (d *Device) File() *os.File           { d.mu.Lock(); defer d.mu.Unlock(); return d.file }
func (d *Device) Name() (string, error)    { return "xio-tailnet", nil }
func (d *Device) MTU() (int, error)        { return 1280, nil }
func (d *Device) BatchSize() int           { return 1 }
func (d *Device) Events() <-chan tun.Event { return d.events }
func (d *Device) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	f, e := d.wait()
	if e != nil {
		return 0, e
	}
	if len(packets) == 0 || len(slab) < 1280+128 {
		return 0, errors.New("tailscale: packet buffer too small")
	}
	n, e := f.Read(slab[64 : len(slab)-64])
	if n > 0 {
		packets[0] = tun.ReadPacket{Offset: 64, Size: n}
		d.tx.Add(int64(n))
		return 1, e
	}
	return 0, e
}
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	f, e := d.wait()
	if e != nil {
		return 0, e
	}
	for i, b := range bufs {
		if offset > len(b) {
			return i, errors.New("tailscale: invalid offset")
		}
		n, e := f.Write(b[offset:])
		if e != nil {
			return i, e
		}
		d.rx.Add(int64(n))

	}
	return len(bufs), nil
}
func (d *Device) Close() error {
	d.once.Do(func() {
		close(d.done)
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.stream != nil {
			d.stream.Close()
			d.file = nil
			d.handshake.Store(0)
		}
		close(d.events)
	})
	return nil
}
