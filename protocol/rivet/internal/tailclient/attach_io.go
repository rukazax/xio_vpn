package tailclient

import (
	"errors"
	"github.com/tailscale/wireguard-go/tun"
	"io"
	"os"
)

func (d *Device) attachIO(stream io.ReadWriteCloser, file *os.File) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if stream == nil || d.stream != nil {
		return errors.New("tailscale: invalid TUN")
	}
	select {
	case <-d.done:
		return os.ErrClosed
	default:
	}
	d.stream = stream
	d.file = file
	close(d.ready)
	d.events <- tun.EventUp
	return nil
}
func (s *Session) AttachIO(stream io.ReadWriteCloser) error { return s.device.attachIO(stream, nil) }

func (d *Device) active() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.done:
		return false
	default:
		return d.stream != nil
	}
}
