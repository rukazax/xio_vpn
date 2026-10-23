//go:build !windows

package xrayclient

import (
	"errors"
	tengine "github.com/amnezia-vpn/amnezia-tun2socks/v2/engine"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/tunnel/statistic"
	"golang.org/x/sys/unix"
	"net"
	"strconv"
	"time"
)

func (s *Session) Attach(fd int) error {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if fd < 0 || s.closed.Load() {
		return net.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attached {
		return ErrConfig
	}
	statistic.DefaultManager.ResetStatistic()
	owned, e := unix.Dup(fd)
	if e != nil {
		return e
	}
	tengine.Insert(&tengine.Key{MTU: 1280, Device: "fd://" + strconv.Itoa(owned), Proxy: "xio://", LogLevel: "silent", UDPTimeout: 30 * time.Second})
	if e := tengine.StartTun2Socks(); e != nil {
		_ = tengine.StopTun2Socks()
		return errors.New("xray: TUN start failed")
	}
	s.attached = true
	_ = unix.Close(fd) // Ownership transferred only after successful setup.
	return nil
}
