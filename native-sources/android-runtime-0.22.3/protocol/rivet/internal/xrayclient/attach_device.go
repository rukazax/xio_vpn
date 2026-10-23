package xrayclient

import (
	"errors"
	tengine "github.com/amnezia-vpn/amnezia-tun2socks/v2/engine"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/tunnel/statistic"
	"time"
)

// AttachDevice is for the desktop helper only. It owns a named platform TUN.
func (s *Session) AttachDevice(name string) error {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attached || s.closed.Load() || name != "xio019" {
		return ErrConfig
	}
	statistic.DefaultManager.ResetStatistic()
	tengine.Insert(&tengine.Key{MTU: 1280, Device: "tun://" + name, Proxy: "xio://", LogLevel: "silent", UDPTimeout: 30 * time.Second})
	if err := tengine.StartTun2Socks(); err != nil {
		_ = tengine.StopTun2Socks()
		return errors.New("xray: platform TUN failed")
	}
	s.attached = true
	return nil
}
