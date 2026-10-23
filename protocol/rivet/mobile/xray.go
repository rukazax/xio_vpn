package mobile

import (
	"net"
	"sync"
	"time"
	"xio.local/rivet/internal/xrayclient"
)

var xrayMobile struct {
	sync.Mutex
	s *xrayclient.Session
}

func XrayValidate(raw string) error { _, e := xrayclient.Parse(raw); return e }
func XrayStart(raw string, p Protector, timeoutMillis int64) error {
	XrayStop()
	s, e := xrayclient.Start(raw, p, time.Duration(timeoutMillis)*time.Millisecond)
	if e != nil {
		return e
	}
	xrayMobile.Lock()
	xrayMobile.s = s
	xrayMobile.Unlock()
	return nil
}
func XrayAttachTun(fd int64) error {
	xrayMobile.Lock()
	defer xrayMobile.Unlock()
	if xrayMobile.s == nil || fd < 0 || fd > 2147483647 {
		return net.ErrClosed
	}
	return xrayMobile.s.Attach(int(fd))
}
func XrayStop() {
	xrayMobile.Lock()
	s := xrayMobile.s
	xrayMobile.s = nil
	xrayMobile.Unlock()
	if s != nil {
		s.Close()
	}
}
func XrayStatus() string {
	xrayMobile.Lock()
	s := xrayMobile.s
	xrayMobile.Unlock()
	if s == nil {
		return `{"active":false,"secure":false}`
	}
	return s.Status()
}

// XrayCheckHttps uses the active encrypted session, even if routing excludes the app.
func XrayCheckHttps(site, rootsPEM string, timeoutMillis int64) error {
	xrayMobile.Lock()
	s := xrayMobile.s
	xrayMobile.Unlock()
	if s == nil {
		return net.ErrClosed
	}
	return s.ProbeHTTPS(site, rootsPEM, time.Duration(timeoutMillis)*time.Millisecond)
}
