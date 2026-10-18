package mobile

import (
	"net"
	"sync"
	"time"
	"xio.local/rivet/internal/tailclient"
)

type NetworkInfo interface{ Interfaces() string }
type SecureStore interface {
	Load(string) string
	Save(string, string) bool
}

var tailMobile struct {
	sync.Mutex
	s *tailclient.Session
}

func TailscaleValidate(raw string) error { _, e := tailclient.Parse(raw); return e }
func TailscaleStart(raw, dir string, p Protector, store SecureStore, networkInfo NetworkInfo, timeoutMillis int64) (string, error) {
	TailscaleStop()
	s, e := tailclient.Start(raw, dir, p, store, networkInfo, time.Duration(timeoutMillis)*time.Millisecond)
	if e != nil {
		return "", e
	}
	tailMobile.Lock()
	tailMobile.s = s
	tailMobile.Unlock()
	return s.Addresses(), nil
}
func TailscaleAttachTun(fd int64) error {
	tailMobile.Lock()
	defer tailMobile.Unlock()
	if tailMobile.s == nil || fd < 0 || fd > 2147483647 {
		return net.ErrClosed
	}
	return tailMobile.s.Attach(int(fd))
}
func TailscaleStatus() string {
	tailMobile.Lock()
	s := tailMobile.s
	tailMobile.Unlock()
	if s == nil {
		return `{"active":false,"secure":false}`
	}
	return s.Status()
}
func TailscaleStop() {
	tailMobile.Lock()
	s := tailMobile.s
	tailMobile.s = nil
	tailMobile.Unlock()
	if s != nil {
		s.Close()
	}
}

func TailscaleNetworkChanged() {
	tailMobile.Lock()
	s := tailMobile.s
	tailMobile.Unlock()
	if s != nil {
		s.NetworkChanged()
	}
}
