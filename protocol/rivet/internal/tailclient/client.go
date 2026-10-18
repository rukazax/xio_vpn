package tailclient

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/logtail"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"time"
)

type NetworkInfo interface{ Interfaces() string }
type Protector interface {
	Protect(int64) bool
	Resolve(string) string
}
type SecureStore interface {
	Load(string) string
	Save(string, string) bool
}
type encryptedStore struct {
	mu    sync.Mutex
	store SecureStore
}

func (s *encryptedStore) ReadState(k ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.store.Load(string(k))
	if b == "" {
		return nil, ipn.ErrStateNotExist
	}
	decoded, e := base64.StdEncoding.DecodeString(b)
	if e != nil {
		return nil, errors.New("tailscale: encrypted state unavailable")
	}
	return decoded, nil
}
func (s *encryptedStore) WriteState(k ipn.StateKey, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := ""
	if b != nil {
		value = base64.StdEncoding.EncodeToString(b)
	}
	if !s.store.Save(string(k), value) {
		return errors.New("tailscale: encrypted state could not be saved")
	}
	return nil
}

type Config struct {
	Protocol   string `json:"protocol"`
	ControlURL string `json:"controlURL"`
	ControlCA  string `json:"controlCA,omitempty"`
	AuthKey    string `json:"authKey"`
	ExitNode   string `json:"exitNode"`
	Hostname   string `json:"hostname"`
}

func Parse(raw string) (Config, error) {
	var c Config
	if len(raw) > 65536 {
		return c, errors.New("tailscale: profile too large")
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("tailscale: invalid profile")
	}
	u, e := url.Parse(c.ControlURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || c.Protocol != "tailscale" || len(c.AuthKey) < 1 || len(c.AuthKey) > 1024 || c.ExitNode == "" || len(c.ExitNode) > 253 || len(c.Hostname) > 63 {
		return c, errors.New("tailscale: invalid profile")
	}
	if c.ControlCA != "" {
		pool := x509.NewCertPool()
		if len(c.ControlCA) > 16384 || !pool.AppendCertsFromPEM([]byte(c.ControlCA)) {
			return c, errors.New("tailscale: invalid control CA")
		}
	}
	return c, nil
}

type Session struct {
	handshake atomic.Int64

	server *tsnet.Server
	device *Device
	cancel context.CancelFunc
	once   sync.Once
	ips    []string
}

func init() { logtail.Disable(); envknob.SetNoLogsNoSupport() }
func Start(raw, dir string, p Protector, store SecureStore, networkInfo NetworkInfo, timeout time.Duration) (*Session, error) {
	c, e := Parse(raw)
	if e != nil {
		return nil, e
	}
	if p == nil || store == nil || timeout < time.Millisecond || timeout > 60*time.Second {
		return nil, errors.New("tailscale: invalid startup")
	}
	setProtect(p)
	setNetworkInfo(networkInfo)
	device := NewDevice()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{device: device, cancel: cancel}
	discard := func(string, ...any) {}
	server := &tsnet.Server{Dir: dir, Hostname: c.Hostname, AuthKey: c.AuthKey, ControlURL: c.ControlURL, Store: &encryptedStore{store: store}, Tun: device, Logf: discard, UserLogf: discard}
	if c.ControlCA != "" {
		server.ExtraRootCAs = x509.NewCertPool()
		server.ExtraRootCAs.AppendCertsFromPEM([]byte(c.ControlCA))
	}
	s.server = server
	fail := true
	defer func() {
		if fail {
			s.Close()
		}
	}()
	wait, stop := context.WithTimeout(ctx, timeout)
	defer stop()
	status, e := server.Up(wait)
	if e != nil {
		return nil, errors.New("tailscale: authentication/control connection failed")
	}
	local, e := server.LocalClient()
	if e != nil {
		return nil, e
	}
	var selected tailcfg.StableNodeID
	for selected == "" {
		for _, peer := range status.Peer {
			if !peer.Online || !peer.ExitNodeOption {
				continue
			}
			matches := string(peer.ID) == c.ExitNode || peer.DNSName == c.ExitNode
			for _, ip := range peer.TailscaleIPs {
				matches = matches || ip.String() == c.ExitNode
			}
			if matches {
				selected = peer.ID
				break
			}
		}
		if selected != "" {
			break
		}
		select {
		case <-wait.Done():
			return nil, errors.New("tailscale: exit node unavailable or not approved")
		case <-time.After(200 * time.Millisecond):
		}
		status, e = local.Status(wait)
		if e != nil {
			return nil, errors.New("tailscale: control status failed")
		}
	}
	_, e = local.EditPrefs(wait, &ipn.MaskedPrefs{Prefs: ipn.Prefs{ExitNodeID: selected, CorpDNS: false, ExitNodeAllowLANAccess: false}, ExitNodeIDSet: true, CorpDNSSet: true, ExitNodeAllowLANAccessSet: true})
	if e != nil {
		return nil, errors.New("tailscale: exit node selection failed")
	}
	for _, ip := range status.TailscaleIPs {
		s.ips = append(s.ips, ip.String())
	}
	if len(s.ips) == 0 {
		return nil, errors.New("tailscale: no assigned address")
	}
	go func() {
		var previousRx int64
		for {
			status, e := local.Status(ctx)
			if e == nil {
				for _, peer := range status.Peer {
					if peer.ID == selected {
						if peer.RxBytes > previousRx {
							s.handshake.Store(time.Now().UnixMilli())
						}
						previousRx = peer.RxBytes
						if h := peer.LastHandshake.UnixMilli(); !peer.LastHandshake.IsZero() && h > s.handshake.Load() {
							s.handshake.Store(h)
						}
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}()
	fail = false
	return s, nil
}
func (s *Session) Attach(fd int) error { return s.device.Attach(fd) }
func (s *Session) Addresses() string   { b, _ := json.Marshal(s.ips); return string(b) }
func (s *Session) Status() string {
	b, _ := json.Marshal(map[string]any{"active": s.device.active(), "secure": s.handshake.Load() > 0, "handshake": s.handshake.Load(), "rx": s.device.rx.Load(), "tx": s.device.tx.Load()})
	return string(b)
}
func (s *Session) Close() {
	s.once.Do(func() {
		s.cancel()
		s.device.Close()
		s.handshake.Store(0)
		if s.server != nil {
			s.server.Close()
		}
	})
}

func (s *Session) NetworkChanged() {
	if sys := s.server.Sys(); sys != nil {
		if m, ok := sys.NetMon.GetOK(); ok && m != nil {
			m.InjectEvent()
		}
	}
}
