// Package xrayclient embeds Xray without a local listener or direct route.
package xrayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	tengine "github.com/amnezia-vpn/amnezia-tun2socks/v2/engine"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/proxy"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/tunnel/statistic"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Protector interface {
	Protect(int64) bool
	Resolve(string) string
}

var ErrConfig = errors.New("xray: invalid or unsafe profile")
var ErrProtect = errors.New("xray: physical socket protection failed")

type Config struct {
	Protocol string         `json:"protocol"`
	Outbound map[string]any `json:"outbound"`
}

func unsafe(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, w := range v {
			l := strings.ToLower(k)
			if strings.HasSuffix(l, "file") || l == "allowinsecure" && w != false || l == "sockopt" || l == "dialerproxy" || l == "proxysettings" || l == "downloadsettings" {
				return true
			}
			if unsafe(w) {
				return true
			}
		}
	case []any:
		for _, w := range v {
			if unsafe(w) {
				return true
			}
		}
	}
	return false
}
func Parse(raw string) (Config, error) {
	var c Config
	if len(raw) > 65536 || len(raw) == 0 {
		return c, ErrConfig
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, ErrConfig
	}
	if d.Decode(new(any)) != io.EOF {
		return c, ErrConfig
	}
	if (c.Protocol != "xray" && c.Protocol != "shadowsocks") || unsafe(c.Outbound) {
		return c, ErrConfig
	}
	for k := range c.Outbound {
		if k != "protocol" && k != "settings" && k != "streamSettings" && k != "mux" && k != "tag" {
			return c, ErrConfig
		}
	}
	kind, _ := c.Outbound["protocol"].(string)
	if kind != "vless" && kind != "vmess" && kind != "trojan" && kind != "shadowsocks" {
		return c, ErrConfig
	}
	if (kind == "shadowsocks") != (c.Protocol == "shadowsocks") {
		return c, ErrConfig
	}
	stream, _ := c.Outbound["streamSettings"].(map[string]any)
	sec, _ := stream["security"].(string)
	if kind == "vless" && sec != "tls" && sec != "reality" || kind == "trojan" && sec != "tls" {
		return c, ErrConfig
	}
	network, _ := stream["network"].(string)
	if network != "" && network != "tcp" && network != "raw" && network != "ws" && network != "grpc" && network != "httpupgrade" && network != "xhttp" && network != "splithttp" {
		return c, ErrConfig
	}
	if _, _, e := endpoint(c); e != nil {
		return c, e
	}
	if _, e := core.LoadConfig("json", bytes.NewReader(configBytes(c))); e != nil {
		return c, ErrConfig
	}
	return c, nil
}
func endpoint(c Config) (map[string]any, string, error) {
	settings, _ := c.Outbound["settings"].(map[string]any)
	key := "servers"
	if c.Outbound["protocol"] == "vless" || c.Outbound["protocol"] == "vmess" {
		key = "vnext"
	}
	a, _ := settings[key].([]any)
	if len(a) != 1 {
		return nil, "", ErrConfig
	}
	s, _ := a[0].(map[string]any)
	host, _ := s["address"].(string)
	port, ok := s["port"].(float64)
	if host == "" || strings.ContainsAny(host, "\x00\r\n/") || !ok || port < 1 || port > 65535 || port != float64(int(port)) {
		return nil, "", ErrConfig
	}
	return s, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}
func configBytes(c Config) []byte {
	b, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{c.Outbound}})
	return b
}

type Session struct {
	instance  *core.Instance
	p         Protector
	endpoint  string
	ctx       context.Context
	cancel    context.CancelFunc
	handshake atomic.Int64
	closed    atomic.Bool
	attached  bool
	mu        sync.Mutex
}

var current struct {
	sync.RWMutex
	s *Session
}
var lifecycle sync.Mutex

func init() {
	// Default Xray controllers log errors and continue. This dialer fails closed.
	internet.UseAlternativeSystemDialer(protectedDialer{})
	proxy.RegisterProtocol("xio", func(*url.URL) (proxy.Proxy, error) {
		current.RLock()
		s := current.s
		current.RUnlock()
		if s == nil || s.closed.Load() {
			return nil, net.ErrClosed
		}
		return s, nil
	})
}

type protectedDialer struct{}

func (protectedDialer) DestIpAddress() net.IP { return nil }
func (protectedDialer) Dial(ctx context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	current.RLock()
	s := current.s
	current.RUnlock()
	if s == nil || s.closed.Load() || dest.NetAddr() != s.endpoint {
		return nil, ErrProtect
	}
	d := net.Dialer{Timeout: 10 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		ok := false
		e := c.Control(func(fd uintptr) { ok = s.p != nil && s.p.Protect(int64(fd)) })
		if e != nil {
			return e
		}
		if !ok {
			return ErrProtect
		}
		return nil
	}}
	return d.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}
func Start(raw string, p Protector, timeout time.Duration) (*Session, error) {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if timeout <= 0 || timeout > 60*time.Second || p == nil {
		return nil, ErrConfig
	}
	c, e := Parse(raw)
	if e != nil {
		return nil, e
	}
	server, ep, e := endpoint(c)
	if e != nil {
		return nil, e
	}
	host, port, _ := net.SplitHostPort(ep)
	if net.ParseIP(host) == nil {
		done := make(chan string, 1)
		go func() { done <- p.Resolve(host) }()
		select {
		case host = <-done:
		case <-time.After(timeout):
			return nil, errors.New("xray: endpoint resolution timeout")
		}
		if net.ParseIP(host) == nil {
			return nil, errors.New("xray: endpoint resolution failed")
		}
		stream, _ := c.Outbound["streamSettings"].(map[string]any)
		if stream["security"] == "tls" {
			tls, _ := stream["tlsSettings"].(map[string]any)
			if tls == nil {
				tls = map[string]any{}
				stream["tlsSettings"] = tls
			}
			if tls["serverName"] == nil {
				original, _, _ := net.SplitHostPort(ep)
				tls["serverName"] = original
			}
		}
		server["address"] = host
	}
	current.RLock()
	old := current.s
	current.RUnlock()
	if old != nil {
		old.closeLocked()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{p: p, endpoint: net.JoinHostPort(host, port), ctx: ctx, cancel: cancel}
	current.Lock()
	current.s = s
	current.Unlock()
	v, e := core.StartInstance("json", configBytes(c))
	if e != nil {
		s.closeLocked()
		return nil, ErrConfig
	}
	s.instance = v
	return s, nil
}
func (s *Session) Close() { lifecycle.Lock(); defer lifecycle.Unlock(); s.closeLocked() }
func (s *Session) closeLocked() {
	if s.closed.Swap(true) {
		return
	}
	s.cancel()
	if s.instance != nil {
		s.instance.Close()
	}
	s.mu.Lock()
	if s.attached {
		_ = tengine.StopTun2Socks()
		s.attached = false
	}
	s.mu.Unlock()
	current.Lock()
	if current.s == s {
		current.s = nil
	}
	current.Unlock()
}
func (s *Session) Status() string {
	s.mu.Lock()
	attached := s.attached
	s.mu.Unlock()
	st := statistic.DefaultManager.Snapshot()
	b, _ := json.Marshal(map[string]any{"active": attached && !s.closed.Load(), "secure": s.handshake.Load() > 0 && !s.closed.Load(), "handshake": s.handshake.Load(), "rx": st.DownloadTotal, "tx": st.UploadTotal})
	return string(b)
}

type countedConn struct {
	net.Conn
	s      *Session
	cancel context.CancelFunc
}

func (c *countedConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.s.handshake.Store(time.Now().UnixMilli())
	}
	return n, e
}
func (c *countedConn) Close() error { c.cancel(); return c.Conn.Close() }
func (s *Session) DialContext(ctx context.Context, m *metadata.Metadata) (net.Conn, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	dest, e := xnet.ParseDestination("tcp:" + m.DestinationAddress())
	if e != nil {
		return nil, e
	}
	life, cancel := context.WithCancel(s.ctx)
	stop := context.AfterFunc(ctx, cancel)
	c, e := core.Dial(life, s.instance, dest)
	if e != nil {
		stop()
		cancel()
		return nil, e
	}
	return &countedConn{Conn: c, s: s, cancel: func() { stop(); cancel() }}, nil
}
func (s *Session) DialUDP(m *metadata.Metadata) (net.PacketConn, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(s.ctx)
	pc, e := core.DialUDP(ctx, s.instance)
	if e != nil {
		cancel()
		return nil, e
	}
	return newPacketConn(pc, s, cancel), nil
}
