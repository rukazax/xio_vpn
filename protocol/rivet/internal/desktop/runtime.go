package desktop

import (
	"context"
	"encoding/json"
	"errors"
	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdev "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdev "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"xio.local/rivet/internal/tailclient"
	"xio.local/rivet/internal/xrayclient"
	"xio.local/rivet/mobile"
)

const deviceName = "xio019"

var Protocols = []string{"wireguard", "awg", "rivet-h3", "rivet-s1", "xray", "shadowsocks", "tailscale"}

type packetDevice interface {
	Read([][]byte, []int, int) (int, error)
	Write([][]byte, int) (int, error)
	Close() error
	Name() (string, error)
}

// Native WireGuard TUNs use a virtio header and batched GSO packets on Linux.
// Reserve headroom for Write and consume every packet returned by Read.
type deviceIO struct {
	dev         packetDevice
	buffers     [][]byte
	sizes       []int
	next, count int
}

func newDeviceIO(dev packetDevice) *deviceIO {
	count := 1
	if b, ok := dev.(interface{ BatchSize() int }); ok {
		count = b.BatchSize()
	}
	if count < 1 || count > 256 {
		count = 1
	}
	d := &deviceIO{dev: dev, buffers: make([][]byte, count), sizes: make([]int, count)}
	for i := range d.buffers {
		d.buffers[i] = make([]byte, 65536+16)
	}
	return d
}
func (d *deviceIO) Read(b []byte) (int, error) {
	if d.next >= d.count {
		n, e := d.dev.Read(d.buffers, d.sizes, 16)
		if e != nil {
			return 0, e
		}
		d.next = 0
		d.count = n
	}
	if d.next >= d.count {
		return 0, io.ErrNoProgress
	}
	i := d.next
	d.next++
	if d.sizes[i] > len(b) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, d.buffers[i][16:16+d.sizes[i]]), nil
}
func (d *deviceIO) Write(b []byte) (int, error) {
	packet := make([]byte, 16+len(b))
	copy(packet[16:], b)
	_, e := d.dev.Write([][]byte{packet}, 16)
	if e != nil {
		return 0, e
	}
	return len(b), nil
}
func (d *deviceIO) Close() error              { return d.dev.Close() }
func (d *deviceIO) WritePacket(b []byte) bool { _, e := d.Write(b); return e == nil }

type Runtime struct {
	mu      sync.Mutex
	current *session
}
type session struct {
	id, protocol string
	stop         func()
	status       func() string
	network      *networkState
}

func (r *Runtime) Disconnect() { r.mu.Lock(); defer r.mu.Unlock(); r.stop() }
func (r *Runtime) stop() {
	if s := r.current; s != nil {
		r.current = nil
		s.stop()
		s.network.close()
	}
}
func (r *Runtime) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return map[string]any{"active": false}
	}
	s := r.current
	j := map[string]any{}
	_ = json.Unmarshal([]byte(s.status()), &j)
	j["id"] = s.id
	j["protocol"] = s.protocol
	return j
}
func (r *Runtime) Connect(id, protocol, raw string, timeout int64) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !isAdmin() {
		return nil, errors.New("administrator authorization required")
	}
	if timeout < 1000 || timeout > 60000 {
		return nil, ErrProfile
	}
	p, e := ParseProfile(protocol, raw)
	if e != nil {
		return nil, e
	}
	r.stop()
	n, e := prepareNetwork()
	if e != nil {
		return nil, e
	}
	s := &session{id: id, protocol: protocol, network: n}
	failed := true
	defer func() {
		if failed {
			if s.stop != nil {
				s.stop()
			}
			n.close()
		}
	}()
	started := time.Now()
	// Resolve endpoints on the physical network before installing full-tunnel routes.
	for i, ep := range p.Endpoints {
		h, port, _ := net.SplitHostPort(ep)
		resolved := n.Resolve(h)
		if net.ParseIP(resolved) == nil {
			return nil, errors.New("endpoint DNS failed")
		}
		ip, e := netip.ParseAddr(resolved)
		if e != nil || !ip.Is4() {
			return nil, errors.New("this desktop release requires an IPv4 endpoint")
		}
		p.Endpoints[i] = net.JoinHostPort(resolved, port)
		if e = n.bypass(ip); e != nil {
			return nil, e
		}
	}
	switch protocol {
	case "rivet-h3", "rivet-s1":
		if _, e = mobile.ConnectTimeout(raw, n, timeout); e != nil {
			return nil, e
		}
		s.stop = mobile.Stop
		s.status = mobile.Status
		t, e := awgtun.CreateTUN(deviceName, p.MTU)
		if e != nil {
			return nil, e
		}
		d := newDeviceIO(t)
		s.stop = func() { mobile.Stop(); d.Close() }
		if e = mobile.AttachPacketFlow(d); e != nil {
			return nil, e
		}
		go func() {
			buf := make([]byte, 65536)
			for {
				size, err := d.Read(buf)
				if err != nil {
					return
				}
				mobile.PacketInput(buf[:size])
			}
		}()
	case "wireguard":
		t, e := wgtun.CreateTUN(deviceName, p.MTU)
		if e != nil {
			return nil, e
		}
		d := wgdev.NewDevice(t, wgconn.NewDefaultBind(), &wgdev.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
		s.stop = d.Close
		s.status = func() string { v, _ := d.IpcGet(); return wgStatus(v) }
		p.IPC = resolvedIPC(p.IPC, p.Endpoints[0])
		if e = d.IpcSet(platformFwmark() + p.IPC); e != nil {
			return nil, ErrProfile
		}
		if e = d.Up(); e != nil {
			return nil, e
		}
	case "awg":
		t, e := awgtun.CreateTUN(deviceName, p.MTU)
		if e != nil {
			return nil, e
		}
		d := awgdev.NewDevice(t, awgconn.NewStdNetBind(), &awgdev.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
		s.stop = d.Close
		s.status = func() string { v, _ := d.IpcGet(); return wgStatus(v) }
		p.IPC = resolvedIPC(p.IPC, p.Endpoints[0])
		if e = d.IpcSet(platformFwmark() + p.IPC); e != nil {
			return nil, ErrProfile
		}
		if e = d.Up(); e != nil {
			return nil, e
		}
	case "xray", "shadowsocks":
		x, e := xrayclient.Start(raw, n, time.Duration(timeout)*time.Millisecond)
		if e != nil {
			return nil, e
		}
		s.stop = x.Close
		s.status = x.Status
		if e = x.AttachDevice(deviceName); e != nil {
			return nil, e
		}
	case "tailscale":
		store, e := newStore(raw)
		if e != nil {
			return nil, e
		}
		x, e := tailclient.Start(raw, store.dir, n, store, nil, time.Duration(timeout)*time.Millisecond)
		if e != nil {
			return nil, e
		}
		s.stop = x.Close
		s.status = x.Status
		t, e := awgtun.CreateTUN(deviceName, p.MTU)
		if e != nil {
			return nil, e
		}
		d := newDeviceIO(t)
		s.stop = func() { x.Close(); d.Close() }
		if e = x.AttachIO(d); e != nil {
			return nil, e
		}
		var addresses []string
		if json.Unmarshal([]byte(x.Addresses()), &addresses) != nil {
			return nil, ErrProfile
		}
		for _, a := range addresses {
			ip, e := netip.ParsePrefix(a)
			if e != nil {
				if addr, err := netip.ParseAddr(a); err == nil {
					ip = netip.PrefixFrom(addr, addr.BitLen())
					e = nil
				}
			}
			if e == nil && ip.Addr().Is4() {
				p.Addresses = append(p.Addresses, ip)
			}
		}
	default:
		return nil, ErrProfile
	}
	if len(p.Addresses) == 0 {
		return nil, ErrProfile
	}
	if e = n.configure(p); e != nil {
		return nil, e
	}
	r.current = s
	failed = false
	return map[string]any{"connectMillis": time.Since(started).Milliseconds()}, nil
}
func resolvedIPC(raw, ep string) string {
	var out strings.Builder
	for _, l := range strings.Split(raw, "\n") {
		if strings.HasPrefix(l, "endpoint=") {
			l = "endpoint=" + ep
		}
		if l != "" {
			out.WriteString(l + "\n")
		}
	}
	return out.String()
}
func wgStatus(raw string) string {
	j := map[string]any{"active": true}
	var sec, nano int64
	for _, l := range strings.Split(raw, "\n") {
		p := strings.SplitN(l, "=", 2)
		if len(p) != 2 {
			continue
		}
		v, _ := strconv.ParseInt(p[1], 10, 64)
		switch p[0] {
		case "rx_bytes":
			j["rx"] = v
		case "tx_bytes":
			j["tx"] = v
		case "last_handshake_time_sec":
			sec = v
		case "last_handshake_time_nsec":
			nano = v
		}
	}
	j["handshake"] = sec*1000 + nano/1000000
	b, _ := json.Marshal(j)
	return string(b)
}

var _ io.ReadWriteCloser = (*deviceIO)(nil)
var _ = context.Canceled
