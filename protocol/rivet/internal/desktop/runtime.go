package desktop

import (
	"context"
	"encoding/json"
	"errors"
	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdev "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"xio.local/rivet/internal/awgactivation"
	"xio.local/rivet/internal/physical"
	"xio.local/rivet/internal/xrayclient"
	"xio.local/rivet/mobile"
)

const deviceName = "xio019"

var Protocols = []string{"awg", "rivet-h3", "rivet-s1", "xray"}

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
	pendingMu        sync.Mutex
	pendingAWG       *awgConnectOperation
	mu               sync.Mutex
	current          *session
	sharingWanted    bool
	sharingInterface string
}
type session struct {
	id, protocol string
	stop         func()
	status       func() string
	network      *networkState
}

type awgConnectOperation struct{ cancel context.CancelFunc }

func (r *Runtime) Disconnect() {
	// Connect owns mu while waiting for authentication. Cancel its bounded AWG
	// operation BEFORE waiting for mu so DOWN can interrupt a pending handshake.
	r.pendingMu.Lock()
	if op := r.pendingAWG; op != nil {
		op.cancel()
	}
	r.pendingMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stop()
}
func (r *Runtime) withAWGContext(timeout int64, run func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	op := &awgConnectOperation{cancel: cancel}
	r.pendingMu.Lock()
	r.pendingAWG = op
	r.pendingMu.Unlock()
	defer func() {
		r.pendingMu.Lock()
		if r.pendingAWG == op {
			r.pendingAWG = nil
		}
		r.pendingMu.Unlock()
		cancel()
	}()
	err := run(ctx)
	if err == nil {
		err = ctx.Err()
	}
	return err
}
func (r *Runtime) stop() {
	if s := r.current; s != nil {
		if r.sharingWanted {
			_ = applySharing(false, r.sharingInterface)
		}
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
	if e = prepareEndpoints(&p, n); e != nil {
		return nil, e
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
		if e = r.withAWGContext(timeout, func(ctx context.Context) error { return activateAWGContext(ctx, d, p, timeout) }); e != nil {
			return nil, e
		}
	case "xray":
		x, e := xrayclient.Start(raw, n, time.Duration(timeout)*time.Millisecond)
		if e != nil {
			return nil, e
		}
		s.stop = x.Close
		s.status = x.Status
		if e = x.AttachDevice(deviceName); e != nil {
			return nil, e
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
	if r.sharingWanted {
		if e = applySharing(true, r.sharingInterface); e != nil {
			return nil, e
		}
	}
	r.current = s
	failed = false
	return map[string]any{"connectMillis": time.Since(started).Milliseconds()}, nil
}

// Endpoints are resolved on the physical network before full-tunnel routes.
func prepareEndpoints(p *Profile, n interface {
	Resolve(string) string
	bypass(netip.Addr) error
}) error {
	p.EndpointCandidates = make([][]string, len(p.Endpoints))
	for i, ep := range p.Endpoints {
		h, port, err := physical.ParseEndpoint(ep)
		if err != nil {
			return ErrProfile
		}
		resolved := n.Resolve(h)
		addresses, e := physical.Addresses(resolved)
		if e != nil {
			return errors.New("endpoint DNS failed")
		}
		// Rivet/Xray race their protected numeric candidates; reserve bypass
		// routes for ALL of them, not just the first family. AWG uses the first
		// for its initial configuration and walks every candidate for proof.
		p.Endpoints[i] = net.JoinHostPort(addresses[0], port)
		candidates := make([]string, 0, len(addresses))
		for _, address := range addresses {
			if e = n.bypass(netip.MustParseAddr(address)); e != nil {
				return e
			}
			candidates = append(candidates, net.JoinHostPort(address, port))
		}
		p.EndpointCandidates[i] = candidates
	}
	return nil
}

// awgPeerKey returns the single peer public key of generated IPC. Multiple
// peers keep the legacy path because one activation run proves one peer.
func awgPeerKey(ipc string) (string, bool) {
	key := ""
	for _, line := range strings.Split(ipc, "\n") {
		if !strings.HasPrefix(line, "public_key=") {
			continue
		}
		if key != "" {
			return "", false
		}
		key = strings.TrimPrefix(line, "public_key=")
	}
	if key == "" {
		return "", false
	}
	return key, true
}

// activateAWG proves an authenticated initial handshake from the exact packet
// source of one numeric candidate. Only the peer endpoint changes between
// attempts; the device, TUN, keypairs, counters, timers and bind are kept.
func activateAWGContext(ctx context.Context, d *awgdev.Device, p Profile, timeout int64) error {
	if len(p.Endpoints) != 1 || len(p.EndpointCandidates) != 1 || len(p.EndpointCandidates[0]) == 0 {
		return ErrProfile
	}
	key, ok := awgPeerKey(p.IPC)
	if !ok {
		return ErrProfile
	}
	public, candidates, err := awgactivation.Validate(key, strings.Join(p.EndpointCandidates[0], ","), timeout)
	if err != nil {
		return ErrProfile
	}
	return awgactivation.Run(ctx, d, public, candidates)
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
