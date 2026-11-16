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
	"sync/atomic"
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

// Private injection seam for offline setup-pipeline tests; nil uses native ops.
type runtimeSetupOps struct {
	admin   func() bool
	prepare func(*setupLease) (*networkState, error)
	start   func(*setupLease, Profile, *networkState) (func(), func() string, error)
}
type Runtime struct {
	setupOps         *runtimeSetupOps
	generation       atomic.Uint64
	cleanupPending   atomic.Bool
	cleanupFailure   atomic.Bool
	now              func() time.Time
	pendingMu        sync.Mutex
	pendingAWG       *awgConnectOperation
	pendingSetup     *setupLease
	mu               sync.Mutex
	current          *session
	sharingWanted    bool
	sharingInterface string
	// Versioned policy admission (WIRE-V2). All policy state is mutated under
	// mu; read-only platform evidence happens outside it while `policy.writing`
	// still owns the single writer lane.
	policy           policyMachine
	policyNonceOnce  sync.Once
	policyNonceState atomic.Pointer[instanceNonceState]
	newPolicyNonce   func() (string, error)
}
type session struct {
	id, protocol string
	stop         func()
	status       func() string
	network      *networkState
}

type awgConnectOperation struct{ cancel context.CancelFunc }

func (r *Runtime) Disconnect() { _ = r.DisconnectTimeout(30000) }

func (r *Runtime) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// lockUntil bounds admission without abandoning a lock-acquisition goroutine.
// A timed-out old owner still holds mu, so no replacement can open a device.
func (r *Runtime) lockUntil(deadline time.Time) bool {
	for {
		if !r.clock().Before(deadline) {
			return false
		}
		if r.mu.TryLock() {
			return true
		}
		timer := time.NewTimer(min(5*time.Millisecond, deadline.Sub(r.clock())))
		<-timer.C
	}
}

// Called with mu held. On timeout ownership of mu transfers to the joiner;
// callers must not unlock or admit a competing activation until teardown joins.
func (r *Runtime) stopUntilLocked(deadline time.Time, cleanup ...func()) bool {
	done := make(chan struct{})
	r.cleanupFailure.Store(false)
	r.cleanupPending.Store(true)
	run := r.stop
	if len(cleanup) > 0 {
		run = cleanup[0]
	}
	go func() { defer close(done); run() }()
	left := max(time.Duration(0), deadline.Sub(r.clock()))
	timer := time.NewTimer(left)
	defer timer.Stop()
	select {
	case <-done:
		r.cleanupPending.Store(r.cleanupFailure.Load())
		return true
	case <-timer.C:
		go func() { <-done; r.cleanupPending.Store(r.cleanupFailure.Load()); r.mu.Unlock() }()
		return false
	}
}

func (r *Runtime) DisconnectTimeout(timeoutMillis int64) error {
	if timeoutMillis < 1 || timeoutMillis > 30000 {
		return ErrProfile
	}
	deadline := r.clock().Add(time.Duration(timeoutMillis) * time.Millisecond)
	r.pendingMu.Lock()
	r.generation.Add(1)
	if r.pendingSetup != nil {
		r.pendingSetup.cancel()
	}
	r.pendingMu.Unlock()
	mobile.CancelConnect()
	// Connect owns mu while waiting for authentication. Cancel its bounded AWG
	// operation BEFORE waiting for mu so DOWN can interrupt a pending handshake.
	r.pendingMu.Lock()
	if op := r.pendingAWG; op != nil {
		op.cancel()
	}
	r.pendingMu.Unlock()
	r.cleanupPending.Store(true)
	if !r.lockUntil(deadline) {
		return errors.New("desktop: teardown incomplete")
	}
	locked := true
	defer func() {
		if locked {
			r.mu.Unlock()
		}
	}()
	if !r.stopUntilLocked(deadline) {
		locked = false
		return errors.New("desktop: teardown incomplete")
	}
	if r.cleanupFailure.Load() {
		return errors.New("desktop: teardown incomplete")
	}
	left := deadline.Sub(r.clock()).Milliseconds()
	if left <= 0 {
		return errors.New("desktop: teardown incomplete")
	}
	if err := mobile.StopWithTimeout(left); err != nil {
		r.cleanupPending.Store(true)
		return err
	}
	if !r.clock().Before(deadline) {
		return errors.New("desktop: teardown incomplete")
	}
	return nil
}
func (r *Runtime) withAWGContext(timeout int64, run func(context.Context) error, leases ...*setupLease) error {
	var lease *setupLease
	if len(leases) > 0 {
		lease = leases[0]
	}
	ctx, cancel, admissionErr := lease.admit(time.Duration(timeout) * time.Millisecond)
	if admissionErr != nil {
		return admissionErr
	}
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
	if r.sharingWanted {
		if err := applySharing(false, r.sharingInterface); err != nil {
			r.cleanupFailure.Store(true)
		}
	}
	if s := r.current; s != nil {
		r.current = nil
		s.stop()
		s.network.close()
	}
}
func (r *Runtime) Status() map[string]any {
	if !r.mu.TryLock() {
		return map[string]any{"active": false, "secure": false, "phase": "pending", "cleanupPending": r.cleanupPending.Load()}
	}
	defer r.mu.Unlock()
	if r.cleanupPending.Load() {
		return map[string]any{"active": false, "secure": false, "phase": "stopping", "cleanupPending": true}
	}
	if r.current == nil {
		return map[string]any{"active": false}
	}
	s := r.current
	j := map[string]any{}
	_ = json.Unmarshal([]byte(s.status()), &j)
	j["id"] = s.id
	if s.protocol != "rivet-h3" && s.protocol != "rivet-s1" || j["protocol"] == nil {
		j["protocol"] = s.protocol
	}
	return j
}
func (r *Runtime) Connect(id, protocol, raw string, timeout int64) (map[string]any, error) {
	return r.ConnectWithPolicy(id, protocol, raw, timeout, min(timeout, 30000), "")
}

// ConnectWithPolicy keeps the legacy unversioned activation entrypoint. It is
// refused once versioned policy ownership began (see admitPolicyLocked).
func (r *Runtime) ConnectWithPolicy(id, protocol, raw string, timeout, roundMillis int64, policyJSON string) (map[string]any, error) {
	return r.connectWithReceipt(id, protocol, raw, timeout, roundMillis, policyJSON, "")
}

// ConnectWithPolicyReceipt is the versioned activation entrypoint. The receipt
// is validated and compared with actual raw configuration before any stop,
// setup or route effect.
func (r *Runtime) ConnectWithPolicyReceipt(id, protocol, raw string, timeout, roundMillis int64, policyJSON, receiptJSON string) (map[string]any, error) {
	return r.connectWithReceipt(id, protocol, raw, timeout, roundMillis, policyJSON, receiptJSON)
}

func (r *Runtime) connectWithReceipt(id, protocol, raw string, timeout, roundMillis int64, policyJSON, receiptJSON string) (map[string]any, error) {
	receipt, err := parsePolicyReceipt(receiptJSON)
	if err != nil {
		return nil, err
	}
	epoch := r.generation.Load()
	started := r.clock()
	mode, err := mobile.ConnectionPolicyMode(policyJSON)
	if err != nil {
		return nil, err
	}
	if roundMillis == 0 {
		roundMillis = min(timeout, 30000)
	}
	if timeout < 1 || timeout > 60000 || roundMillis < 1 || roundMillis > 30000 {
		return nil, ErrProfile
	}
	deadline := started.Add(time.Duration(roundMillis) * time.Millisecond)
	workDeadline := started.Add(time.Duration(min(timeout, roundMillis)) * time.Millisecond)
	remaining := func() (int64, error) {
		if epoch != r.generation.Load() {
			return 0, context.Canceled
		}
		left := workDeadline.Sub(r.clock()).Milliseconds()
		if left <= 0 {
			return 0, context.DeadlineExceeded
		}
		return left, nil
	}
	if !r.lockUntil(workDeadline) {
		return nil, context.DeadlineExceeded
	}
	locked := true
	defer func() {
		if locked {
			r.mu.Unlock()
		}
	}()
	if _, err := remaining(); err != nil {
		return nil, err
	}
	if r.cleanupPending.Load() {
		return nil, errors.New("desktop: teardown incomplete")
	}
	// Admission happens under the Runtime mutex before ANY stop/setup/effect and
	// re-derives the saved-config digest from the actual raw bytes.
	if err := r.admitPolicyLocked(id, protocol, raw, receipt); err != nil {
		return nil, err
	}
	admin := isAdmin
	if r.setupOps != nil && r.setupOps.admin != nil {
		admin = r.setupOps.admin
	}
	if !admin() {
		return nil, errors.New("administrator authorization required")
	}
	p, e := ParseProfile(protocol, raw)
	if e != nil {
		return nil, e
	}
	if !r.stopUntilLocked(deadline) {
		locked = false
		return nil, errors.New("desktop: teardown incomplete")
	}
	if r.cleanupFailure.Load() {
		return nil, errors.New("desktop: teardown incomplete")
	}
	cleanupLeft := deadline.Sub(r.clock()).Milliseconds()
	if cleanupLeft <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := mobile.StopWithTimeout(cleanupLeft); err != nil {
		return nil, err
	}
	if _, err := remaining(); err != nil {
		return nil, err
	}
	r.pendingMu.Lock()
	setup := newSetupLease(&r.pendingMu, workDeadline, r.clock, func() bool { return epoch == r.generation.Load() })
	r.pendingSetup = setup
	r.pendingMu.Unlock()
	defer func() {
		r.pendingMu.Lock()
		if r.pendingSetup == setup {
			r.pendingSetup = nil
		}
		setup.cancel()
		r.pendingMu.Unlock()
	}()
	if err := setup.check(); err != nil {
		return nil, err
	}
	prepare := func(s *setupLease) (*networkState, error) { return prepareNetwork(s) }
	if r.setupOps != nil && r.setupOps.prepare != nil {
		prepare = r.setupOps.prepare
	}
	n, e := prepare(setup)
	if e != nil {
		return nil, e
	}
	s := &session{id: id, protocol: protocol, network: n}
	failed := true
	sharingTouched := false
	defer func() {
		if failed {
			if protocol == "rivet-h3" || protocol == "rivet-s1" {
				mobile.CancelConnect()
			}
			if !r.stopUntilLocked(deadline, func() {
				if sharingTouched {
					if err := applySharing(false, r.sharingInterface); err != nil {
						r.cleanupFailure.Store(true)
					}
				}
				if s.stop != nil {
					s.stop()
				}
				n.close()
			}) {
				locked = false // The teardown joiner, not this obsolete activation, now owns mu.
			} else if protocol == "rivet-h3" || protocol == "rivet-s1" {
				if err := mobile.StopWithTimeout(max(int64(1), deadline.Sub(r.clock()).Milliseconds())); err != nil {
					r.cleanupPending.Store(true)
				}
			}
		}
	}()
	if _, err := remaining(); err != nil {
		return nil, err
	}
	if e = prepareEndpointsBudget(&p, n, func() error { _, err := remaining(); return err }, setup.ctx); e != nil {
		return nil, e
	}
	timeout, e = remaining()
	if e != nil {
		return nil, e
	}
	if r.setupOps != nil && r.setupOps.start != nil {
		e = setup.effect(func() error { s.stop, s.status, e = r.setupOps.start(setup, p, n); return e })
		if e != nil {
			return nil, e
		}
	} else {
		switch protocol {
		case "rivet-h3", "rivet-s1":
			e = setup.effect(func() error {
				left, err := remaining()
				if err != nil {
					return err
				}
				_, err = mobile.ConnectPolicyTimeout(raw, n, left, policyJSON)
				return err
			})
			if e != nil {
				return nil, e
			}
			s.stop = mobile.Stop
			s.status = mobile.Status
			var t awgtun.Device
			e = setup.effect(func() error { var err error; t, err = awgtun.CreateTUN(deviceName, p.MTU); return err })
			if e != nil {
				return nil, e
			}
			d := newDeviceIO(t)
			readerDone := make(chan struct{})
			readerStarted := false
			s.stop = func() {
				d.Close() // Unblock the caller-owned device before joining the packet sink.
				mobile.Stop()
				if readerStarted {
					<-readerDone
				}
			}
			if e = setup.effect(func() error { return mobile.AttachPacketFlow(d) }); e != nil {
				return nil, e
			}
			readerStarted = true
			go func() {
				defer close(readerDone)
				buf := make([]byte, 65536)
				for {
					size, err := d.Read(buf)
					if err != nil {
						mobile.CancelConnect()
						return
					}
					mobile.PacketInput(buf[:size])
				}
			}()
		case "awg":
			var t awgtun.Device
			e = setup.effect(func() error { var err error; t, err = awgtun.CreateTUN(deviceName, p.MTU); return err })
			if e != nil {
				return nil, e
			}
			s.stop = func() { _ = t.Close() }
			var d *awgdev.Device
			e = setup.effect(func() error {
				d = awgdev.NewDevice(t, awgconn.NewStdNetBind(), &awgdev.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
				return nil
			})
			if e != nil {
				return nil, e
			}
			s.stop = d.Close
			s.status = func() string { v, _ := d.IpcGet(); return wgStatus(v) }
			p.IPC = resolvedIPC(p.IPC, p.Endpoints[0])
			if e = setup.effect(func() error { return d.IpcSet(platformFwmark() + p.IPC) }); e != nil {
				return nil, ErrProfile
			}
			if e = setup.effect(d.Up); e != nil {
				return nil, e
			}
			timeout, e = remaining()
			if e != nil {
				return nil, e
			}
			if e = r.withAWGContext(timeout, func(ctx context.Context) error { return activateAWGContext(ctx, d, p, timeout) }, setup); e != nil {
				return nil, e
			}
		case "xray":
			var x *xrayclient.Session
			e = setup.effect(func() error {
				left, err := remaining()
				if err != nil {
					return err
				}
				x, err = xrayclient.Start(raw, n, time.Duration(left)*time.Millisecond)
				return err
			})
			if e != nil {
				return nil, e
			}
			s.stop = x.Close
			s.status = x.Status
			if e = setup.effect(func() error { return x.AttachDevice(deviceName) }); e != nil {
				return nil, e
			}
		default:
			return nil, ErrProfile
		}
	}
	if len(p.Addresses) == 0 {
		return nil, ErrProfile
	}
	if _, err := remaining(); err != nil {
		return nil, err
	}
	if e = n.configure(p); e != nil {
		return nil, e
	}
	if _, err := remaining(); err != nil {
		return nil, err
	}
	if r.sharingWanted {
		sharingTouched = true
		if e = applySharingSetup(true, r.sharingInterface, setup); e != nil {
			return nil, e
		}
	}
	if _, err := remaining(); err != nil {
		return nil, err
	}
	if err := setup.commit(func() { r.current = s; r.pendingSetup = nil }); err != nil {
		return nil, err
	}
	failed = false
	return map[string]any{"connectMillis": r.clock().Sub(started).Milliseconds(), "policyMode": mode}, nil
}

// Endpoints are resolved on the physical network before full-tunnel routes.
type endpointNetwork interface {
	Resolve(string) string
	bypass(netip.Addr) error
}

func prepareEndpoints(p *Profile, n endpointNetwork) error {
	return prepareEndpointsBudget(p, n, func() error { return nil })
}
func prepareEndpointsBudget(p *Profile, n endpointNetwork, current func() error, contexts ...context.Context) error {
	p.EndpointCandidates = make([][]string, len(p.Endpoints))
	for i, ep := range p.Endpoints {
		if err := current(); err != nil {
			return err
		}
		h, port, err := physical.ParseEndpoint(ep)
		if err != nil {
			return ErrProfile
		}
		var resolved string
		if len(contexts) > 0 {
			resolver, ok := n.(interface {
				ResolveContext(context.Context, string) string
			})
			if !ok {
				return errors.New("endpoint resolver lacks setup cancellation")
			}
			resolved = resolver.ResolveContext(contexts[0], h)
		} else {
			resolved = n.Resolve(h)
		}
		if err := current(); err != nil {
			return err
		}
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
			if err := current(); err != nil {
				return err
			}
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
