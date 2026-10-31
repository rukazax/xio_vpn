package mobile

import (
	"context"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"xio.local/rivet/internal/awgactivation"
)

// Entries remain reserved until native close AND the pending operation have
// joined. Unknown/stale handles cannot release another entry's capacity.
var awgHandles = struct {
	sync.Mutex
	next     int64
	creating bool
	entries  map[int64]*awgHandleEntry
}{entries: make(map[int64]*awgHandleEntry)}

type awgHandshakeOperation struct {
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	canceled bool // guarded by awgHandles
	doneOnce sync.Once
}

func (op *awgHandshakeOperation) finish() { op.doneOnce.Do(func() { close(op.done) }) }

type awgHandleEntry struct {
	device      *device.Device
	closeDevice func()
	closeOnce   sync.Once
	closed      chan struct{}
	closing     bool // guarded by awgHandles; one closer owns final retirement
	operation   *awgHandshakeOperation
	attempted   map[device.NoisePublicKey]bool
}

func (e *awgHandleEntry) close() { e.closeOnce.Do(e.closeDevice) }

func awgReserveCreation() bool {
	awgHandles.Lock()
	defer awgHandles.Unlock()
	if awgHandles.creating || len(awgHandles.entries) != 0 || awgHandles.next >= 2147483647 {
		return false
	}
	awgHandles.creating = true
	return true
}
func awgAbortCreation() {
	awgHandles.Lock()
	awgHandles.creating = false
	awgHandles.Unlock()
}
func awgPublishDevice(d *device.Device) int64 {
	awgHandles.Lock()
	defer awgHandles.Unlock()
	if !awgHandles.creating || len(awgHandles.entries) != 0 {
		return -1
	}
	awgHandles.next++
	handle := awgHandles.next
	awgHandles.entries[handle] = &awgHandleEntry{device: d, closeDevice: func() { awgCloseDevice(d) },
		closed: make(chan struct{}), attempted: make(map[device.NoisePublicKey]bool)}
	awgHandles.creating = false
	return handle
}
func awgDevice(handle int64) *device.Device {
	awgHandles.Lock()
	defer awgHandles.Unlock()
	e := awgHandles.entries[handle]
	if e == nil || e.closing {
		return nil
	}
	return e.device
}

// Called with awgHandles locked, after device close and operation join.
func awgRetireLocked(handle int64, e *awgHandleEntry) {
	if awgHandles.entries[handle] == e {
		delete(awgHandles.entries, handle)
		close(e.closed)
	}
}
func awgTurnOff(handle int64) {
	awgHandles.Lock()
	e := awgHandles.entries[handle]
	if e == nil {
		awgHandles.Unlock()
		return
	}
	if e.closing {
		done := e.closed
		awgHandles.Unlock()
		<-done
		return
	}
	e.closing = true
	op := e.operation
	if op != nil {
		op.canceled = true
		op.cancel()
	}
	awgHandles.Unlock()
	e.close() // no registry lock during close, IPC or worker joins
	if op != nil {
		<-op.done
	}
	awgHandles.Lock()
	awgRetireLocked(handle, e)
	awgHandles.Unlock()
}
func awgCancelHandshake(handle int64) {
	awgHandles.Lock()
	e := awgHandles.entries[handle]
	if e == nil {
		awgHandles.Unlock()
		return
	}
	if e.closing {
		done := e.closed
		awgHandles.Unlock()
		<-done
		return
	}
	op := e.operation
	if op != nil {
		op.canceled = true
		op.cancel()
	}
	awgHandles.Unlock()
	if op != nil {
		<-op.done
	}
}

// Success is linearized under the SAME lock as cancel/TurnOff. The result of
// Run alone is never enough: cancellation can win after its watcher has joined.
func awgFinishOperation(handle int64, e *awgHandleEntry, op *awgHandshakeOperation, runErr error) error {
	awgHandles.Lock()
	current := awgHandles.entries[handle] == e && e.operation == op
	if runErr == nil && (!current || e.closing || op.canceled || op.ctx.Err() != nil) {
		runErr = errAWGFallback
	}
	if runErr == nil {
		e.operation = nil
		op.finish()
		awgHandles.Unlock()
		return nil
	}
	ownsClose := current && !e.closing
	if ownsClose {
		e.closing = true
	}
	op.canceled = true
	op.cancel()
	awgHandles.Unlock()
	e.close() // also joins a close already owned by TurnOff; sync.Once serializes it
	awgHandles.Lock()
	if e.operation == op {
		e.operation = nil
	}
	op.finish() // TurnOff may be waiting here; never wait for e.closed in this path
	if ownsClose {
		awgRetireLocked(handle, e)
	}
	awgHandles.Unlock()
	return errAWGFallback
}
func awgHandshakeCandidates(handle int64, publicKey, endpoints string, timeoutMillis int64) error {
	key, candidates, err := awgactivation.Validate(publicKey, endpoints, timeoutMillis)
	if err != nil {
		return errAWGFallback
	}
	awgHandles.Lock()
	e := awgHandles.entries[handle]
	if handle < 1 || e == nil || e.closing || e.operation != nil || e.attempted[key] || e.device.LookupPeer(key) == nil {
		awgHandles.Unlock()
		return errAWGFallback
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMillis)*time.Millisecond)
	op := &awgHandshakeOperation{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	e.attempted[key] = true
	e.operation = op
	awgHandles.Unlock()
	runErr := awgactivation.Run(ctx, e.device, key, candidates)
	result := awgFinishOperation(handle, e, op, runErr)
	cancel()
	return result
}

// Bind close precedes Device.Close because a native IPC post-hook can hold
// ipcMutex while blocked in Send; Device.Close acquires that mutex first.
func awgCloseDevice(d *device.Device) {
	if d != nil {
		d.AbortInitialActivation()
	}
}
