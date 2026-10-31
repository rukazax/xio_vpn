package mobile

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

func registryEntry(t *testing.T, closeDevice func()) (int64, *awgHandleEntry) {
	t.Helper()
	awgHandles.Lock()
	if len(awgHandles.entries) != 0 || awgHandles.creating {
		awgHandles.Unlock()
		t.Fatal("registry not drained")
	}
	awgHandles.next++
	handle := awgHandles.next
	e := &awgHandleEntry{closeDevice: closeDevice, closed: make(chan struct{}), attempted: make(map[device.NoisePublicKey]bool)}
	awgHandles.entries[handle] = e
	awgHandles.Unlock()
	t.Cleanup(func() { awgTurnOff(handle) })
	return handle, e
}
func registryOperation(e *awgHandleEntry) *awgHandshakeOperation {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	op := &awgHandshakeOperation{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	awgHandles.Lock()
	e.operation = op
	awgHandles.Unlock()
	return op
}
func awaitRegistry(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("registry work did not join")
	}
}
func TestAwgRegistryCancelAfterRunBeforePublication(t *testing.T) {
	var closes atomic.Int32
	handle, e := registryEntry(t, func() { closes.Add(1) })
	op := registryOperation(e)
	defer op.cancel()
	canceled := make(chan struct{})
	go func() { awgCancelHandshake(handle); close(canceled) }()
	awaitRegistry(t, op.ctx.Done())
	if err := awgFinishOperation(handle, e, op, nil); err == nil {
		t.Fatal("cancel lost after native Run success")
	}
	awaitRegistry(t, canceled)
	awaitRegistry(t, e.closed)
	if closes.Load() != 1 {
		t.Fatal("device close not exactly once")
	}
}
func TestAwgRegistryTurnOffReservesUntilCloseAndJoin(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var closes atomic.Int32
	handle, e := registryEntry(t, func() { closes.Add(1); close(entered); <-release })
	finished := make(chan struct{})
	go func() { awgTurnOff(handle); close(finished) }()
	awaitRegistry(t, entered)
	if awgReserveCreation() {
		awgAbortCreation()
		t.Fatal("new device admitted during native close")
	}
	second, cancelled := make(chan struct{}), make(chan struct{})
	go func() { awgTurnOff(handle); close(second) }()
	go func() { awgCancelHandshake(handle); close(cancelled) }()
	select {
	case <-finished:
		t.Fatal("TurnOff returned before close")
	default:
	}
	once.Do(func() { close(release) })
	awaitRegistry(t, finished)
	awaitRegistry(t, second)
	awaitRegistry(t, cancelled)
	awaitRegistry(t, e.closed)
	if closes.Load() != 1 {
		t.Fatal("repeated TurnOff closed twice")
	}
	if !awgReserveCreation() {
		t.Fatal("capacity not released after join")
	}
	awgTurnOff(handle) // stale handle must not release the creation reservation
	if awgReserveCreation() {
		awgAbortCreation()
		t.Fatal("stale handle cleared newer creation")
	}
	awgAbortCreation()
}
func TestAwgRegistryFailureKeepsReservation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	handle, e := registryEntry(t, func() { close(entered); <-release })
	op := registryOperation(e)
	defer op.cancel()
	result := make(chan error, 1)
	go func() { result <- awgFinishOperation(handle, e, op, errors.New("native failure")) }()
	awaitRegistry(t, entered)
	if awgReserveCreation() {
		awgAbortCreation()
		t.Fatal("new device admitted before failed device close")
	}
	cancelled := make(chan struct{})
	go func() { awgCancelHandshake(handle); close(cancelled) }()
	select {
	case <-op.done:
		t.Fatal("done before close")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("failure became success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failure did not join")
	}
	awaitRegistry(t, cancelled)
	awaitRegistry(t, e.closed)
}
func TestAwgRegistryTurnOffWinsBeforeNativeResult(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	handle, e := registryEntry(t, func() { close(entered); <-release })
	op := registryOperation(e)
	defer op.cancel()
	turnedOff := make(chan struct{})
	go func() { awgTurnOff(handle); close(turnedOff) }()
	awaitRegistry(t, entered)
	result := make(chan error, 1)
	go func() { result <- awgFinishOperation(handle, e, op, nil) }()
	once.Do(func() { close(release) })
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("dead handle accepted as success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not join")
	}
	awaitRegistry(t, turnedOff)
	awaitRegistry(t, e.closed)
}
func TestAwgRegistryCompletedActivationNotCanceled(t *testing.T) {
	var closes atomic.Int32
	handle, e := registryEntry(t, func() { closes.Add(1) })
	op := registryOperation(e)
	defer op.cancel()
	if err := awgFinishOperation(handle, e, op, nil); err != nil {
		t.Fatal(err)
	}
	awgCancelHandshake(handle)
	if closes.Load() != 0 {
		t.Fatal("cancel closed a committed tunnel")
	}
	if awgReserveCreation() {
		awgAbortCreation()
		t.Fatal("active device capacity released")
	}
	awgTurnOff(handle)
	if closes.Load() != 1 {
		t.Fatal("device not closed exactly once")
	}
}
