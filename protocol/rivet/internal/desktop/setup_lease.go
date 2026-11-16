package desktop

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// setupLease linearizes effect admission/publication with DOWN. The gate is
// never held across an OS call: an admitted call is in flight, and the original
// runtime/network owner must join it before releasing its reservation.
// Detaching commits setup, not the lifetime of a winning transport.
type setupLease struct {
	gate     *sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
	now      func() time.Time
	valid    func() bool
	detached bool
}

func newSetupLease(gate *sync.Mutex, deadline time.Time, now func() time.Time, valid func() bool) *setupLease {
	ctx, cancel := context.WithTimeout(context.Background(), max(time.Duration(0), deadline.Sub(now())))
	return &setupLease{gate: gate, ctx: ctx, cancel: cancel, deadline: deadline, now: now, valid: valid}
}
func (s *setupLease) errLocked() error {
	if s.detached {
		return nil
	}
	if !s.valid() {
		return context.Canceled
	}
	if !s.now().Before(s.deadline) {
		return context.DeadlineExceeded
	}
	return s.ctx.Err()
}
func (s *setupLease) check() error {
	if s == nil {
		return nil
	}
	s.gate.Lock()
	defer s.gate.Unlock()
	return s.errLocked()
}
func (s *setupLease) admit(cap time.Duration) (context.Context, context.CancelFunc, error) {
	if s == nil {
		ctx, cancel := context.WithTimeout(context.Background(), cap)
		return ctx, cancel, nil
	}
	s.gate.Lock()
	defer s.gate.Unlock()
	if err := s.errLocked(); err != nil {
		return nil, func() {}, err
	}
	parent := s.ctx
	if s.detached {
		parent = context.Background()
	} else {
		cap = min(cap, s.deadline.Sub(s.now()))
	}
	ctx, cancel := context.WithTimeout(parent, cap)
	return ctx, cancel, nil
}
func (s *setupLease) effect(run func() error) error {
	_, done, err := s.admit(30 * time.Second)
	if err != nil {
		return err
	}
	defer done()
	return run() // Admission is before revoke, not a promise of kernel instant-cancel.
}
func (s *setupLease) publish(publish func()) error {
	if s == nil {
		publish()
		return nil
	}
	s.gate.Lock()
	defer s.gate.Unlock()
	if err := s.errLocked(); err != nil {
		return err
	}
	publish()
	return nil
}
func (s *setupLease) commit(publish func()) error {
	s.gate.Lock()
	defer s.gate.Unlock()
	if err := s.errLocked(); err != nil {
		return err
	}
	s.detached = true
	publish()
	s.cancel() // Only setup children; lifetime users acquire detached contexts.
	return nil
}
func setupLookup(s *setupLease, raw physicalLookup) physicalLookup {
	return func(parent context.Context, network, host, server string) ([]netip.Addr, error) {
		ctx, done, err := s.admit(1500 * time.Millisecond)
		if err != nil {
			return nil, err
		}
		defer done()
		stop := context.AfterFunc(parent, done)
		defer stop()
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		if deadline, ok := parent.Deadline(); ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
		return raw(ctx, network, host, server)
	}
}
func (s *setupLease) command(run commandRunner, name string, args ...string) ([]byte, error) {
	ctx, done, err := s.admit(10 * time.Second)
	if err != nil {
		return nil, err
	}
	defer done()
	if run != nil {
		return run(name, args...)
	}
	return runNetworkCommandContext(ctx, name, args...)
}
