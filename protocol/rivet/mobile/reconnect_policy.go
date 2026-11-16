package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"xio.local/rivet/internal/rivet"
)

const maxRound = 30 * time.Second
const maxRecoveryRounds = 3

// Runtime intent is not part of the exported/server profile schema.
type reconnectPolicy struct {
	Mode        string `json:"mode"`
	RoundMillis int64  `json:"roundMillis"`
}

func parseReconnectPolicy(raw string) (reconnectPolicy, error) {
	p := reconnectPolicy{Mode: "automatic", RoundMillis: 30000}
	if raw == "" {
		return p, nil
	} // Compatibility for existing native callers.
	if len(raw) > 1024 {
		return p, rivet.ErrProtocol
	}
	p.Mode = "" // Explicit malformed/missing intent never silently becomes automatic.
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, rivet.ErrProtocol
	}
	if d.Decode(new(any)) != io.EOF || (p.Mode != "automatic" && p.Mode != "selectedOnly") || p.RoundMillis < 1 || p.RoundMillis > 30000 {
		return p, rivet.ErrProtocol
	}
	return p, nil
}

// ConnectionPolicyMode validates intent before a desktop caller opens a device.
// Empty policy preserves the legacy automatic API.
func ConnectionPolicyMode(raw string) (string, error) {
	p, err := parseReconnectPolicy(raw)
	return p.Mode, err
}

type nativeSession interface {
	Close()
	ReadPacket() ([]byte, error)
	SendPacket([]byte) error
	Counts() (uint64, uint64, int64)
}

type recoveryHooks struct {
	now     func() time.Time
	wait    func(context.Context, time.Duration) error
	timeout func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	dial    func(lifetime, establishment context.Context, cfg rivet.ClientConfig, p Protector, budget time.Duration) (nativeSession, error)
}

func realRecoveryHooks() recoveryHooks {
	return recoveryHooks{
		now:     time.Now,
		timeout: context.WithTimeout,
		wait: func(ctx context.Context, delay time.Duration) error {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
		dial: func(lifetime, establishment context.Context, cfg rivet.ClientConfig, p Protector, budget time.Duration) (nativeSession, error) {
			return dialPhysical(lifetime, establishment, cfg, p, budget)
		},
	}
}

// One synchronous dial owner. Every phase consumes the same round deadline;
// returning also joins the cooperative dial, never detaches it to start another.
func recoveryRound(parent context.Context, cfg rivet.ClientConfig, preferred string, p Protector, policy reconnectPolicy, hooks recoveryHooks) (nativeSession, rivet.ClientConfig, error) {
	budget := min(time.Duration(policy.RoundMillis)*time.Millisecond, maxRound)
	deadline := hooks.now().Add(budget)
	ctx, cancel := hooks.timeout(parent, budget)
	defer cancel()
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, cfg, err
		}
		if attempt > 0 {
			delay := min(time.Duration(1<<min(attempt-1, 3))*time.Second, deadline.Sub(hooks.now()))
			if delay <= 0 {
				return nil, cfg, context.DeadlineExceeded
			}
			if err := hooks.wait(ctx, delay); err != nil {
				return nil, cfg, err
			}
		}
		left := deadline.Sub(hooks.now())
		if left <= 0 {
			return nil, cfg, context.DeadlineExceeded
		}
		candidate := cfg
		candidate.Protocol = preferred // Attempt zero always honors the selected transport.
		if policy.Mode == "automatic" && attempt%2 == 1 {
			if preferred == "rivet-h3" {
				candidate.Protocol = "rivet-s1"
			} else {
				candidate.Protocol = "rivet-h3"
			}
		}
		phase := min(10*time.Second, left)
		dialCtx, dialCancel := hooks.timeout(ctx, phase)
		session, err := hooks.dial(parent, dialCtx, candidate, p, phase)
		if err == nil {
			err = dialCtx.Err()
		}
		if err == nil && !hooks.now().Before(deadline) {
			err = context.DeadlineExceeded
		}
		dialCancel()
		if err == nil && session != nil {
			return session, candidate, nil
		}
		if session != nil {
			session.Close()
		}
		if err == nil {
			return nil, cfg, errors.New("rivet: missing session")
		}
		if parent.Err() != nil {
			return nil, cfg, parent.Err()
		}
	}
}
