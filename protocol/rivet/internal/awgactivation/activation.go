// Package awgactivation performs a one-shot initial AmneziaWG handshake over a
// bounded list of numeric endpoints.
//
// It changes only the peer endpoint between attempts: the peer, its keypairs,
// handshake counters, retry timers, routes, obfuscation settings and bind are
// preserved. Success requires a typed authenticated completion reported by the
// library for the exact numeric packet source of the current candidate; a
// timestamp, an unchanged counter, device Up or any IpcGet field is not proof.
package awgactivation

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

const (
	// MaxCandidates bounds one activation attempt.
	MaxCandidates = 16
	// MaxTimeoutMillis bounds the whole activation attempt.
	MaxTimeoutMillis = 60000
	// maxConfigBytes bounds the comma-separated candidate list.
	maxConfigBytes = 2048
	pollInterval   = 25 * time.Millisecond
)

var (
	// ErrInvalid reports a rejected candidate list, key or deadline.
	ErrInvalid = errors.New("awg activation: invalid candidate set")
	// ErrUnavailable reports that no candidate produced an authenticated
	// completion from its own packet source within the deadline.
	ErrUnavailable = errors.New("awg activation: initial authenticated handshake unavailable")
)

// Validate parses a public key and a comma-separated numeric endpoint list.
// Only numeric addresses are accepted so no DNS state is needed here and an
// injected IPC fragment can never reach the device configuration.
func Validate(key, raw string, timeoutMillis int64) (device.NoisePublicKey, []netip.AddrPort, error) {
	var public device.NoisePublicKey
	if len(key) != 64 || timeoutMillis < 1 || timeoutMillis > MaxTimeoutMillis || len(raw) == 0 || len(raw) > maxConfigBytes {
		return public, nil, ErrInvalid
	}
	decoded, err := hex.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return public, nil, ErrInvalid
	}
	copy(public[:], decoded)
	if public == (device.NoisePublicKey{}) {
		return public, nil, ErrInvalid
	}
	values := strings.Split(raw, ",")
	if len(values) == 0 || len(values) > MaxCandidates {
		return public, nil, ErrInvalid
	}
	addresses := make([]netip.AddrPort, 0, len(values))
	seen := make(map[netip.AddrPort]bool, len(values))
	for _, value := range values {
		a, err := netip.ParseAddrPort(value)
		if err != nil || a.Port() == 0 {
			return public, nil, ErrInvalid
		}
		addr := a.Addr().Unmap()
		if !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() ||
			(!addr.IsGlobalUnicast() && !addr.IsLoopback()) {
			return public, nil, ErrInvalid
		}
		a = netip.AddrPortFrom(addr.Unmap(), a.Port())
		if !seen[a] {
			seen[a] = true
			addresses = append(addresses, a)
		}
	}
	if len(addresses) == 0 {
		return public, nil, ErrInvalid
	}
	return public, addresses, nil
}

// Run activates a single peer over candidates in order and returns nil only
// after the exact response packet source has been authenticated.
// Invalid arguments are rejected before device ownership is assumed.
//
// The caller owns device d. A failed initial activation closes it so no send
// can outlive the attempt; a successful activation leaves the tunnel running.
func Run(ctx context.Context, d *device.Device, key device.NoisePublicKey, candidates []netip.AddrPort) error {
	if ctx == nil || d == nil || key == (device.NoisePublicKey{}) || len(candidates) == 0 || len(candidates) > MaxCandidates {
		return ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > MaxTimeoutMillis*time.Millisecond {
		return ErrInvalid
	}
	normalized := make([]netip.AddrPort, 0, len(candidates))
	seen := make(map[netip.AddrPort]bool)
	for _, candidate := range candidates {
		if !candidate.IsValid() || candidate.Port() == 0 {
			return ErrInvalid
		}
		candidate = netip.AddrPortFrom(candidate.Addr().Unmap(), candidate.Port())
		a := candidate.Addr()
		if a.Zone() != "" || (!a.IsGlobalUnicast() && !a.IsLoopback()) {
			return ErrInvalid
		}
		if !seen[candidate] {
			seen[candidate] = true
			normalized = append(normalized, candidate)
		}
	}
	candidates = normalized
	peer := d.LookupPeer(key)
	if peer == nil {
		return ErrUnavailable
	}
	// The lifetime and every per-candidate baseline are captured before that
	// candidate's endpoint change: a completion that already exists, or one
	// retained from an earlier candidate, must never satisfy this attempt.
	lifetime := peer.AuthenticatedLifetime()

	var closeOnce sync.Once
	closeAttempt := func() {
		closeOnce.Do(func() {
			// Device.Close takes ipcMutex before BindClose in the pinned library.
			// Abort closes the immutable bind FIRST without using Bind(), whose
			// accessor also needs the net lock held by a blocked SendBuffers.
			d.AbortInitialActivation()
		})
	}
	current := func() bool { return d.LookupPeer(key) == peer && peer.AuthenticatedLifetime() == lifetime }
	finished := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			// Unblocks a native Bind.Send that would otherwise outlive the attempt.
			closeAttempt()
		case <-finished:
		}
	}()
	stopped, succeeded := false, false
	stopWatcher := func() {
		if stopped {
			return
		}
		stopped = true
		close(finished)
		<-watcherDone
	}
	defer func() {
		stopWatcher()
		if !succeeded {
			closeAttempt()
		}
	}()

	// A retransmission needs one rekey interval to reach the new endpoint.
	minimumDwell := peer.InitialActivationRetryInterval() + time.Second
	events := make([]device.AuthenticatedInitiation, 0, 8)
	for index, candidate := range candidates {
		if err := contextError(ctx); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrUnavailable
		}
		slice := remaining / time.Duration(len(candidates)-index)
		if slice < minimumDwell {
			slice = minimumDwell
		}
		if slice > remaining {
			slice = remaining
		}
		until := time.Now().Add(slice)
		// Per-candidate freshness: a completion retained from an earlier
		// candidate must not be attributed to the endpoint installed now.
		candidateBaseline := peer.AuthenticatedSequence()
		if !current() {
			return ErrUnavailable
		}
		// Typed endpoint-only setter deliberately avoids IpcSet's SendStagedPackets
		// post-hook (which can reset initial handshake counters with queued traffic).
		if err := peer.SetEndpointForInitialActivation(candidate); err != nil {
			return ErrUnavailable
		}
		if err := peer.SendHandshakeInitiation(true); err != nil {
			if ctxErr := contextError(ctx); ctxErr != nil {
				return ctxErr
			}
			continue // a real send error is not proof; try the next candidate
		}
		nextRequest := time.Now().Add(100 * time.Millisecond)
		for {
			if err := contextError(ctx); err != nil {
				return err
			}
			if !current() {
				return ErrUnavailable
			}
			events = peer.AuthenticatedInitiationsSince(candidateBaseline, events[:0])
			for _, event := range events {
				if event.PublicKey != key || event.Initiation == 0 {
					continue
				}
				if !event.Matches(candidate, lifetime, candidateBaseline) {
					continue
				}
				// Stop the watcher before publishing success so a late
				// cancellation cannot close the device behind the caller.
				stopWatcher()
				if err := contextError(ctx); err != nil {
					return err
				}
				if !current() {
					return ErrUnavailable
				}
				succeeded = true
				return nil
			}
			// A late response from another source can stop the native retransmit
			// timer. Bounded retry requests still use the native rate gate and never
			// reset its counters; no asynchronous sends are launched here.
			if !time.Now().Before(nextRequest) {
				if err := peer.SendHandshakeInitiation(true); err != nil {
					if ctxErr := contextError(ctx); ctxErr != nil {
						return ctxErr
					}
					break
				}
				nextRequest = time.Now().Add(100 * time.Millisecond)
			}
			if !time.Now().Before(deadline) {
				return ErrUnavailable
			}
			if !time.Now().Before(until) {
				break
			}
			wait := min(pollInterval, time.Until(until), time.Until(deadline))
			if wait <= 0 {
				continue
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return contextError(ctx)
			case <-timer.C:
			}
		}
	}
	return ErrUnavailable
}

// contextError reports cancellation, but normalizes the attempt deadline to
// ErrUnavailable so consumers distinguish "candidate set exhausted" from an
// explicit caller cancellation.
func contextError(ctx context.Context) error {
	switch err := ctx.Err(); {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return err
	default:
		return ErrUnavailable
	}
}
