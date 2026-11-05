/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * Additive, initiator-only authenticated completion observation.
 * It does not change the wire format, crypto, rate limits or retry timers.
 */

package device

import (
	"net/netip"
	"sort"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

const authenticatedInitiationRing = 8

// AuthenticatedInitiation is an immutable copy of one observed completion of
// an INITIATOR handshake response. It is published only after the responder's
// response has been cryptographically consumed and a symmetric keypair has
// been derived successfully.
//
// Sequence is a device-wide monotonic publication counter. It is the freshness
// token; do not use wall-clock time. Lifetime changes on start, stop and key
// material zeroing; a stale copy must never be accepted across a lifetime
// change. Source is the numeric source of the packet that carried the
// authenticated response (elem.endpoint), not the configured peer endpoint.
//
// This type does not report responder-side key confirmation. It is scoped to
// the one-shot initial initiator activation flow.
type AuthenticatedInitiation struct {
	Sequence   uint64
	Lifetime   uint64
	Initiation uint64
	PublicKey  NoisePublicKey
	Index      uint32
	Source     netip.AddrPort
}

// Matches reports whether this completion is fresh for the expected numeric
// candidate in the same lifetime. afterSequence is the sequence baseline taken
// before the attempt; equal or older completions are rejected.
func (e AuthenticatedInitiation) Matches(expected netip.AddrPort, lifetime, afterSequence uint64) bool {
	if e.Sequence <= afterSequence || e.Lifetime != lifetime || !e.Source.IsValid() || !expected.IsValid() {
		return false
	}
	expected = netip.AddrPortFrom(expected.Addr().Unmap(), expected.Port())
	return e.Source == expected
}

type observationState struct {
	sync.Mutex
	lifetime uint64
	stopped  bool
	ring     [authenticatedInitiationRing]AuthenticatedInitiation
	count    int
	next     int
}

func (peer *Peer) observationInit() {
	peer.observation.Lock()
	peer.observation.lifetime = 1
	peer.observation.stopped = true
	peer.observation.count = 0
	peer.observation.next = 0
	for i := range peer.observation.ring {
		peer.observation.ring[i] = AuthenticatedInitiation{}
	}
	peer.observation.Unlock()
}

func (peer *Peer) observationStart() {
	peer.observation.Lock()
	peer.observation.lifetime++
	peer.observation.stopped = false
	peer.observation.count = 0
	peer.observation.next = 0
	for i := range peer.observation.ring {
		peer.observation.ring[i] = AuthenticatedInitiation{}
	}
	peer.observation.Unlock()
}

func (peer *Peer) observationZero() {
	peer.observation.Lock()
	peer.observation.lifetime++
	peer.observation.count = 0
	peer.observation.next = 0
	for i := range peer.observation.ring {
		peer.observation.ring[i] = AuthenticatedInitiation{}
	}
	peer.observation.Unlock()
}

func (peer *Peer) observationStop() {
	peer.observation.Lock()
	peer.observation.lifetime++
	peer.observation.stopped = true
	peer.observation.count = 0
	peer.observation.next = 0
	for i := range peer.observation.ring {
		peer.observation.ring[i] = AuthenticatedInitiation{}
	}
	peer.observation.Unlock()
}

// AuthenticatedLifetime returns the current observation lifetime of the peer.
// Take a baseline before an attempt and pass it to Matches.
func (peer *Peer) AuthenticatedLifetime() uint64 {
	peer.observation.Lock()
	defer peer.observation.Unlock()
	return peer.observation.lifetime
}

// AuthenticatedSequence returns the newest publication sequence retained for
// this peer. It is a baseline helper; it is not proof by itself.
func (peer *Peer) AuthenticatedSequence() uint64 {
	peer.observation.Lock()
	defer peer.observation.Unlock()
	var newest uint64
	for _, event := range peer.observation.ring {
		if event.Sequence > newest {
			newest = event.Sequence
		}
	}
	return newest
}

// AuthenticatedInitiationsSince copies retained events newer than sequence into
// dst. The returned slice is owned by the caller. History is bounded; a missing
// event is not evidence that no completion happened.
func (peer *Peer) AuthenticatedInitiationsSince(sequence uint64, dst []AuthenticatedInitiation) []AuthenticatedInitiation {
	peer.observation.Lock()
	defer peer.observation.Unlock()
	out := dst[:0]
	for _, event := range peer.observation.ring {
		if event.Sequence > sequence {
			out = append(out, event)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

func (peer *Peer) authenticatedResponseKey() (NoisePublicKey, bool) {
	peer.handshake.mutex.Lock()
	defer peer.handshake.mutex.Unlock()
	return peer.handshake.remoteStatic, true
}

// publishAuthenticatedInitiation is called only from the response receive path,
// after beginSymmetricSessionForResponse succeeded. derived is the exact keypair
// produced by that derivation; its localIndex must still identify the response
// that was consumed. initiation pins the exact initiation epoch.
func (peer *Peer) publishAuthenticatedInitiation(lifetime, initiation uint64, index uint32, derived *Keypair, source conn.Endpoint) bool {
	if peer == nil || derived == nil || derived.localIndex != index {
		return false
	}
	key, ok := peer.authenticatedResponseKey()
	if !ok {
		return false
	}
	sourceAddr, ok := numericEndpoint(source)
	if !ok {
		return false
	}
	peer.observation.Lock()
	defer peer.observation.Unlock()
	if peer.observation.stopped || peer.observation.lifetime != lifetime {
		return false
	}
	if peer.device == nil || peer.device.isClosed() {
		return false
	}
	sequence := peer.device.observationSequence.Add(1)
	event := AuthenticatedInitiation{
		Sequence:   sequence,
		Lifetime:   lifetime,
		Initiation: initiation,
		PublicKey:  key,
		Index:      index,
		Source:     sourceAddr,
	}
	peer.observation.ring[peer.observation.next] = event
	peer.observation.next = (peer.observation.next + 1) % authenticatedInitiationRing
	if peer.observation.count < authenticatedInitiationRing {
		peer.observation.count++
	}
	return true
}

func numericEndpoint(endpoint conn.Endpoint) (netip.AddrPort, bool) {
	if endpoint == nil {
		return netip.AddrPort{}, false
	}
	address, err := netip.ParseAddrPort(endpoint.DstToString())
	if err != nil || !address.IsValid() || address.Port() == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(address.Addr().Unmap(), address.Port()), true
}
