/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * Pure/in-memory observation tests. No OS sockets, TUN devices, drivers,
 * ADB, VMs or external network are used.
 */

package device

import (
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
)

func hexKey(k NoisePublicKey) string { return hex.EncodeToString(k[:]) }

func waitObservation(t *testing.T, peer *Peer, after uint64) []AuthenticatedInitiation {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		events := peer.AuthenticatedInitiationsSince(after, nil)
		if len(events) > 0 {
			return events
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for authenticated completion")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestObservationAuthenticatedInitiatorCompletion(t *testing.T) {
	pair := genTestPair(t, false)
	a, b := &pair[0], &pair[1]
	keyB := b.dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("initiator peer not found")
	}
	// Send the initiation through the IPv4 fixture channel while the response
	// arrives on the IPv6 channel. The configured endpoint (1) therefore differs
	// deterministically from the actual response source (3).
	peer.endpoint.Lock()
	peer.endpoint.val = bindtest.ChannelEndpoint(1)
	configured := peer.endpoint.val.DstToString()
	peer.endpoint.Unlock()
	lifetime := peer.AuthenticatedLifetime()
	baseline := peer.AuthenticatedSequence()

	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("send handshake initiation: %v", err)
	}
	events := waitObservation(t, peer, baseline)
	event := events[len(events)-1]
	if event.Lifetime != lifetime {
		t.Fatalf("lifetime = %d, want %d", event.Lifetime, lifetime)
	}
	if event.PublicKey != keyB {
		t.Fatalf("public key = %x, want %x", event.PublicKey, keyB)
	}
	if event.Index == 0 {
		t.Fatal("zero initiation index")
	}
	// bindtest gives device A the fixed receive endpoint 127.0.0.1:3. Device B's
	// configured endpoint is 127.0.0.1:2 or :4, so this proves Source is the
	// packet endpoint, not peer.endpoint.val.
	if event.Source.String() != "127.0.0.1:3" {
		t.Fatalf("source = %s, want 127.0.0.1:3", event.Source)
	}
	if event.Source.String() == configured {
		t.Fatalf("source equals configured endpoint %s; fixture does not prove actual source", configured)
	}
	if !event.Matches(event.Source, lifetime, baseline) {
		t.Fatal("fresh actual-source event did not match")
	}
}

// NOTE: this test is a PURE MODEL of AuthenticatedInitiation.Matches. It does
// not create network packets or cryptographic responses. The real in-memory
// crypto interleavings are covered by TestObservationRealCryptoStaleCommit and
// TestObservationDelayedCompletionAfterNewInitiation.
func TestObservationMatchesModelLateARejectedForB(t *testing.T) {
	for _, pair := range [][2]string{
		{"203.0.113.42:51820", "[2001:db8::42]:51820"},
		{"[2001:db8::42]:51820", "203.0.113.42:51820"},
	} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) {
			a := netip.MustParseAddrPort(pair[0])
			b := netip.MustParseAddrPort(pair[1])
			const lifetime = 7
			const baseline = 10
			lateA := AuthenticatedInitiation{Sequence: 11, Lifetime: lifetime, Source: a}
			freshB := AuthenticatedInitiation{Sequence: 12, Lifetime: lifetime, Source: b}
			if lateA.Matches(b, lifetime, baseline) {
				t.Fatal("late A accepted for expected B")
			}
			if freshB.Matches(b, lifetime, baseline) != true {
				t.Fatal("fresh B rejected")
			}
			if freshB.Matches(a, lifetime, baseline) {
				t.Fatal("fresh B accepted for expected A")
			}
			if !lateA.Matches(a, lifetime, baseline) {
				t.Fatal("same-candidate A rejected")
			}
			if lateA.Matches(a, lifetime+1, baseline) {
				t.Fatal("old lifetime accepted")
			}
			if lateA.Matches(a, lifetime, 11) {
				t.Fatal("event at baseline accepted")
			}
		})
	}
}

func TestObservationNoPublishOnInvalidDerivation(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	lifetime := peer.AuthenticatedLifetime()
	baseline := peer.AuthenticatedSequence()

	if peer.publishAuthenticatedInitiation(lifetime, 1, 1, nil, nil) {
		t.Fatal("published without derived keypair")
	}
	derived := &Keypair{localIndex: 2}
	if peer.publishAuthenticatedInitiation(lifetime, 1, 1, derived, bindtest.ChannelEndpoint(3)) {
		t.Fatal("published with mismatched keypair identity")
	}
	if got := peer.AuthenticatedInitiationsSince(baseline, nil); len(got) != 0 {
		t.Fatalf("published %d events on invalid derivation", len(got))
	}
}

func TestObservationInvalidResponseDoesNotPublish(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	baseline := peer.AuthenticatedSequence()
	if got, _, _ := peer.device.consumeMessageResponse(&MessageResponse{}); got != nil {
		t.Fatal("zero response was authenticated")
	}
	if _, err := peer.beginSymmetricSession(0, 0, false); err == nil {
		t.Fatal("key derivation succeeded without a consumed response")
	}
	if got := peer.AuthenticatedInitiationsSince(baseline, nil); len(got) != 0 {
		t.Fatalf("invalid response/derive failure published %d events", len(got))
	}
}

func TestObservationCommitRejectsStaleIdentity(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	if _, err := peer.device.CreateMessageInitiation(peer); err != nil {
		t.Fatalf("create initiation A: %v", err)
	}
	peer.handshake.mutex.Lock()
	epochA, indexA := peer.handshake.initiationEpoch, peer.handshake.localIndex
	hashA, chainA := peer.handshake.hash, peer.handshake.chainKey
	peer.handshake.mutex.Unlock()

	if _, err := peer.device.CreateMessageInitiation(peer); err != nil {
		t.Fatalf("create initiation B: %v", err)
	}
	peer.handshake.mutex.Lock()
	epochB, indexB := peer.handshake.initiationEpoch, peer.handshake.localIndex
	hashB, chainB := peer.handshake.hash, peer.handshake.chainKey
	peer.handshake.mutex.Unlock()
	if epochA == epochB || indexA == indexB {
		t.Fatal("fixture did not create distinct initiation identities")
	}

	if peerCommitResponse(peer, epochA, indexA, &MessageResponse{Type: MessageResponseType, Sender: 1}, hashA, chainA) {
		t.Fatal("stale response commit accepted")
	}
	peer.handshake.mutex.Lock()
	defer peer.handshake.mutex.Unlock()
	if peer.handshake.state != handshakeInitiationCreated || peer.handshake.initiationEpoch != epochB || peer.handshake.localIndex != indexB {
		t.Fatal("stale commit mutated newer handshake identity/state")
	}
	if peer.handshake.hash != hashB || peer.handshake.chainKey != chainB {
		t.Fatal("stale commit mutated newer handshake key material")
	}
}

func TestObservationBeginRejectsStaleIdentity(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("send: %v", err)
	}
	events := waitObservation(t, peer, peer.AuthenticatedSequence())
	event := events[len(events)-1]
	peer.keypairs.Lock()
	current := peer.keypairs.current
	peer.keypairs.Unlock()

	if _, err := peer.device.CreateMessageInitiation(peer); err != nil {
		t.Fatalf("create newer initiation: %v", err)
	}
	peer.handshake.mutex.Lock()
	peer.handshake.state = handshakeResponseConsumed // model a newer committed response
	epochB, indexB := peer.handshake.initiationEpoch, peer.handshake.localIndex
	peer.handshake.mutex.Unlock()

	derived, err := peer.beginSymmetricSessionForResponse(event.Initiation, event.Index)
	if err == nil || derived != nil {
		t.Fatal("stale derivation accepted")
	}
	peer.keypairs.Lock()
	unchanged := peer.keypairs.current == current
	peer.keypairs.Unlock()
	if !unchanged {
		t.Fatal("stale derivation rotated keypairs")
	}
	peer.handshake.mutex.Lock()
	defer peer.handshake.mutex.Unlock()
	if peer.handshake.state != handshakeResponseConsumed || peer.handshake.initiationEpoch != epochB || peer.handshake.localIndex != indexB {
		t.Fatal("stale derivation mutated newer handshake")
	}
}

func TestObservationStalePublicationRejectedAfterStopStart(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	lifetime := peer.AuthenticatedLifetime()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("send: %v", err)
	}
	events := waitObservation(t, peer, peer.AuthenticatedSequence())
	event := events[len(events)-1]
	peer.keypairs.Lock()
	derived := peer.keypairs.current
	peer.keypairs.Unlock()
	if derived == nil {
		t.Fatal("missing keypair for stale-publication fixture")
	}

	peer.Stop()
	peer.Start()
	if peer.AuthenticatedLifetime() == lifetime {
		t.Fatal("lifetime did not change on stop/start")
	}
	if got := peer.AuthenticatedInitiationsSince(0, nil); len(got) != 0 {
		t.Fatalf("old history survived stop/start: %d", len(got))
	}
	if peer.publishAuthenticatedInitiation(lifetime, event.Initiation, event.Index, derived, bindtest.ChannelEndpoint(3)) {
		t.Fatal("stale in-flight publication accepted after stop/start")
	}
}

func TestObservationNoEventAfterClose(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitObservation(t, peer, peer.AuthenticatedSequence())
	baseline := peer.AuthenticatedSequence()
	a.dev.Close()
	if got := peer.AuthenticatedInitiationsSince(baseline, nil); len(got) != 0 {
		t.Fatalf("events visible after close: %d", len(got))
	}
}

func TestObservationRingBoundedAndSequenceMonotonic(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	lifetime := peer.AuthenticatedLifetime()
	derived := &Keypair{localIndex: 1}
	for i := 0; i < authenticatedInitiationRing*3; i++ {
		if !peer.publishAuthenticatedInitiation(lifetime, 1, 1, derived, bindtest.ChannelEndpoint(3)) {
			t.Fatalf("publish %d rejected", i)
		}
	}
	events := peer.AuthenticatedInitiationsSince(0, nil)
	if len(events) != authenticatedInitiationRing {
		t.Fatalf("ring length = %d, want %d", len(events), authenticatedInitiationRing)
	}
	for i := 1; i < len(events); i++ {
		if events[i].Sequence <= events[i-1].Sequence {
			t.Fatal("sequence not strictly increasing")
		}
	}
	if got := peer.AuthenticatedSequence(); got != events[len(events)-1].Sequence {
		t.Fatalf("newest sequence = %d, want %d", got, events[len(events)-1].Sequence)
	}
}

func TestObservationRateLimitedSendDoesNotPublish(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("first send: %v", err)
	}
	waitObservation(t, peer, peer.AuthenticatedSequence())
	baseline := peer.AuthenticatedSequence()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("rate-limited legacy false returned error: %v", err)
	}
	if err := peer.SendHandshakeInitiation(true); err != nil {
		t.Fatalf("rate-limited legacy true returned error: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := peer.AuthenticatedInitiationsSince(baseline, nil); len(got) != 0 {
		t.Fatalf("rate-limited send published %d events", len(got))
	}
}

// TestObservationEndpointOnlyIpcSetPreservesPeerState proves that the consumer
// contract (public_key + update_only + endpoint) mutates only peer.endpoint and
// preserves identity, keypairs, counters, timers, PSK, allowed IPs and bind.
func TestObservationEndpointOnlyIpcSetPreservesPeerState(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	// Create a real keypair so pointer identity is meaningful.
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitObservation(t, peer, peer.AuthenticatedSequence())

	peer.handshake.mutex.Lock()
	lastSent := time.Now().Add(-2 * time.Minute)
	peer.handshake.lastSentHandshake = lastSent
	psk := peer.handshake.presharedKey
	peer.handshake.mutex.Unlock()
	peer.timers.handshakeAttempts.Store(7)
	peer.timers.maxHandshakeAttempts.Store(3)
	keepalive := peer.persistentKeepaliveInterval.Load()
	peer.keypairs.Lock()
	current, previous, next := peer.keypairs.current, peer.keypairs.previous, peer.keypairs.next.Load()
	peer.keypairs.Unlock()
	if current == nil {
		t.Fatal("no current keypair")
	}
	var allowedBefore []netip.Prefix
	a.dev.allowedips.EntriesForPeer(peer, func(p netip.Prefix) bool {
		allowedBefore = append(allowedBefore, p)
		return true
	})
	bindBefore := a.dev.Bind()

	update := "public_key=" + hexKey(keyB) + "\nupdate_only=true\nendpoint=127.0.0.1:9\n"
	if err := a.dev.IpcSet(update); err != nil {
		t.Fatalf("endpoint-only IpcSet: %v", err)
	}

	if got := a.dev.LookupPeer(keyB); got != peer {
		t.Fatal("peer identity changed")
	}
	peer.keypairs.Lock()
	if peer.keypairs.current != current || peer.keypairs.previous != previous || peer.keypairs.next.Load() != next {
		t.Fatal("keypair pointers changed")
	}
	peer.keypairs.Unlock()
	if got := peer.timers.handshakeAttempts.Load(); got != 7 {
		t.Fatalf("handshakeAttempts = %d, want 7", got)
	}
	if got := peer.timers.maxHandshakeAttempts.Load(); got != 3 {
		t.Fatalf("maxHandshakeAttempts = %d, want 3", got)
	}
	peer.handshake.mutex.Lock()
	gotLastSent, gotPSK := peer.handshake.lastSentHandshake, peer.handshake.presharedKey
	peer.handshake.mutex.Unlock()
	if !gotLastSent.Equal(lastSent) {
		t.Fatalf("lastSentHandshake changed: %v -> %v", lastSent, gotLastSent)
	}
	if gotPSK != psk {
		t.Fatal("PSK changed")
	}
	if got := peer.persistentKeepaliveInterval.Load(); got != keepalive {
		t.Fatal("persistent keepalive changed")
	}
	var allowedAfter []netip.Prefix
	a.dev.allowedips.EntriesForPeer(peer, func(p netip.Prefix) bool {
		allowedAfter = append(allowedAfter, p)
		return true
	})
	if len(allowedBefore) != len(allowedAfter) {
		t.Fatalf("allowed IP count changed: %d -> %d", len(allowedBefore), len(allowedAfter))
	}
	for i := range allowedBefore {
		if allowedBefore[i] != allowedAfter[i] {
			t.Fatal("allowed IP changed")
		}
	}
	if a.dev.Bind() != bindBefore {
		t.Fatal("bind identity changed")
	}
	peer.endpoint.Lock()
	configured := peer.endpoint.val.DstToString()
	peer.endpoint.Unlock()
	if configured != "127.0.0.1:9" {
		t.Fatalf("endpoint = %s, want 127.0.0.1:9", configured)
	}
}

// TestObservationSendRetryPreservesCountersAndLegacyFalseResets documents the
// EXACT send behavior: legacy true (native retry) preserves counters while
// rate-limited; legacy false resets them before its rate-limit check. Consumers
// for one-shot activation must use true, not false.
func TestObservationSendRetryPreservesCountersAndLegacyFalseResets(t *testing.T) {
	pair := genTestPair(t, false)
	a := &pair[0]
	keyB := pair[1].dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()
	peer.timers.handshakeAttempts.Store(4)
	peer.timers.maxHandshakeAttempts.Store(2)

	if err := peer.SendHandshakeInitiation(true); err != nil {
		t.Fatalf("rate-limited true: %v", err)
	}
	if got := peer.timers.handshakeAttempts.Load(); got != 4 {
		t.Fatalf("true reset handshakeAttempts to %d", got)
	}
	if got := peer.timers.maxHandshakeAttempts.Load(); got != 2 {
		t.Fatalf("true reset maxHandshakeAttempts to %d", got)
	}

	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("rate-limited false: %v", err)
	}
	if got := peer.timers.handshakeAttempts.Load(); got != 0 {
		t.Fatalf("legacy false did not reset handshakeAttempts: %d", got)
	}
	if got := peer.timers.maxHandshakeAttempts.Load(); got != a.dev.maxHandshakeAttemps() {
		t.Fatalf("legacy false maxHandshakeAttempts = %d, want %d", got, a.dev.maxHandshakeAttemps())
	}
}

// TestObservationRealCryptoStaleCommit uses real in-memory Noise messages, not
// sockets. A response authenticated for initiation A must not commit or derive
// after initiation B replaced the handshake.
func TestObservationRealCryptoStaleCommit(t *testing.T) {
	pair := genTestPair(t, false)
	a, b := &pair[0], &pair[1]
	peerA := a.dev.LookupPeer(b.dev.staticIdentity.publicKey)
	if peerA == nil {
		t.Fatal("peer A not found")
	}
	msg1, err := a.dev.CreateMessageInitiation(peerA)
	if err != nil {
		t.Fatalf("initiation A: %v", err)
	}
	peerB := b.dev.ConsumeMessageInitiation(msg1)
	if peerB == nil {
		t.Fatal("B rejected real initiation A")
	}
	msg2, err := b.dev.CreateMessageResponse(peerB)
	if err != nil {
		t.Fatalf("response A: %v", err)
	}
	peer, epochA, idxA := a.dev.consumeMessageResponse(msg2)
	if peer != peerA {
		t.Fatal("A did not authenticate real response A")
	}
	peerA.handshake.mutex.Lock()
	hashA, chainA := peerA.handshake.hash, peerA.handshake.chainKey
	peerA.handshake.mutex.Unlock()

	msg1b, err := a.dev.CreateMessageInitiation(peerA)
	if err != nil || msg1b == nil {
		t.Fatalf("initiation B: %v", err)
	}
	peerA.handshake.mutex.Lock()
	epochB, idxB := peerA.handshake.initiationEpoch, peerA.handshake.localIndex
	hashB, chainB := peerA.handshake.hash, peerA.handshake.chainKey
	stateB := peerA.handshake.state
	peerA.handshake.mutex.Unlock()
	if epochB == epochA || idxB == idxA {
		t.Fatal("fixture did not create a distinct initiation B")
	}

	if peerCommitResponse(peerA, epochA, idxA, msg2, hashA, chainA) {
		t.Fatal("stale response A committed after initiation B")
	}
	peerA.handshake.mutex.Lock()
	if peerA.handshake.state != stateB || peerA.handshake.initiationEpoch != epochB || peerA.handshake.localIndex != idxB {
		peerA.handshake.mutex.Unlock()
		t.Fatal("stale commit mutated initiation B identity/state")
	}
	if peerA.handshake.hash != hashB || peerA.handshake.chainKey != chainB {
		peerA.handshake.mutex.Unlock()
		t.Fatal("stale commit mutated initiation B key material")
	}
	peerA.handshake.mutex.Unlock()

	if derived, err := peerA.beginSymmetricSessionForResponse(epochA, idxA); err == nil || derived != nil {
		t.Fatal("stale derivation accepted")
	}
	if got, _, _ := a.dev.consumeMessageResponse(msg2); got != nil {
		t.Fatal("old queued response A accepted after initiation B")
	}
	if got := peerA.AuthenticatedInitiationsSince(0, nil); len(got) != 0 {
		t.Fatalf("direct stale path published %d events", len(got))
	}
}

// TestObservationDelayedCompletionAfterNewInitiation models a completion that
// became visible only after a newer initiation. The event is a true A
// completion with source A; it must not prove expected B. Consumers must take
// the baseline BEFORE the endpoint update, recheck current peer/lifetime, and
// recheck cancellation before returning.
func TestObservationDelayedCompletionAfterNewInitiation(t *testing.T) {
	pair := genTestPair(t, false)
	a, b := &pair[0], &pair[1]
	keyB := b.dev.staticIdentity.publicKey
	peer := a.dev.LookupPeer(keyB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	// Send to fixture endpoint 1; the fixture delivers the response from
	// endpoint 3, so actual source differs from expected candidate 1.
	peer.endpoint.Lock()
	peer.endpoint.val = bindtest.ChannelEndpoint(1)
	peer.endpoint.Unlock()
	lifetime := peer.AuthenticatedLifetime()
	baseline := peer.AuthenticatedSequence()
	if err := peer.SendHandshakeInitiation(true); err != nil {
		t.Fatalf("send: %v", err)
	}
	events := waitObservation(t, peer, baseline)
	event := events[len(events)-1]

	if _, err := a.dev.CreateMessageInitiation(peer); err != nil {
		t.Fatalf("newer initiation: %v", err)
	}
	peer.handshake.mutex.Lock()
	currentEpoch := peer.handshake.initiationEpoch
	peer.handshake.mutex.Unlock()
	if event.Initiation == currentEpoch {
		t.Fatal("event unexpectedly belongs to the newer initiation")
	}
	expectedB := netip.MustParseAddrPort("127.0.0.1:2")
	if event.Matches(expectedB, lifetime, baseline) {
		t.Fatal("delayed A event accepted for expected B")
	}
	if !event.Matches(event.Source, lifetime, baseline) {
		t.Fatal("real A event did not match its own actual source")
	}
	// A pre-endpoint-update baseline rejects the delayed event even if the
	// consumer expected the same source: take baseline before the attempt.
	if event.Sequence <= baseline {
		t.Fatal("event sequence not newer than baseline")
	}
	peer.Stop()
	peer.Start()
	newLifetime := peer.AuthenticatedLifetime()
	if newLifetime == event.Lifetime {
		t.Fatal("lifetime did not change on stop/start")
	}
	if event.Matches(event.Source, newLifetime, 0) {
		t.Fatal("delayed event matched after lifetime change")
	}
}

// TestObservationStandardBindConstructorIdentity is a pure constructor check:
// standard bind remains concrete *conn.StdNetBind, so Linux sticky listener
// still recognizes it. No Open/socket IO.
func TestObservationStandardBindConstructorIdentity(t *testing.T) {
	bind := conn.NewStdNetBind()
	if _, ok := bind.(*conn.StdNetBind); !ok {
		t.Fatal("NewStdNetBind no longer returns *conn.StdNetBind")
	}
}
