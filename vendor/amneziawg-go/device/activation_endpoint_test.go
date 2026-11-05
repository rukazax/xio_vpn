/* SPDX-License-Identifier: MIT */
package device

import (
	"net/netip"
	"testing"
	"time"
)

func TestActivationEndpointPreservesStagedInitialState(t *testing.T) {
	pair := genTestPair(t, false)
	d := pair[0].dev
	p := d.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	// No derived keypair. A queued packet would make legacy IpcSet's post-hook
	// call SendHandshakeInitiation(false), resetting counters even when rate limited.
	staged := d.GetOutboundElementsContainer()
	p.queue.staged <- staged
	p.timers.handshakeAttempts.Store(4)
	p.timers.maxHandshakeAttempts.Store(2)
	p.handshake.mutex.Lock()
	before := time.Now()
	p.handshake.lastSentHandshake = before
	p.handshake.mutex.Unlock()
	if err := p.SetEndpointForInitialActivation(netip.MustParseAddrPort("127.0.0.1:3")); err != nil {
		t.Fatal(err)
	}
	if d.LookupPeer(pair[1].dev.staticIdentity.publicKey) != p {
		t.Fatal("peer replaced")
	}
	if len(p.queue.staged) != 1 {
		t.Fatal("staged packets consumed")
	}
	if p.timers.handshakeAttempts.Load() != 4 || p.timers.maxHandshakeAttempts.Load() != 2 {
		t.Fatal("attempt counters reset")
	}
	p.handshake.mutex.RLock()
	same := p.handshake.lastSentHandshake.Equal(before)
	p.handshake.mutex.RUnlock()
	if !same {
		t.Fatal("last sent handshake changed")
	}
	if p.keypairs.Current() != nil {
		t.Fatal("keypair created by endpoint update")
	}
	p.FlushStagedPackets()
}
func TestActivationEndpointRejectsStoppedOrInvalid(t *testing.T) {
	pair := genTestPair(t, false)
	p := pair[0].dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	for _, s := range []string{"[::]:1", "[::ffff:0.0.0.0]:1", "255.255.255.255:1", "[fe80::1%eth0]:1"} {
		if err := p.SetEndpointForInitialActivation(netip.MustParseAddrPort(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	p.Stop()
	if err := p.SetEndpointForInitialActivation(netip.MustParseAddrPort("127.0.0.1:3")); err == nil {
		t.Fatal("stopped peer accepted")
	}
}
