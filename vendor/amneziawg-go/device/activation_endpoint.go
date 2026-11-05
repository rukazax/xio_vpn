/* SPDX-License-Identifier: MIT */
package device

import (
	"errors"
	"net/netip"
	"time"
)

// SetEndpointForInitialActivation updates only this existing peer's endpoint.
// Unlike IpcSet's general post-config hook it never drains staged packets,
// sends a keepalive, starts/stops a peer, or resets handshake attempt counters.
// The caller must own an exclusive, bounded initial activation of the device.
func (peer *Peer) SetEndpointForInitialActivation(address netip.AddrPort) error {
	if peer == nil || peer.device == nil || !address.IsValid() || address.Port() == 0 {
		return errors.New("invalid activation endpoint")
	}
	address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	a := address.Addr()
	if a.Zone() != "" || (!a.IsGlobalUnicast() && !a.IsLoopback()) {
		return errors.New("invalid activation endpoint")
	}
	d := peer.device
	d.ipcMutex.Lock()
	defer d.ipcMutex.Unlock()
	if !d.isUp() || !peer.isRunning.Load() {
		return errors.New("activation peer is not running")
	}
	d.peers.RLock()
	defer d.peers.RUnlock()
	if d.peers.keyMap[peer.handshake.remoteStatic] != peer {
		return errors.New("activation peer replaced")
	}
	endpoint, err := d.net.bind.ParseEndpoint(address.String())
	if err != nil {
		return err
	}
	peer.endpoint.Lock()
	peer.endpoint.val = endpoint
	peer.endpoint.Unlock()
	return nil
}

// InitialActivationRetryInterval reports the configured minimum native rekey
// interval for allocating candidate dwell time. It neither arms nor resets timers.
func (peer *Peer) InitialActivationRetryInterval() time.Duration {
	if peer == nil || peer.device == nil {
		return RekeyTimeout
	}
	return peer.device.rekeyMinTimeout()
}

// AbortInitialActivation closes the immutable bind directly before taking
// device/state/IPC/net locks. SendBuffers holds net.RLock throughout Send, so
// even the public Bind() accessor would deadlock behind a blocked native send.
// net.bind is assigned once by NewDevice, never replaced. The caller must own
// this failed initial device; established tunnels use normal Close.
func (device *Device) AbortInitialActivation() {
	if device == nil {
		return
	}
	_ = device.net.bind.Close()
	device.Close()
}
