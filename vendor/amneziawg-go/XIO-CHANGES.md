# XIO-controlled AWG source fork

Owner: XIO VPN owner138. Scope: this repository only; not the shared Go module cache.
Upstream: github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814.
Upstream module zip: h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0=.
The upstream MIT LICENSE is preserved byte-for-byte.

## Additive changes

- device/{device,peer,receive,noise-protocol}.go plus observation.go:
  authenticated initiator completion after exact response identity is revalidated
  both at commit and derivation; immutable actual packet source, sequence and
  peer lifetime; bounded copied history. Stale responses cannot overwrite a
  newer initiation's cryptographic state.
- device/activation_endpoint.go: SetEndpointForInitialActivation updates only
  the existing peer endpoint and InitialActivationRetryInterval reads the
  configured native minimum retry interval. AbortInitialActivation closes the
  immutable bind without first acquiring the IPC or net lock, then joins Close.
  No staged-packet post-config hook:
  unlike general IpcSet, a pending staged packet cannot cause the endpoint
  update itself to call SendHandshakeInitiation(false) and reset counters.
- observation_test.go and activation_endpoint_test.go: pure/in-memory tests.

send.go, conn/*, timers.go, uapi.go and Linux sticky bind handling are unchanged
from upstream. The existing public signatures, wire format and cryptography
are unchanged except intentional rejection of the stale-response race. The
initial controller requests SendHandshakeInitiation(true), preserving the
native rate gate; it does not clear timers/keypairs or recreate peers.

## Consumer contract and limits

Use only for an exclusively owned, bounded initial activation. Capture a new
sequence baseline before EACH endpoint update, then require actual source,
public key, newer sequence, unchanged peer identity and current lifetime.
Join cancellation/close before releasing the native handle reservation. Use AbortInitialActivation when aborting: Bind() also takes the exclusive net
lock held in read mode by a blocked SendBuffers. In addition, the upstream Close acquires
ipcMutex before closing the bind, while a general IPC post-hook may send.

A typed source observation proves authenticated source address, not physical
network-path identity. Relay provenance, physical IPv4/IPv6 fallback, Android
VpnService lifecycle, payload, DNS and no-leak checks still require platform
acceptance. No external/device VPN PASS is implied by source or memory tests.

Builds must include this fork in tools/native_fingerprint.py. Immutable native,
AAR and application candidates must record source-before/source-after hashes;
previous qualified releases must not be overwritten.
