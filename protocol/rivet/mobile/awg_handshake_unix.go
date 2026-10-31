//go:build linux || android

package mobile

// AwgCancelHandshake cancels and joins only a pending initial activation.
// A completed activation has no pending operation and is not canceled here.
func AwgCancelHandshake(handle int64) { awgCancelHandshake(handle) }

// AwgHandshakeCandidates changes only peer endpoints during initial activation.
// A failed attempt closes its own device; success preserves the live tunnel.
func AwgHandshakeCandidates(handle int64, publicKey, endpoints string, timeoutMillis int64) error {
	return awgHandshakeCandidates(handle, publicKey, endpoints, timeoutMillis)
}
