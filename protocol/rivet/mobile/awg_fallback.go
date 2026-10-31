package mobile

import (
	"errors"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"xio.local/rivet/internal/awgactivation"
)

var errAWGFallback = errors.New("awg: initial authenticated handshake unavailable")

// awgCandidates is the legacy shape kept for the mobile tests; validation and
// the activation controller live in the shared awgactivation package.
func awgCandidates(key, raw string, timeout int64) (device.NoisePublicKey, []netip.AddrPort, error) {
	public, addresses, err := awgactivation.Validate(key, raw, timeout)
	if err != nil {
		return device.NoisePublicKey{}, nil, errAWGFallback
	}
	return public, addresses, nil
}
