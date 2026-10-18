package rivet

import (
	"encoding/binary"
	"net/netip"
)

var prohibited = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("198.18.0.0/15"),
}

func CheckIPv4(b []byte, source string, publicOnly bool) error {
	if len(b) < 20 || len(b) > MTU || b[0] != 0x45 || int(binary.BigEndian.Uint16(b[2:])) != len(b) || binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
		return ErrProtocol
	}
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	if sum != 65535 {
		return ErrProtocol
	}
	src := netip.AddrFrom4([4]byte(b[12:16]))
	if source != "" && src.String() != source {
		return ErrProtocol
	}
	if b[9] != 1 && b[9] != 6 && b[9] != 17 {
		return ErrProtocol
	}
	if publicOnly {
		dst := netip.AddrFrom4([4]byte(b[16:20]))
		for _, p := range prohibited {
			if p.Contains(dst) {
				return ErrProtocol
			}
		}
	}
	return nil
}
func Destination(b []byte) string {
	if len(b) < 20 {
		return ""
	}
	return netip.AddrFrom4([4]byte(b[16:20])).String()
}
