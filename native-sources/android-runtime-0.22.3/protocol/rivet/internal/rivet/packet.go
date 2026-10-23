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
	if len(b) >= 40 && b[0]>>4 == 6 {
		return netip.AddrFrom16([16]byte(b[24:40])).String()
	}
	if len(b) < 20 {
		return ""
	}
	return netip.AddrFrom4([4]byte(b[16:20])).String()
}

// IPv6For derives the IPv6 address from the authenticated IPv4 user slot. No
// untrusted client request can choose another user's IPv6 source address.
func IPv6For(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() {
		return ""
	}
	b := address.As4()
	if b[0] != 10 || b[1] != 79 || b[2] != 0 || b[3] < 2 || b[3] > 254 {
		return ""
	}
	v6 := [16]byte{0xfd, 0x79, 0, 1}
	v6[15] = b[3]
	return netip.AddrFrom16(v6).String()
}

var prohibited6 = []netip.Prefix{
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2001:20::/28"),
}

func CheckIP(b []byte, source string, publicOnly bool) error {
	if len(b) == 0 {
		return ErrProtocol
	}
	if b[0]>>4 == 4 {
		return CheckIPv4(b, source, publicOnly)
	}
	if b[0]>>4 != 6 || len(b) < 40 || len(b) > MTU || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) {
		return ErrProtocol
	}
	// No jumbograms, fragmentation or extension chains. TCP, UDP and bounded
	// ICMPv6 errors/echo suffice for ordinary tunnel traffic and PMTU discovery.
	if b[6] != 6 && b[6] != 17 && b[6] != 58 {
		return ErrProtocol
	}
	src := netip.AddrFrom16([16]byte(b[8:24]))
	dst := netip.AddrFrom16([16]byte(b[24:40]))
	if source != "" && src.String() != IPv6For(source) {
		return ErrProtocol
	}
	if b[6] == 58 && (len(b) < 48 || !(b[40] >= 1 && b[40] <= 4 || b[40] == 128 || b[40] == 129)) {
		return ErrProtocol
	}
	if publicOnly {
		if !dst.IsGlobalUnicast() {
			return ErrProtocol
		}
		for _, prefix := range prohibited6 {
			if prefix.Contains(dst) {
				return ErrProtocol
			}
		}
		if netip.MustParsePrefix("64:ff9b::/96").Contains(dst) {
			v := dst.As16()
			embedded := netip.AddrFrom4([4]byte(v[12:16]))
			for _, prefix := range prohibited {
				if prefix.Contains(embedded) {
					return ErrProtocol
				}
			}
		}
	}
	return nil
}
