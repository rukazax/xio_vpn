package tailclient

import (
	"encoding/binary"
	"encoding/json"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testProtector struct{}

func (testProtector) Protect(int64) bool { return true }
func (testProtector) Resolve(host string) string {
	ips, _ := net.LookupIP(host)
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}
func TestVPSExitNode(t *testing.T) {
	dir := os.Getenv("XIO_VPS_PROFILE_DIR")
	if dir == "" {
		t.Skip("requires authorized VPS fixture")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "tailscale-017.json"))
	if e != nil {
		t.Fatal(e)
	}
	s, e := Start(string(raw), t.TempDir(), testProtector{}, &memoryStore{values: map[string]string{}}, nil, 30*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var addresses []string
	_ = json.Unmarshal([]byte(s.Addresses()), &addresses)
	var source net.IP
	for _, a := range addresses {
		if !strings.Contains(a, ":") {
			source = net.ParseIP(a).To4()
		}
	}
	if source == nil {
		t.Fatal("no IPv4 address")
	}
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Attach(fds[0]); e != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		t.Fatal(e)
	}
	peer := os.NewFile(uintptr(fds[1]), "tail-test-peer")
	defer peer.Close()
	_ = peer.SetReadDeadline(time.Now().Add(12 * time.Second))
	dns := []byte{0x58, 0x49, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	packet := make([]byte, 28+len(dns))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source)
	copy(packet[16:20], net.ParseIP("9.9.9.9").To4())
	binary.BigEndian.PutUint16(packet[20:22], 53017)
	binary.BigEndian.PutUint16(packet[22:24], 53)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(dns)))
	copy(packet[28:], dns)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	if _, e = peer.Write(packet); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4096)
	for {
		n, e := peer.Read(b)
		if e != nil {
			t.Fatal(e)
		}
		if n < 40 || b[0]>>4 != 4 || b[9] != 17 {
			continue
		}
		offset := int(b[0]&15)*4 + 8
		if n < offset+12 {
			continue
		}
		if binary.BigEndian.Uint16(b[offset:offset+2]) != 0x5849 {
			continue
		}
		if b[offset+3]&15 != 0 || binary.BigEndian.Uint16(b[offset+6:offset+8]) == 0 {
			t.Fatal("DNS response failed")
		}
		break
	}
}
