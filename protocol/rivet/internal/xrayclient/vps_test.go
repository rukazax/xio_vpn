package xrayclient

import (
	"context"
	"encoding/binary"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVPSProfiles(t *testing.T) {
	dir := os.Getenv("XIO_VPS_PROFILE_DIR")
	if dir == "" {
		t.Skip("requires authorized VPS fixture")
	}
	for _, protocol := range []string{"xray", "shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			raw, e := os.ReadFile(filepath.Join(dir, protocol+"-017.json"))
			if e != nil {
				t.Fatal(e)
			}
			s, e := Start(string(raw), protect(true), 10*time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				a, e := netip.ParseAddrPort(addr)
				if e != nil {
					return nil, e
				}
				return s.DialContext(ctx, &metadata.Metadata{DstIP: a.Addr(), DstPort: a.Port()})
			}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			response, e := client.Get("https://1.1.1.1/cdn-cgi/trace")
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(io.LimitReader(response.Body, 10000))
			response.Body.Close()
			if e != nil || response.StatusCode != 200 || !strings.Contains(string(b), "ip=81.177.142.37") {
				t.Fatal("VPS exit verification failed")
			}
			pc, e := s.DialUDP(nil)
			if e != nil {
				t.Fatal(e)
			}
			defer pc.Close()
			_ = pc.SetReadDeadline(time.Now().Add(8 * time.Second))
			query := []byte{0x58, 0x49, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
			_, e = pc.WriteTo(query, &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 53})
			if e != nil {
				t.Fatal(e)
			}
			packet := make([]byte, 4096)
			n, _, e := pc.ReadFrom(packet)
			if e != nil || n < 12 || binary.BigEndian.Uint16(packet[:2]) != 0x5849 || packet[3]&15 != 0 || binary.BigEndian.Uint16(packet[6:8]) == 0 {
				t.Fatalf("UDP DNS failed: %v", e)
			}
		})
	}
}
