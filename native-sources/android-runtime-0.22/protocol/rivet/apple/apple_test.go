package apple

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
	"xio.local/rivet/internal/rivet"
)

type testProtector struct{}

func (testProtector) Protect(int64) bool { return true }
func (testProtector) Resolve(h string) string {
	v, _ := net.LookupIP(h)
	for _, ip := range v {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

type testSink struct{ packets chan []byte }

func (s testSink) WritePacket(b []byte) bool {
	select {
	case s.packets <- append([]byte(nil), b...):
	default:
	}
	return true
}
func TestVPSPacketFlow(t *testing.T) {
	path := os.Getenv("XIO_APPLE_VPS_PROFILE")
	if path == "" {
		t.Skip("private VPS fixture required")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var fixtures map[string]string
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("fixture schema")
	}
	for _, proto := range []string{"rivet-h3", "rivet-s1"} {
		t.Run(proto, func(t *testing.T) {
			cfg := fixtures[proto]
			var c rivet.ClientConfig
			if json.Unmarshal([]byte(cfg), &c) != nil {
				t.Fatal("profile schema")
			}
			sink := testSink{make(chan []byte, 8)}
			if _, e := Start(cfg, testProtector{}, sink, 15000); e != nil {
				t.Fatal(e)
			}
			defer Stop()
			dns := []byte{0x58, 0x49, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
			b := make([]byte, 28+len(dns))
			b[0] = 0x45
			binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
			b[8] = 64
			b[9] = 17
			copy(b[12:16], net.ParseIP(c.IP).To4())
			copy(b[16:20], []byte{1, 1, 1, 1})
			binary.BigEndian.PutUint16(b[20:], 42919)
			binary.BigEndian.PutUint16(b[22:], 53)
			binary.BigEndian.PutUint16(b[24:], uint16(8+len(dns)))
			copy(b[28:], dns)
			var sum uint32
			for i := 0; i < 20; i += 2 {
				sum += uint32(binary.BigEndian.Uint16(b[i:]))
			}
			for sum>>16 != 0 {
				sum = (sum & 65535) + (sum >> 16)
			}
			binary.BigEndian.PutUint16(b[10:], ^uint16(sum))
			if !Input(b) {
				t.Fatal("packet not accepted")
			}
			deadline := time.After(10 * time.Second)
			for {
				select {
				case reply := <-sink.packets:
					if len(reply) > 40 && reply[9] == 17 && binary.BigEndian.Uint16(reply[20:]) == 53 && reply[28] == 0x58 && reply[29] == 0x49 {
						if reply[31]&15 != 0 {
							t.Fatal("DNS response error")
						}
						return
					}
				case <-deadline:
					t.Fatal("packet-flow DNS response deadline")
				}
			}
		})
	}
}
func TestStoppedInputAndStatus(t *testing.T) {
	Stop()
	if Input(make([]byte, 20)) {
		t.Fatal("input accepted after stop")
	}
	if Status() != `{"active":false}` {
		t.Fatal(Status())
	}
}
