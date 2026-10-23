package mobile

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"
)

func cloakFixture(t *testing.T, port int) string {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]any{"protocol": "cloak", "cloak": map[string]any{"RemoteHost": "127.0.0.1", "RemotePort": strconv.Itoa(port), "UID": base64.StdEncoding.EncodeToString(make([]byte, 16)), "PublicKey": base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), "ServerName": "example.com", "EncryptionMethod": "aes-gcm"}})
	return string(b)
}
func TestCloakCancellationAndProtection(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	for _, allow := range []bool{false, true} {
		localPort, e := CloakStart(cloakFixture(t, port), pinnedProtector(allow), 100)
		if e != nil {
			t.Fatal(e)
		}
		c, e := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(localPort))))
		if e != nil {
			t.Fatal(e)
		}
		_, _ = c.Write([]byte("OpenVPN fixture"))
		if allow {
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			remote, e := listener.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer remote.Close()
		}
		deadline := time.AfterFunc(time.Second, func() { c.Close() })
		b := make([]byte, 1)
		_, e = c.Read(b)
		deadline.Stop()
		c.Close()
		if e == nil {
			t.Fatal("unauthenticated bridge returned data")
		}
		started := time.Now()
		CloakStop()
		if time.Since(started) > time.Second {
			t.Fatal("Cloak stop exceeded timeout")
		}
	}
}

type pinnedProtector bool

func (p pinnedProtector) Protect(int64) bool    { return bool(p) }
func (p pinnedProtector) Resolve(string) string { return "127.0.0.1" }
