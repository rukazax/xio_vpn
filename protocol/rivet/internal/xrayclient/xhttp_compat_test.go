package xrayclient

// These are local interoperability checks against the pinned upstream engine,
// not a claim about a Russian operator or a CDN's permitted traffic policy.
import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestXHTTPModesWithVLESSEncryption(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	cert := strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), "\n")
	secret := strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))), "\n")
	pq, e := mlkem.GenerateKey768()
	if e != nil {
		t.Fatal(e)
	}
	encryption := "mlkem768x25519plus.native.1rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())
	decryption := "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(pq.Bytes())
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			uuid := "b3b2eb49-e41f-41df-9761-0956785a236b"
			stream := map[string]any{"network": "xhttp", "security": "tls", "xhttpSettings": map[string]any{"path": "/xio-test", "mode": mode}, "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificate": cert, "key": secret}}, "alpn": []string{"h2", "http/1.1"}}}
			config, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": uuid}}, "decryption": decryption}, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1"}}}}}}})
			child := exec.Command(os.Args[0], "-test.run=^TestServerFixture$")
			child.Env = append(os.Environ(), "XIO_TEST_SERVER="+string(config))
			out, e := child.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			child.Stderr = os.Stderr
			if e = child.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() { child.Process.Kill(); child.Wait() }()
			scanner := bufio.NewScanner(out)
			for scanner.Scan() && scanner.Text() != "READY" {
			}
			if scanner.Text() != "READY" {
				t.Fatal("server not ready")
			}
			stream["tlsSettings"] = map[string]any{"serverName": "localhost", "alpn": []string{"h2"}, "disableSystemRoot": true, "certificates": []any{map[string]any{"certificate": cert, "usage": "verify"}}}
			raw, _ := json.Marshal(map[string]any{"protocol": "xray", "outbound": map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": uuid, "encryption": encryption}}}}}, "streamSettings": stream}})
			s, e := Start(string(raw), protect(true), 5*time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			target := echo.Addr().(*net.TCPAddr)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, e := s.DialContext(ctx, &metadata.Metadata{DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(target.Port)})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := fmt.Sprintf("XIO %s encrypted local probe", mode)
			if _, e = c.Write([]byte(payload)); e != nil {
				t.Fatal(e)
			}
			reply := make([]byte, len(payload))
			if _, e = io.ReadFull(c, reply); e != nil || string(reply) != payload {
				t.Fatalf("round trip: %v", e)
			}
		})
	}
}
