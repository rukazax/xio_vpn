package xrayclient

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
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

var fixtureCert, fixtureKey []string

func init() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	secret, _ := x509.MarshalPKCS8PrivateKey(key)
	fixtureCert = strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), "\n")
	fixtureKey = strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secret}))), "\n")
}
func profile(port int) string {
	cert, _ := json.Marshal(fixtureCert)
	return fmt.Sprintf(`{"protocol":"xray","outbound":{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"localhost","disableSystemRoot":true,"certificates":[{"certificate":%s,"usage":"verify"}]}}}}`, port, cert)
}

type protect bool

func (p protect) Protect(int64) bool    { return bool(p) }
func (p protect) Resolve(string) string { return "127.0.0.1" }
func TestRejectUnsafe(t *testing.T) {
	for _, raw := range []string{`{}`, profile(0), strings.Replace(profile(8388), `"security":"tls"`, `"security":"none"`, 1), strings.Replace(profile(8388), `"outbound":{`, `"outbound":{"proxySettings":{},`, 1), strings.Replace(profile(8388), `"serverName":"localhost"`, `"allowInsecure":true,"serverName":"localhost"`, 1), profile(8388) + ` {}`, strings.Replace(profile(8388), `"vless","settings"`, `"freedom","settings"`, 1)} {
		if _, e := Parse(raw); e == nil {
			t.Fatalf("unsafe profile accepted: %s", raw)
		}
	}
}
func TestServerFixture(t *testing.T) {
	if os.Getenv("XIO_TEST_SERVER") == "" {
		return
	}
	internet.UseAlternativeSystemDialer(nil)
	v, e := core.StartInstance("json", []byte(os.Getenv("XIO_TEST_SERVER")))
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	fmt.Println("READY")
	select {}
}
func TestProtectedVLESSTLSRoundTrip(t *testing.T) {
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
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], a)
		}
	}()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cert, _ := json.Marshal(fixtureCert)
	secret, _ := json.Marshal(fixtureKey)
	cfg := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificate":%s,"key":%s}]}}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1"]}]}}]}`, port, cert, secret)
	child := exec.Command(os.Args[0], "-test.run=^TestServerFixture$")
	child.Env = append(os.Environ(), "XIO_TEST_SERVER="+cfg)
	out, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	child.Stderr = os.Stderr
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	ready := bufio.NewScanner(out)
	for ready.Scan() && ready.Text() != "READY" {
	}
	if ready.Text() != "READY" {
		t.Fatal("fixture not ready")
	}
	go func() {
		for ready.Scan() {
			fmt.Println("SERVER", ready.Text())
		}
	}()
	for _, allowed := range []bool{false, true} {
		s, e := Start(profile(port), protect(allowed), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		target := echo.Addr().(*net.TCPAddr)
		c, e := s.DialContext(ctx, &metadata.Metadata{DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(target.Port)})
		if e != nil {
			t.Fatal(e)
		}
		timer := time.AfterFunc(2*time.Second, func() { c.Close() })
		_, _ = c.Write([]byte("probe"))
		b := make([]byte, 5)
		_, e = io.ReadFull(c, b)
		timer.Stop()
		c.Close()
		cancel()
		if allowed && (e != nil || string(b) != "probe") {
			t.Fatalf("TCP round trip failed: %v", e)
		}
		if !allowed && e == nil {
			t.Fatal("unprotected connection succeeded")
		}
		if allowed {
			pc, e := s.DialUDP(nil)
			if e != nil {
				t.Fatal(e)
			}
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, e = pc.WriteTo([]byte("udp"), udp.LocalAddr())
			if e != nil {
				t.Fatal(e)
			}
			n, _, e := pc.ReadFrom(b)
			pc.Close()
			if e != nil || string(b[:n]) != "udp" {
				t.Fatalf("UDP round trip failed: %v", e)
			}
		}
		s.Close()
	}
}
func TestNoHandshakeBeforeRemoteData(t *testing.T) {
	s, e := Start(profile(9), protect(true), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var status map[string]any
	_ = json.Unmarshal([]byte(s.Status()), &status)
	if status["secure"] != false || status["handshake"] != float64(0) {
		t.Fatal("false handshake")
	}
}
func TestPacketReadDeadlineAndClose(t *testing.T) {
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := newPacketConn(pc, &Session{}, func() {})
	defer p.Close()
	_ = p.SetReadDeadline(time.Now().Add(15 * time.Millisecond))
	_, _, e = p.ReadFrom(make([]byte, 64))
	var ne net.Error
	if !errors.As(e, &ne) || !ne.Timeout() {
		t.Fatalf("deadline missing: %v", e)
	}
	p.Close()
	if _, _, e = p.ReadFrom(make([]byte, 64)); e == nil {
		t.Fatal("closed packet connection read succeeded")
	}
}
