package xrayclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func profile(port int) string {
	return fmt.Sprintf(`{"protocol":"shadowsocks","outbound":{"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":%d,"method":"aes-128-gcm","password":"test-only-long-password"}]}}}`, port)
}

type protect bool

func (p protect) Protect(int64) bool    { return bool(p) }
func (p protect) Resolve(string) string { return "127.0.0.1" }
func TestRejectUnsafe(t *testing.T) {
	for _, raw := range []string{`{}`, profile(0), strings.Replace(profile(8388), `"aes-128-gcm"`, `"none"`, 1), strings.Replace(profile(8388), `"outbound":{`, `"outbound":{"proxySettings":{},`, 1), strings.Replace(profile(8388), `"outbound":{`, `"outbound":{"streamSettings":{"tlsSettings":{"allowInsecure":true}},`, 1), profile(8388) + ` {}`, strings.Replace(profile(8388), `"shadowsocks","settings"`, `"freedom","settings"`, 1)} {
		if _, e := Parse(raw); e == nil {
			t.Fatal("unsafe profile accepted")
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
func TestProtectedShadowsocksRoundTrip(t *testing.T) {
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
	cfg := fmt.Sprintf(`{"log":{"loglevel":"debug"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks","settings":{"method":"aes-128-gcm","password":"test-only-long-password","network":"tcp,udp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1"]}]}}]}`, port)
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
