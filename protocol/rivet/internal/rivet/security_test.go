package rivet

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNoClassicalGroupFallback(t *testing.T) {
	dir := t.TempDir()
	pin, e := GenerateInner(dir)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(filepath.Join(dir, "inner.crt"), filepath.Join(dir, "inner.key"))
	if e != nil {
		t.Fatal(e)
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(time.Second))
		b.SetDeadline(time.Now().Add(time.Second))
		cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: version, MaxVersion: version, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"rivet/1"}}
		done := make(chan error, 1)
		go func() { done <- tls.Server(b, cfg).HandshakeContext(context.Background()) }()
		err := tls.Client(a, InnerTLS(pin)).HandshakeContext(context.Background())
		a.Close()
		b.Close()
		<-done
		if err == nil {
			t.Fatal("downgrade accepted")
		}
	}
}
func TestUnauthenticatedPathsAndProxyTarget(t *testing.T) {
	dir := t.TempDir()
	token := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tokens := filepath.Join(dir, "tokens.json")
	if e := WriteJSON(tokens, map[string]string{"test": TokenHash(token)}); e != nil {
		t.Fatal(e)
	}
	page := filepath.Join(dir, "index.html")
	os.WriteFile(page, []byte("service"), 0600)
	entry := NewEntry(EntryConfig{Tokens: tokens, Page: page, GatewayUDP: "127.0.0.1:7444"})
	var body string
	for i, path := range []string{"/api/stream", "/unknown"} {
		req := httptest.NewRequest("GET", "https://service.test"+path, nil)
		req.Header.Set("Upgrade", "websocket")
		req.RemoteAddr = "198.51.100.1:12345"
		res := httptest.NewRecorder()
		entry.ServeHTTP(res, req)
		if res.Code != 404 {
			t.Fatal("unauthenticated endpoint exposed")
		}
		if i == 0 {
			body = res.Body.String()
		} else if body != res.Body.String() {
			t.Fatal("path distinguisher")
		}
	}
	for _, target := range []string{"1.1.1.1/53", "169.254.169.254/80", "localhost/7444", "127.0.0.1/22"} {
		req := httptest.NewRequest("CONNECT", "https://service.test/.well-known/masque/udp/"+target+"/", nil)
		req.Proto = "connect-udp"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Capsule-Protocol", "?1")
		req.RemoteAddr = "198.51.100.2:12345"
		res := httptest.NewRecorder()
		entry.ServeHTTP(res, req)
		if res.Code != 404 || strings.Contains(res.Body.String(), "XIO") {
			t.Fatal("arbitrary proxy destination accepted")
		}
	}
}

func TestCarrierHandshakeHonorsAttemptDeadline(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	token := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	cfg := ClientConfig{Protocol: "rivet-s1", Endpoint: listener.Addr().String(), ServerName: "localhost", Pin: key, GatewayID: base64.StdEncoding.EncodeToString(make([]byte, 16)), ID: strings.Repeat("a", 32), Secret: key, EntryToken: token, IP: "10.79.0.2"}
	started := time.Now()
	session, e := DialWithTimeout(context.Background(), cfg, nil, 60*time.Millisecond)
	if e == nil {
		session.Close()
		t.Fatal("stalled carrier accepted")
	}
	if time.Since(started) > time.Second {
		t.Fatal("attempt deadline ignored")
	}
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(time.Second):
		t.Fatal("listener not reached")
	}
}

func TestWebSocketAdvertisesHTTP11ALPN(t *testing.T) {
	dir := t.TempDir()
	ca, e := GenerateOuter(dir, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(filepath.Join(dir, "outer.crt"), filepath.Join(dir, "outer.key"))
	if e != nil {
		t.Fatal(e)
	}
	observed := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observed <- r.TLS.NegotiatedProtocol; w.WriteHeader(401) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	token := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	cfg := ClientConfig{Protocol: "rivet-s1", Endpoint: server.Listener.Addr().String(), ServerName: "127.0.0.1", OuterCA: ca, Pin: key, GatewayID: base64.StdEncoding.EncodeToString(make([]byte, 16)), ID: strings.Repeat("a", 32), Secret: key, EntryToken: token, IP: "10.79.0.2"}
	if c, e := Dial(context.Background(), cfg, nil); e == nil {
		c.Close()
		t.Fatal("unauthorized server accepted")
	}
	select {
	case got := <-observed:
		if got != "http/1.1" {
			t.Fatal("HTTP/1.1 ALPN stripped")
		}
	case <-time.After(time.Second):
		t.Fatal("outer handshake not reached")
	}
}

type fatalTun struct{}

func (fatalTun) Read([]byte) (int, error)    { return 0, io.ErrUnexpectedEOF }
func (fatalTun) Write(b []byte) (int, error) { return len(b), nil }
func (fatalTun) Close() error                { return nil }
func TestGatewayStopsWhenTunReaderFails(t *testing.T) {
	dir := t.TempDir()
	if _, e := GenerateInner(dir); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "seal.key"), make([]byte, 32), 0600)
	cfg := GatewayConfig{TCP: freeTCP(t), UDP: "127.0.0.1:0", Cert: filepath.Join(dir, "inner.crt"), Key: filepath.Join(dir, "inner.key"), Seal: filepath.Join(dir, "seal.key"), Stats: filepath.Join(dir, "stats.json"), GatewayID: base64.StdEncoding.EncodeToString(make([]byte, 16))}
	gateway, e := NewGateway(cfg, fatalTun{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = gateway.Serve(ctx); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal("dead TUN left listeners running", e)
	}
}
