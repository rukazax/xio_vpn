package xrayclient

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeUsesSessionDialAndValidatesTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	var calls atomic.Int32
	dial := func(ctx context.Context, address string) (net.Conn, error) {
		calls.Add(1)
		if address != strings.TrimPrefix(server.URL, "https://") {
			t.Errorf("unexpected target")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(server.URL, "https://"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeHTTPS(ctx, server.URL, dial, roots); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("session dial was not used exactly once")
	}
	if err := probeHTTPS(ctx, server.URL, dial, x509.NewCertPool()); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}
func TestProbeRejectsUnsafeRedirectsAndHonorsDeadline(t *testing.T) {
	for _, target := range []string{"http://example.org", "https://u:p@example.org", "https://example.org/#fragment", strings.Repeat("x", 2049)} {
		if _, err := probeURL(target); err == nil {
			t.Fatal("invalid probe URL accepted")
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.org", http.StatusFound)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dial := func(ctx context.Context, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(server.URL, "https://"))
	}
	if err := probeHTTPS(context.Background(), server.URL, dial, roots); err == nil {
		t.Fatal("HTTPS downgrade accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	blocked := func(ctx context.Context, address string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	if err := probeHTTPS(ctx, "https://example.org", blocked, roots); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
}
