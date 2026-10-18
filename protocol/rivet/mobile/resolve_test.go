package mobile

import (
	"context"
	"errors"
	"testing"
	"time"
	"xio.local/rivet/internal/rivet"
)

type stalledResolver struct{ release chan struct{} }

func (p stalledResolver) Protect(int64) bool    { return true }
func (p stalledResolver) Resolve(string) string { <-p.release; return "192.0.2.1" }
func TestHostnameResolutionHonorsCancellationAndDeadline(t *testing.T) {
	for _, cancelNow := range []bool{false, true} {
		resolver := stalledResolver{make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		if cancelNow {
			cancel()
		}
		start := time.Now()
		_, e := resolveTimed(ctx, rivet.ClientConfig{Endpoint: "vpn.example:8443"}, resolver, 30*time.Millisecond)
		close(resolver.release)
		cancel()
		if !errors.Is(e, context.DeadlineExceeded) && !errors.Is(e, context.Canceled) {
			t.Fatal("resolver did not stop")
		}
		if time.Since(start) > time.Second {
			t.Fatal("DNS deadline ignored")
		}
	}
}
