package desktop

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestAWGPeerKeySinglePeerOnly(t *testing.T) {
	if key, ok := awgPeerKey("private_key=aa\npublic_key=bb\nendpoint=203.0.113.1:443\n"); !ok || key != "bb" {
		t.Fatalf("single peer key: %q %v", key, ok)
	}
	if _, ok := awgPeerKey("public_key=bb\npublic_key=cc\n"); ok {
		t.Fatal("multi-peer profile must keep the legacy path")
	}
	if _, ok := awgPeerKey("endpoint=203.0.113.1:443\n"); ok {
		t.Fatal("missing peer key accepted")
	}
}

func TestPrepareEndpointsKeepsEveryCandidate(t *testing.T) {
	p := Profile{Endpoints: []string{"vpn.example:443"}}
	n := &fakeEndpointNetwork{result: "2001:db8::42,203.0.113.42"}
	if err := prepareEndpoints(&p, n); err != nil {
		t.Fatal(err)
	}
	want := []string{"[2001:db8::42]:443", "203.0.113.42:443"}
	if len(p.EndpointCandidates) != 1 || !reflect.DeepEqual(p.EndpointCandidates[0], want) {
		t.Fatalf("candidates = %v", p.EndpointCandidates)
	}
	if p.Endpoints[0] != want[0] {
		t.Fatalf("initial endpoint = %q", p.Endpoints[0])
	}
	if len(n.bypassed) != 2 {
		t.Fatalf("bypass routes = %v", n.bypassed)
	}
}

func TestAWGPendingDisconnectCancelsBeforeRuntimeLock(t *testing.T) {
	var r Runtime
	entered, finished, disconnected := make(chan struct{}), make(chan error, 1), make(chan struct{})
	go func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		finished <- r.withAWGContext(5000, func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() })
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("activation not started")
	}
	go func() { r.Disconnect(); close(disconnected) }()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Disconnect waited for Connect deadline")
	}
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("Disconnect did not join")
	}
}
func TestAWGActivationMissingCandidatesFailsClosed(t *testing.T) {
	if err := activateAWGContext(context.Background(), nil, Profile{}, 1000); err == nil {
		t.Fatal("no candidate returned success")
	}
}
