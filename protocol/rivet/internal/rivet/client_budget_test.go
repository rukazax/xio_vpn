package rivet

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"sync/atomic"
	"testing"
	"time"
)

// Models the reviewed HTTP/3 CONNECT hazard: opening honored the context, but
// the subsequent response reader only returns when its actual carrier closes.
// This fixture opens no socket and runs no TLS/transport integration.
func TestSourceNoNetworkCarrierCancellationJoinsBlockedResponse(t *testing.T) {
	for _, which := range []string{"establishment", "lifetime", "deadline"} {
		t.Run(which, func(t *testing.T) {
			setup, cancelSetup := context.WithCancel(context.Background())
			defer cancelSetup()
			life, cancelLife := context.WithCancel(context.Background())
			defer cancelLife()
			if which == "deadline" {
				setup, cancelSetup = context.WithDeadline(context.Background(), time.Unix(0, 0))
				defer cancelSetup()
			}
			closed, joined := make(chan struct{}), make(chan struct{})
			var closes atomic.Int32
			carrier := watchCarrierCancellation(setup, life, func() { closes.Add(1); close(closed) })
			defer carrier.release()
			go func() { <-closed; close(joined) }()
			if which == "lifetime" {
				cancelLife()
			} else {
				cancelSetup()
			}
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("context revoked but actual CONNECT response carrier stayed blocked")
			}
			if carrier.accept() {
				t.Fatal("canceled/late carrier accepted")
			}
			carrier.release()
			carrier.release()
			if closes.Load() != 1 {
				t.Fatalf("carrier close ownership duplicated: %d", closes.Load())
			}
		})
	}
}

func TestSourceNoNetworkWinningCarrierDetachesOnlySetupWatch(t *testing.T) {
	setup, cancelSetup := context.WithCancel(context.Background())
	defer cancelSetup()
	life, cancelLife := context.WithCancel(context.Background())
	defer cancelLife()
	closed := make(chan struct{})
	var closes atomic.Int32
	carrier := watchCarrierCancellation(setup, life, func() { closes.Add(1); close(closed) })
	defer carrier.release()
	if !carrier.accept() {
		t.Fatal("live authenticated carrier rejected")
	}
	cancelSetup()
	select {
	case <-closed:
		t.Fatal("winning carrier died with establishment lease")
	default:
	}
	cancelLife()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("retained lifetime failed to close actual carrier")
	}
	carrier.release()
	if closes.Load() != 1 {
		t.Fatal("retained cancellation and explicit cleanup double-closed carrier")
	}
}

func TestSourceNoNetworkH3CancellationClosesActualOwnedResources(t *testing.T) {
	// Guards production wiring as well as the isolated lease helper above. A
	// request-context-only cancellation is insufficient for cached masque/http3.
	file, err := parser.ParseFile(token.NewFileSet(), "client.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || name.Name != "watchCarrierCancellation" || len(call.Args) != 3 {
			return true
		}
		callback, ok := call.Args[2].(*ast.FuncLit)
		if !ok {
			return true
		}
		found++
		closed := map[string]bool{}
		ast.Inspect(callback.Body, func(n ast.Node) bool {
			invoke, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if method, ok := invoke.Fun.(*ast.SelectorExpr); ok {
				if object, ok := method.X.(*ast.Ident); ok {
					closed[object.Name+"."+method.Sel.Name] = true
				}
			}
			return true
		})
		for _, resource := range []string{"outer.CloseWithError", "ot.Close", "packet.Close"} {
			if !closed[resource] {
				t.Errorf("cancellation does not revoke actual %s", resource)
			}
		}
		return true
	})
	if found != 1 {
		t.Fatalf("expected one production H3 carrier watch, got %d", found)
	}
}
