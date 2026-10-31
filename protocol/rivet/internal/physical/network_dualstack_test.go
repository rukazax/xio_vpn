package physical

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestAddressesFamilyOrderAndBounds(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"192.0.2.1,192.0.2.2,2001:db8::1,2001:db8::2", []string{"192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2"}},
		{"2001:db8::1,2001:db8::2,192.0.2.1,192.0.2.2", []string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"}},
		{"2001:0db8:0:0::1,2001:db8::1,192.0.2.1,::ffff:192.0.2.1", []string{"2001:db8::1", "192.0.2.1"}},
	} {
		got, err := Addresses(tc.raw)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("Addresses(%q) = %v, %v; want %v", tc.raw, got, err, tc.want)
		}
	}
	tooMany := []string{}
	for i := 1; i <= 17; i++ {
		tooMany = append(tooMany, fmt.Sprintf("192.0.2.%d", i))
	}
	for _, raw := range []string{strings.Join(tooMany, ","), strings.Repeat(" ", 2049), "fe80::1", "2001:db8::1,fe80::1"} {
		if _, err := Addresses(raw); err == nil {
			t.Errorf("unsafe/oversize DNS result accepted: %q", raw)
		}
	}
}

func TestResolvePhysicalOnlyAndCancellation(t *testing.T) {
	for _, literal := range []string{"192.0.2.1", "2001:db8::1"} {
		called := false
		got, err := Resolve(context.Background(), literal, func(string) string { called = true; return "" })
		if err != nil || called || !reflect.DeepEqual(got, []string{literal}) {
			t.Fatalf("literal: %v %v called=%v", got, err, called)
		}
	}
	if _, err := Resolve(context.Background(), "vpn.invalid", nil); err == nil {
		t.Fatal("hostname must not use a system DNS fallback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Resolve(ctx, "2001:db8::1", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled literal resolve: %v", err)
	}
	called := make(chan struct{}, 1)
	if _, err := Resolve(ctx, "vpn.invalid", func(string) string { called <- struct{}{}; return "192.0.2.1" }); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled DNS resolve: %v", err)
	}
	select {
	case <-called:
		t.Error("resolver invoked after cancellation")
	case <-time.After(10 * time.Millisecond):
	}
	release := make(chan struct{})
	stalled, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	_, err := Resolve(stalled, "vpn.invalid", func(string) string { <-release; return "2001:db8::1" })
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("stalled resolver: %v", err)
	}
}

func TestDialRequiresProtection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	c, err := Dial(context.Background(), "tcp", []string{"127.0.0.1"}, port, nil)
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("physical socket connected without mandatory protection")
	}
	sentinel := errors.New("protection rejected")
	var calls atomic.Int32
	c, err = Dial(context.Background(), "tcp", []string{"127.0.0.1"}, port, func(string, string, syscall.RawConn) error { calls.Add(1); return sentinel })
	if c != nil {
		c.Close()
		t.Error("connection returned after protection failed")
	}
	if !errors.Is(err, sentinel) || calls.Load() != 1 {
		t.Fatalf("protection failure: calls=%d error=%v", calls.Load(), err)
	}
}

func TestDialValidatesWholeRequestBeforeSockets(t *testing.T) {
	for _, tc := range []struct {
		addresses []string
		port      string
	}{
		{[]string{"127.0.0.1", "vpn.invalid"}, "443"},
		{[]string{"::"}, "443"},
		{[]string{"ff02::1"}, "443"},
		{[]string{"fe80::1"}, "443"},
		{[]string{"127.0.0.1"}, "https"},
		{[]string{"127.0.0.1"}, "0"},
		{[]string{"::1"}, "65536"},
	} {
		var calls atomic.Int32
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		c, err := Dial(ctx, "tcp", tc.addresses, tc.port, func(string, string, syscall.RawConn) error { calls.Add(1); return errors.New("unexpected socket") })
		cancel()
		if c != nil {
			c.Close()
		}
		if err == nil || calls.Load() != 0 {
			t.Errorf("request %v:%s opened sockets=%d, err=%v", tc.addresses, tc.port, calls.Load(), err)
		}
	}
}

func TestDialCancellationStopsStaggeredLosers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		c, err := Dial(ctx, "tcp", []string{"127.0.0.1", "::1"}, "443", func(string, string, syscall.RawConn) error {
			calls.Add(1)
			cancel()
			return errors.New("canceling first attempt")
		})
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled Dial did not return")
	}
	time.Sleep(275 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("delayed loser opened after cancellation; calls=%d", calls.Load())
	}
}
