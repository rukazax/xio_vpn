package physical

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestAddresses(t *testing.T) {
	values, err := Addresses("::1,127.0.0.1,::1,2001:db8::1,127.0.0.2")
	if err != nil || len(values) != 4 || values[1] != "127.0.0.1" {
		t.Fatalf("%v %v", values, err)
	}
	for _, raw := range []string{"", "example.org", "::", "ff02::1", "127.0.0.1,bad"} {
		if _, err := Addresses(raw); err == nil {
			t.Fatal(raw)
		}
	}
}
func TestBothFamiliesAndUnreachableFamilyFallback(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			bind := "127.0.0.1:0"
			if family == "tcp6" {
				bind = "[::1]:0"
			}
			listener, err := net.Listen(family, bind)
			if err != nil {
				if family == "tcp6" {
					t.Skip("IPv6 loopback unavailable; isolated IPv6 namespace required")
				}
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				c, err := listener.Accept()
				if err == nil {
					c.Close()
				}
			}()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			addresses := []string{"::1", "127.0.0.1"}
			if family == "tcp6" {
				addresses = []string{"127.0.0.1", "::1"}
			}
			controls := make(chan string, 8)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := Dial(ctx, "tcp", addresses, port, func(network, address string, _ syscall.RawConn) error { controls <- network; return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if len(controls) < 2 {
				t.Fatal("both protected attempts expected")
			}
		})
	}
}
