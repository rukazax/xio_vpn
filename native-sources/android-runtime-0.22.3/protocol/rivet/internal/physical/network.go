// Package physical handles bounded physical-network DNS results without using
// the VPN's resolver. The Android bridge returns numeric addresses only.
package physical

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"
)

func Addresses(raw string) ([]string, error) {
	if len(raw) > 2048 {
		return nil, errors.New("physical: DNS result too large")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, value := range strings.Split(raw, ",") {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("physical: invalid DNS address")
		}
		address := ip.String()
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
		if len(result) > 16 {
			return nil, errors.New("physical: too many DNS addresses")
		}
	}
	if len(result) == 0 {
		return nil, errors.New("physical: empty DNS result")
	}
	// Interleave families while retaining the OS's preferred first family.
	first4 := net.ParseIP(result[0]).To4() != nil
	primary, secondary := []string{}, []string{}
	for _, address := range result {
		if (net.ParseIP(address).To4() != nil) == first4 {
			primary = append(primary, address)
		} else {
			secondary = append(secondary, address)
		}
	}
	result = nil
	for i := 0; i < len(primary) || i < len(secondary); i++ {
		if i < len(primary) {
			result = append(result, primary[i])
		}
		if i < len(secondary) {
			result = append(result, secondary[i])
		}
	}
	return result, nil
}

func Resolve(ctx context.Context, host string, resolver func(string) string) ([]string, error) {
	if net.ParseIP(host) != nil {
		return Addresses(host)
	}
	if resolver == nil {
		return nil, errors.New("physical: resolver unavailable")
	}
	done := make(chan string, 1)
	go func() { done <- resolver(host) }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case value := <-done:
		return Addresses(value)
	}
}

// Dial races staggered numeric endpoints. Every socket passes the same mandatory
// protection callback. Cancellation closes losers; DNS never falls back to Go.
func Dial(ctx context.Context, network string, addresses []string, port string, control func(string, string, syscall.RawConn) error) (net.Conn, error) {
	if len(addresses) == 0 || len(addresses) > 16 {
		return nil, errors.New("physical: no addresses")
	}
	type outcome struct {
		connection net.Conn
		err        error
	}
	done := make(chan outcome)
	attempt, cancel := context.WithCancel(ctx)
	defer cancel()
	for i, address := range addresses {
		if net.ParseIP(address) == nil {
			return nil, errors.New("physical: nonnumeric endpoint")
		}
		go func(i int, address string) {
			timer := time.NewTimer(time.Duration(i) * 250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-attempt.Done():
				return
			case <-timer.C:
			}
			dialer := net.Dialer{Timeout: 10 * time.Second, Control: control}
			connection, err := dialer.DialContext(attempt, network, net.JoinHostPort(address, port))
			select {
			case done <- outcome{connection, err}:
			case <-attempt.Done():
				if connection != nil {
					connection.Close()
				}
			}
		}(i, address)
	}
	var last error
	for range addresses {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-done:
			if result.err == nil {
				return result.connection, nil
			}
			last = result.err
		}
	}
	return nil, last
}
