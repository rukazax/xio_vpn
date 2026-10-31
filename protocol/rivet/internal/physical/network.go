// Package physical handles bounded physical-network DNS results without using
// the VPN's resolver. The Android bridge returns numeric addresses only.
package physical

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ValidHost reports whether host is a numeric endpoint address or an ASCII DNS
// name. Brackets, ports, zones and Unicode IDNs are rejected: callers pass the
// bare host returned by SplitHostPort and resolve HOST through the platform.
func ValidHost(host string) bool {
	if host == "" || len(host) > 253 || strings.TrimSpace(host) != host {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && (ip.To4() != nil || !ip.IsLinkLocalUnicast())
	}
	if strings.ContainsAny(host, ":[]/\\@%") {
		return false
	}
	name := host
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	if name == "" || len(name) > 253 {
		return false
	}
	// A numeric spelling that is not a valid IP must not turn into a DNS query.
	if strings.Trim(name, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c != '-' && (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
				return false
			}
		}
	}
	return true
}

// ParseEndpoint validates a host:port endpoint without resolving it. A
// bracketed host is accepted only for an IPv6 literal; a DNS name or IPv4
// address stays bare. This keeps profile input and the numeric dial contract
// distinct.
func ParseEndpoint(endpoint string) (string, string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" || !ValidHost(host) {
		return "", "", errors.New("physical: invalid endpoint")
	}
	if strings.HasPrefix(endpoint, "[") && (net.ParseIP(host) == nil || !strings.Contains(host, ":")) {
		return "", "", errors.New("physical: brackets require an IPv6 literal")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strings.Trim(port, "0123456789") != "" {
		return "", "", errors.New("physical: invalid numeric port")
	}
	return host, port, nil
}

func Addresses(raw string) ([]string, error) {
	if len(raw) > 2048 {
		return nil, errors.New("physical: DNS result too large")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, value := range strings.Split(raw, ",") {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || (ip.To4() == nil && ip.IsLinkLocalUnicast()) {
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		return Addresses(host)
	}
	if !ValidHost(host) {
		return nil, errors.New("physical: invalid DNS name")
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return Addresses(value)
	}
}

// Dial races staggered numeric endpoints. Every socket passes the same mandatory
// protection callback. Cancellation closes losers; DNS never falls back to Go.
func Dial(ctx context.Context, network string, addresses []string, port string, control func(string, string, syscall.RawConn) error) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if control == nil {
		return nil, errors.New("physical: socket protection unavailable")
	}
	if len(addresses) == 0 || len(addresses) > 16 {
		return nil, errors.New("physical: no addresses")
	}
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 || strings.Trim(port, "0123456789") != "" {
		return nil, errors.New("physical: invalid numeric port")
	}
	// Validate the complete request before any goroutine can open a socket.
	endpoints := make([]string, len(addresses))
	for i, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || (ip.To4() == nil && ip.IsLinkLocalUnicast()) {
			return nil, errors.New("physical: invalid numeric endpoint")
		}
		endpoints[i] = ip.String()
	}
	type outcome struct {
		connection net.Conn
		err        error
	}
	done := make(chan outcome)
	attempt, cancel := context.WithCancel(ctx)
	defer cancel()
	for i, address := range endpoints {
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
			if err := ctx.Err(); err != nil {
				if result.connection != nil {
					result.connection.Close()
				}
				return nil, err
			}
			if result.err == nil {
				return result.connection, nil
			}
			last = result.err
		}
	}
	return nil, last
}
