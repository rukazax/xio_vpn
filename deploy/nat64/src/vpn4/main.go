// Command vpn4 gives IPv4 egress to AmneziaWG clients on an IPv6-only host
// that has a working NAT64 prefix but no IPv4 route.
//
// The host never sees a packet addressed to an IPv4 destination: the clients'
// TCP is redirected by netfilter to this process (nat PREROUTING + REDIRECT),
// the process asks the kernel for the pre-redirect destination with
// getsockopt(SOL_IP, SO_ORIGINAL_DST) and opens a fresh *IPv6* connection to
//   <prefix>/96 + those four IPv4 bytes
// which the provider's NAT64 then translates.  The UDP/53 relay does the same
// for DNS: a query sent to the clients' resolver address is wrapped into an
// IPv6 datagram towards <prefix>::<DNS IPv4>:53.
//
// Only the standard library and package syscall are used, so the binary builds
// with CGO_ENABLED=0 and runs on a bare LXC container without tooling.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// SO_ORIGINAL_DST from <linux/netfilter_ipv4.h> (SOL_IP is 0 on Linux).
const soOriginalDst = 80

// sockaddrInSize is sizeof(struct sockaddr_in) that getsockopt() fills in.
const sockaddrInSize = 16

var (
	// nat64Prefix holds the first 96 bits of every translated address.
	nat64Prefix net.IP
	tcpListen   = env("VPN4_TCP_LISTEN", "0.0.0.0:19192")
	dnsListen   = env("VPN4_DNS_LISTEN", "0.0.0.0:5353")
	dnsUpstream = env("VPN4_DNS_UPSTREAM", "1.1.1.1:53")
	dialTimeout = envDuration("VPN4_DIAL_TIMEOUT", 10*time.Second)
	idleTimeout = envDuration("VPN4_IDLE_TIMEOUT", 10*time.Minute)
	dnsTimeout  = envDuration("VPN4_DNS_TIMEOUT", 5*time.Second)
)

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Printf("ignoring invalid %s=%q, using %s", key, raw, def)
		return def
	}
	return d
}

// nat64Target builds the [prefix:hi:lo]:port literal for an IPv4 endpoint.
// The prefix is written out as six groups and the IPv4 address contributes two
// more, so the result is a full eight-group address that every parser accepts
// (the compressed form "<prefix>::<hi>:<lo>" is rejected by strict parsers when
// the "::" would stand for zero groups).
func nat64Target(ip net.IP, port int) (string, error) {
	v4 := ip.To4()
	if v4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %v", ip)
	}
	hi := uint32(v4[0])<<8 | uint32(v4[1])
	lo := uint32(v4[2])<<8 | uint32(v4[3])
	addr := make(net.IP, net.IPv6len)
	copy(addr, nat64Prefix)
	binary.BigEndian.PutUint32(addr[12:], hi<<16|lo)
	return fmt.Sprintf("[%s]:%d", addr.String(), port), nil
}

// parsePrefix accepts the /96 prefix either as a bare IPv6 prefix
// ("2a01:4f8:c2c:123f:64:5") or in CIDR form ("2a01:4f8:c2c:123f:64:5::/96").
func parsePrefix(raw string) (net.IP, error) {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "/96"))
	if raw == "" {
		return nil, errors.New("empty NAT64 prefix")
	}
	// Six groups are the natural spelling; append "::" so net.ParseIP accepts it.
	if strings.Count(raw, ":") < 2 || !strings.Contains(raw, "::") {
		raw += "::"
	}
	ip := net.ParseIP(raw)
	if ip == nil || ip.To16() == nil {
		return nil, fmt.Errorf("cannot parse NAT64 prefix %q", raw)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("NAT64 prefix %q is an IPv4 address", raw)
	}
	return ip.To16(), nil
}

// originalDst asks netfilter what the client actually wanted to reach.
func originalDst(conn *net.TCPConn) (net.IP, int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, err
	}
	var (
		ip    net.IP
		port  int
		inner error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		var sa [sockaddrInSize]byte
		size := uint32(sockaddrInSize)
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&sa[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			inner = fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", errno)
			return
		}
		// struct sockaddr_in: sin_family(2, HOST order) sin_port(2, network order)
		// sin_addr(4).  Only the family is native-endian; port and address are not.
		family := *(*uint16)(unsafe.Pointer(&sa[0]))
		if family != uint16(syscall.AF_INET) {
			inner = fmt.Errorf("SO_ORIGINAL_DST returned family %d, not AF_INET", family)
			return
		}
		port = int(binary.BigEndian.Uint16(sa[2:4]))
		ip = net.IPv4(sa[4], sa[5], sa[6], sa[7]).To4()
	})
	if ctrlErr != nil {
		return nil, 0, ctrlErr
	}
	if inner != nil {
		return nil, 0, inner
	}
	return ip, port, nil
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("vpn4: ")

	prefix, err := parsePrefix(env("VPN4_PREFIX", "2a01:4f8:c2c:123f:64:5"))
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}
	nat64Prefix = prefix

	tcpAddr, err := net.ResolveTCPAddr("tcp4", tcpListen)
	if err != nil {
		log.Fatalf("fatal: bad VPN4_TCP_LISTEN %q: %v", tcpListen, err)
	}
	tcpLn, err := net.ListenTCP("tcp4", tcpAddr)
	if err != nil {
		log.Fatalf("fatal: cannot listen on %s: %v", tcpListen, err)
	}
	dnsAddr, err := net.ResolveUDPAddr("udp4", dnsListen)
	if err != nil {
		log.Fatalf("fatal: bad VPN4_DNS_LISTEN %q: %v", dnsListen, err)
	}
	dnsConn, err := net.ListenUDP("udp4", dnsAddr)
	if err != nil {
		log.Fatalf("fatal: cannot listen on %s: %v", dnsListen, err)
	}

	upAddr, err := net.ResolveUDPAddr("udp4", dnsUpstream)
	if err != nil {
		log.Fatalf("fatal: bad VPN4_DNS_UPSTREAM %q: %v", dnsUpstream, err)
	}
	upTarget, err := nat64Target(upAddr.IP, upAddr.Port)
	if err != nil {
		log.Fatalf("fatal: DNS upstream %q is not IPv4: %v", dnsUpstream, err)
	}

	log.Printf("nat64 prefix %s/96; tcp %s; udp %s -> %s via %s",
		nat64Prefix, tcpListen, dnsListen, dnsUpstream, upTarget)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Printf("signal %s: shutting down", s)
		_ = tcpLn.Close()
		_ = dnsConn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); serveDNS(dnsConn, upTarget) }()
	go func() { defer wg.Done(); serveTCP(tcpLn) }()
	wg.Wait()
	log.Printf("stopped")
}

func serveTCP(ln *net.TCPListener) {
	// Bound the number of live relays so a wedged client cannot exhaust the box
	// (the container has 1 GiB of RAM and a low file-descriptor budget).
	sem := make(chan struct{}, 4096)
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Printf("accept: too many live relays, dropping %s", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			handleTCP(conn)
		}()
	}
}

func handleTCP(client *net.TCPConn) {
	defer client.Close()

	dstIP, dstPort, err := originalDst(client)
	if err != nil {
		log.Printf("drop %s: %v", client.RemoteAddr(), err)
		return
	}
	if dstIP.IsLoopback() || dstIP.IsUnspecified() {
		// A direct connection to the bridge itself (not redirected by
		// netfilter): there is no IPv4 destination to translate.
		log.Printf("drop %s: original destination %s is loopback, not a REDIRECT",
			client.RemoteAddr(), net.JoinHostPort(dstIP.String(), strconv.Itoa(dstPort)))
		return
	}
	target, err := nat64Target(dstIP, dstPort)
	if err != nil {
		log.Printf("drop %s: %v", client.RemoteAddr(), err)
		return
	}

	upstream, err := net.DialTimeout("tcp6", target, dialTimeout)
	if err != nil {
		log.Printf("tcp client=%s dst=%s -> %s FAIL %v",
			client.RemoteAddr(), net.JoinHostPort(dstIP.String(), strconv.Itoa(dstPort)), target, err)
		return
	}
	defer upstream.Close()
	log.Printf("tcp client=%s dst=%s -> %s",
		client.RemoteAddr(), net.JoinHostPort(dstIP.String(), strconv.Itoa(dstPort)), target)

	relay(client, upstream.(*net.TCPConn))
}

// relay copies in both directions and closes each half once its direction ends,
// so a TLS close_notify does not turn into a reset for the other side.
func relay(client, upstream *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src *net.TCPConn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		// Half-close: the peer may still have data to send back.
		_ = dst.CloseWrite()
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	wg.Wait()
}

func serveDNS(conn *net.UDPConn, upstream string) {
	// DNS queries are tiny and arrive one at a time per client; a small cap is
	// enough and keeps the goroutine count bounded.
	sem := make(chan struct{}, 256)
	buf := make([]byte, 4096)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			log.Printf("dns read: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if n < 12 {
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])

		select {
		case sem <- struct{}{}:
		default:
			continue
		}
		go func() {
			defer func() { <-sem }()
			answer, err := forwardDNS(upstream, query)
			if err != nil {
				log.Printf("dns client=%s -> %s FAIL %v", client, upstream, err)
				return
			}
			if _, err := conn.WriteToUDP(answer, client); err != nil {
				log.Printf("dns client=%s reply: %v", client, err)
				return
			}
			rcode, answers := summarise(answer)
			log.Printf("dns client=%s -> %s ok rcode=%d ancount=%d",
				client, upstream, rcode, answers)
		}()
	}
}

func forwardDNS(upstream string, query []byte) ([]byte, error) {
	raddr, err := net.ResolveUDPAddr("udp6", upstream)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp6", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(dnsTimeout))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

func summarise(msg []byte) (rcode uint8, answers uint16) {
	if len(msg) < 12 {
		return 0, 0
	}
	return msg[3] & 0x0f, binary.BigEndian.Uint16(msg[6:8])
}
