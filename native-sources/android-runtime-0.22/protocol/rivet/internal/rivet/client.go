package rivet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

type Protector interface{ Protect(int64) bool }

func socketControl(p Protector) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		if p == nil {
			return nil
		}
		ok := false
		if e := c.Control(func(fd uintptr) { ok = p.Protect(int64(fd)) }); e != nil {
			return e
		}
		if !ok {
			return errors.New("rivet: socket protection failed")
		}
		return nil
	}
}
func quicConfig(outer bool) *quic.Config {
	size := uint16(1200)
	uni := int64(-1)
	streams := int64(1)
	if outer {
		size = 1450
		uni = 8
		streams = 8
	}
	return &quic.Config{EnableDatagrams: true, InitialPacketSize: size, DisablePathMTUDiscovery: !outer, MaxIncomingStreams: streams, MaxIncomingUniStreams: uni, HandshakeIdleTimeout: 8 * time.Second, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, MaxConnectionReceiveWindow: 256 * 1024, MaxStreamReceiveWindow: 64 * 1024, Allow0RTT: false}
}
func Dial(ctx context.Context, c ClientConfig, protect Protector) (*Session, error) {
	return DialWithTimeout(ctx, c, protect, 10*time.Second)
}
func DialWithTimeout(ctx context.Context, c ClientConfig, protect Protector, timeout time.Duration) (session *Session, err error) {
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	hs, cancel := context.WithTimeout(ctx, min(timeout, 10*time.Second))
	defer cancel()
	var s *Session
	defer func() {
		if err != nil && s != nil {
			s.Close()
		}
	}()
	outerTLS := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ServerName, NextProtos: []string{"http/1.1"}}
	if c.OuterCA != "" {
		outerTLS.RootCAs = x509.NewCertPool()
		if !outerTLS.RootCAs.AppendCertsFromPEM([]byte(c.OuterCA)) {
			return nil, ErrProtocol
		}
	}
	_, port, _ := net.SplitHostPort(c.Endpoint)
	authority := net.JoinHostPort(c.ServerName, port)
	if c.Protocol == "rivet-s1" {
		dialer := &net.Dialer{Timeout: 8 * time.Second, Control: socketControl(protect)}
		transport := &http.Transport{TLSClientConfig: outerTLS, ForceAttemptHTTP2: false, MaxIdleConns: 1, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, c.Endpoint)
		}}
		// net/http strips ALPN on HTTP/1-only Upgrade requests. Perform the
		// normal verified TLS handshake explicitly, retaining honest http/1.1 ALPN.
		transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&tls.Dialer{NetDialer: dialer, Config: outerTLS.Clone()}).DialContext(ctx, network, c.Endpoint)
		}
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("rivet: redirects forbidden") }}
		header := http.Header{"Authorization": []string{"Bearer " + c.EntryToken}}
		ws, resp, e := websocket.Dial(hs, "wss://"+authority+"/api/stream", &websocket.DialOptions{HTTPClient: client, HTTPHeader: header, CompressionMode: websocket.CompressionDisabled})
		if resp != nil && resp.Body != nil && e != nil {
			resp.Body.Close()
		}
		if e != nil {
			transport.CloseIdleConnections()
			return nil, fmt.Errorf("rivet: carrier rejected: %w", e)
		}
		ws.SetReadLimit(65536)
		raw := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		inner := tls.Client(raw, InnerTLS(c.Pin))
		authDeadline, _ := hs.Deadline()
		inner.SetDeadline(authDeadline)
		if e = inner.HandshakeContext(hs); e != nil {
			raw.Close()
			transport.CloseIdleConnections()
			return nil, e
		}
		s = NewSession(inner, inner.ConnectionState(), 1, nil, func() { raw.Close(); transport.CloseIdleConnections() })
		if e = s.ClientAuth(c); e != nil {
			return nil, e
		}
		inner.SetDeadline(time.Time{})
	} else {
		packet, e := (&net.ListenConfig{Control: socketControl(protect)}).ListenPacket(hs, "udp4", "0.0.0.0:0")
		if e != nil {
			return nil, e
		}
		ot := &quic.Transport{Conn: packet}
		defer func() {
			if err != nil {
				ot.Close()
				packet.Close()
			}
		}()
		endpoint, e := net.ResolveUDPAddr("udp4", c.Endpoint)
		if e != nil {
			return nil, e
		}
		outerTLS.NextProtos = []string{"h3"}
		outerTLS.MinVersion = tls.VersionTLS13
		outer, e := ot.Dial(hs, endpoint, outerTLS, quicConfig(true))
		if e != nil {
			return nil, e
		}
		h3 := &http3.Transport{EnableDatagrams: true}
		hc := h3.NewClientConn(outer)
		life, lifeCancel := context.WithCancel(ctx)
		stop := context.AfterFunc(hs, lifeCancel)
		defer stop()
		template, e := uritemplate.New("https://" + authority + "/.well-known/masque/udp/{target_host}/{target_port}/")
		if e != nil {
			lifeCancel()
			outer.CloseWithError(0, "closed")
			return nil, e
		}
		req, e := masque.NewRequest(life, template, "127.0.0.1:7444")
		if e != nil {
			lifeCancel()
			outer.CloseWithError(0, "closed")
			return nil, e
		}
		req.Header().Set("Authorization", "Bearer "+c.EntryToken)
		proxied, response, e := masque.NewClientConn(hc).Dial(req)
		if e != nil {
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			lifeCancel()
			outer.CloseWithError(0, "closed")
			return nil, e
		}
		it := &quic.Transport{Conn: proxied}
		inner, e := it.Dial(hs, proxied.RemoteAddr(), InnerTLS(c.Pin), quicConfig(false))
		if e != nil {
			it.Close()
			proxied.Close()
			lifeCancel()
			outer.CloseWithError(0, "closed")
			return nil, e
		}
		stream, e := inner.OpenStreamSync(hs)
		if e != nil {
			inner.CloseWithError(0, "closed")
			it.Close()
			proxied.Close()
			lifeCancel()
			outer.CloseWithError(0, "closed")
			return nil, e
		}
		authDeadline, _ := hs.Deadline()
		stream.SetDeadline(authDeadline)
		if _, e = stream.Write([]byte{0}); e != nil {
			stream.Close()
			inner.CloseWithError(0, "closed")
			it.Close()
			proxied.Close()
			lifeCancel()
			outer.CloseWithError(0, "closed")
			return nil, e
		}
		s = NewSession(stream, inner.ConnectionState().TLS, 0, inner, func() {
			inner.CloseWithError(0, "closed")
			it.Close()
			proxied.Close()
			lifeCancel()
			outer.CloseWithError(0, "closed")
			ot.Close()
			packet.Close()
		})
		if e = s.ClientAuth(c); e != nil {
			return nil, e
		}
		stream.SetDeadline(time.Time{})
		stop()
	}
	s.StartMaintenance()
	return s, nil
}
func IsRivet(s string) bool { return strings.HasPrefix(s, "rivet-") }
