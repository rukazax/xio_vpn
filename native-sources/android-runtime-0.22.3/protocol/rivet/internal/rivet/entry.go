package rivet

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/netutil"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

type Entry struct {
	quicCount atomic.Int64
	Config    EntryConfig
	slots     chan struct{}
	mu        sync.Mutex
	rate      map[string]*bucket
	proxy     masque.Proxy
}
type bucket struct {
	n  float64
	at time.Time
}

func NewEntry(c EntryConfig) *Entry {
	return &Entry{Config: c, slots: make(chan struct{}, 64), rate: map[string]*bucket{}}
}
func (e *Entry) allowed(r *http.Request) bool {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	e.mu.Lock()
	b := e.rate[ip]
	if b == nil {
		if len(e.rate) >= 4096 {
			for k, v := range e.rate {
				if now.Sub(v.at) > time.Minute {
					delete(e.rate, k)
				}
			}
		}
		if len(e.rate) >= 4096 {
			e.mu.Unlock()
			return false
		}
		b = &bucket{n: 20, at: now}
		e.rate[ip] = b
	}
	b.n = min(20, b.n+now.Sub(b.at).Seconds()*2)
	b.at = now
	ok := b.n >= 1
	if ok {
		b.n--
	}
	e.mu.Unlock()
	if !ok {
		return false
	}
	raw := r.Header.Get("Authorization")
	if len(raw) > 128 || !strings.HasPrefix(raw, "Bearer ") {
		return false
	}
	hash := TokenHash(strings.TrimPrefix(raw, "Bearer "))
	if hash == "" {
		return false
	}
	var tokens map[string]string
	if ReadJSON(e.Config.Tokens, &tokens) != nil {
		return false
	}
	allowed := 0
	for _, h := range tokens {
		allowed |= subtle.ConstantTimeCompare([]byte(hash), []byte(h))
	}
	return allowed == 1
}
func (e *Entry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	isWS := r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	isH3 := r.Method == http.MethodConnect && r.Proto == "connect-udp"
	if !isWS && !isH3 {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			page, _ := os.ReadFile(e.Config.Page)
			if len(page) > 1024*1024 {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(page)
			return
		}
		http.NotFound(w, r)
		return
	}
	if !e.allowed(r) || (isWS && r.URL.Path != "/api/stream") {
		http.NotFound(w, r)
		return
	}
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		http.NotFound(w, r)
		return
	}
	if isH3 {
		template, err := uritemplate.New("https://" + r.Host + "/.well-known/masque/udp/{target_host}/{target_port}/")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil || req.Target != e.Config.GatewayUDP {
			http.NotFound(w, r)
			return
		}
		// Parse and equality check occur before any destination lookup or socket opens.
		_ = e.proxy.Proxy(w, req)
		return
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	up, err := dialer.DialContext(r.Context(), "tcp", e.Config.GatewayTCP)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer up.Close()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	ws.SetReadLimit(65536)
	raw := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	defer raw.Close()
	done := make(chan struct{})
	go func() { io.Copy(up, raw); up.Close(); close(done) }()
	io.Copy(raw, up)
	raw.Close()
	<-done
}
func (e *Entry) Serve(ctx context.Context) error {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	tcp := &http.Server{Addr: e.Config.Listen, Handler: e, TLSConfig: tlsConf, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	h3 := &http3.Server{Addr: e.Config.Listen, Handler: e, EnableDatagrams: true, QUICConfig: quicConfig(true), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, MaxHeaderBytes: 8192}
	h3.ConnContext = func(ctx context.Context, c *quic.Conn) context.Context {
		n := e.quicCount.Add(1)
		if n > 128 {
			c.CloseWithError(0x107, "busy")
		}
		go func() { <-c.Context().Done(); e.quicCount.Add(-1) }()
		return ctx
	}
	listener, err := net.Listen("tcp", e.Config.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- tcp.ServeTLS(netutil.LimitListener(listener, 128), e.Config.Cert, e.Config.Key) }()
	go func() { errorsCh <- h3.ListenAndServeTLS(e.Config.Cert, e.Config.Key) }()
	defer tcp.Close()
	defer h3.Close()
	defer e.proxy.Close()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errorsCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
