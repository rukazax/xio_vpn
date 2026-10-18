package rivet

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"syscall"
)

type UserStats struct {
	Month      string `json:"month"`
	MonthBytes uint64 `json:"monthBytes"`
	RX         uint64 `json:"rx"`
	TX         uint64 `json:"tx"`
	Online     bool   `json:"online"`
	SampledAt  int64  `json:"sampledAt"`
}
type peer struct {
	s     *Session
	queue chan []byte
}
type Gateway struct {
	locals map[string]bool
	Config GatewayConfig
	tun    io.ReadWriteCloser
	mu     sync.Mutex
	peers  map[string]*peer
	stats  map[string]*UserStats
	slots  chan struct{}
	master []byte
	id     []byte
}

func NewGateway(c GatewayConfig, tun io.ReadWriteCloser) (*Gateway, error) {
	master, e := readSeal(c.Seal)
	if e != nil {
		return nil, e
	}
	id, e := Decode(c.GatewayID, 16)
	if e != nil {
		return nil, e
	}
	g := &Gateway{Config: c, tun: tun, peers: map[string]*peer{}, stats: map[string]*UserStats{}, slots: make(chan struct{}, 32), master: master, id: id}
	_ = ReadJSON(c.Stats, &g.stats)
	if g.stats == nil {
		g.stats = map[string]*UserStats{}
	}
	g.locals = map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil {
				g.locals[ip.String()] = true
			}
		}
	} else {
		return nil, err
	}
	for _, s := range g.stats {
		s.Online = false
	}
	return g, nil
}
func (g *Gateway) Lookup(id string) (User, []byte, error) {
	var users map[string]User
	if e := ReadJSON(g.Config.Users, &users); e != nil {
		return User{}, nil, e
	}
	u, ok := users[id]
	if !ok || u.Revoked || u.ID != id {
		return User{}, nil, ErrProtocol
	}
	ip := net.ParseIP(u.IP).To4()
	if ip == nil || ip[0] != 10 || ip[1] != 79 || ip[2] != 0 || ip[3] < 2 || ip[3] > 254 {
		return User{}, nil, ErrProtocol
	}
	key, e := Unseal(g.master, u.Sealed, id)
	return u, key, e
}
func (g *Gateway) add(s *Session) *peer {
	p := &peer{s: s, queue: make(chan []byte, 64)}
	g.mu.Lock()
	old := g.peers[s.IP]
	g.peers[s.IP] = p
	if g.stats[s.ID] == nil {
		g.stats[s.ID] = &UserStats{}
	}
	g.stats[s.ID].Online = true
	g.mu.Unlock()
	if old != nil {
		old.s.Close()
	}
	return p
}
func (g *Gateway) remove(p *peer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.peers[p.s.IP] == p {
		delete(g.peers, p.s.IP)
		if s := g.stats[p.s.ID]; s != nil {
			s.Online = false
		}
	}
}
func (g *Gateway) count(id string, n int, rx bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.stats[id]
	if s == nil {
		return
	}
	month := time.Now().UTC().Format("2006-01")
	if s.Month != month {
		s.Month = month
		s.MonthBytes = 0
	}
	s.MonthBytes += uint64(n)
	if rx {
		s.RX += uint64(n)
	} else {
		s.TX += uint64(n)
	}
}
func (g *Gateway) data(s *Session) {
	defer s.Close()
	p := g.add(s)
	defer g.remove(p)
	s.StartMaintenance()
	go func() {
		defer s.Close()
		for {
			select {
			case <-s.Done():
				return
			case b := <-p.queue:
				if e := s.SendPacket(b); e != nil {
					return
				}
				g.count(s.ID, len(b), false)
			}
		}
	}()
	expiry := time.NewTicker(5 * time.Second)
	defer expiry.Stop()
	go func() {
		for {
			select {
			case <-s.Done():
				return
			case <-expiry.C:
				if _, _, e := g.Lookup(s.ID); e != nil {
					s.Close()
					return
				}
			}
		}
	}()
	for {
		b, e := s.ReadPacket()
		if e != nil {
			return
		}
		if e = CheckIPv4(b, s.IP, true); e != nil {
			return
		}
		if g.localDestination(Destination(b)) {
			return
		}
		if _, e = g.tun.Write(b); e != nil {
			return
		}
		g.count(s.ID, len(b), true)
	}
}
func (g *Gateway) localDestination(dst string) bool { return g.locals[dst] }

func (g *Gateway) route(ctx context.Context) error {
	defer g.tun.Close()
	go func() { <-ctx.Done(); g.tun.Close() }()
	buf := make([]byte, 65536)
	var downSince time.Time
	for {
		n, e := g.tun.Read(buf)
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(e, syscall.EIO) {
				if downSince.IsZero() {
					downSince = time.Now()
				}
				if time.Since(downSince) < 5*time.Second {
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(50 * time.Millisecond):
						continue
					}
				}
			}
			return e
		}
		downSince = time.Time{}
		b := buf[:n]
		if CheckIPv4(b, "", false) != nil {
			continue
		}
		g.mu.Lock()
		p := g.peers[Destination(b)]
		g.mu.Unlock()
		if p != nil {
			copyB := append([]byte{}, b...)
			select {
			case p.queue <- copyB:
			default:
			}
		}
	}
}
func (g *Gateway) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pair, e := tls.LoadX509KeyPair(g.Config.Cert, g.Config.Key)
	if e != nil {
		return e
	}
	cfg := InnerTLS("")
	cfg.Certificates = []tls.Certificate{pair}
	listener, e := net.Listen("tcp", g.Config.TCP)
	if e != nil {
		return e
	}
	defer listener.Close()
	q, e := quic.ListenAddr(g.Config.UDP, cfg, quicConfig(false))
	if e != nil {
		return e
	}
	defer q.Close()
	routeDone := make(chan error, 1)
	go func() { routeDone <- g.route(ctx) }()
	persistDone := make(chan struct{})
	go func() { defer close(persistDone); g.persist(ctx) }()
	go func() {
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			select {
			case g.slots <- struct{}{}:
			default:
				raw.Close()
				continue
			}
			go func() {
				defer func() { <-g.slots }()
				raw.SetDeadline(time.Now().Add(10 * time.Second))
				tlsConn := tls.Server(raw, cfg)
				if tlsConn.HandshakeContext(ctx) != nil {
					raw.Close()
					return
				}
				s := NewSession(tlsConn, tlsConn.ConnectionState(), 1, nil, func() { raw.Close() })
				defer s.Close()
				if s.ServerAuth(g.id, g.Lookup) != nil {
					return
				}
				tlsConn.SetDeadline(time.Time{})
				g.data(s)
			}()
		}
	}()
	go func() {
		for {
			conn, e := q.Accept(ctx)
			if e != nil {
				return
			}
			select {
			case g.slots <- struct{}{}:
			default:
				conn.CloseWithError(0, "closed")
				continue
			}
			go func() {
				defer func() { <-g.slots }()
				defer conn.CloseWithError(0, "closed")
				authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				stream, e := conn.AcceptStream(authCtx)
				if e != nil {
					return
				}
				stream.SetDeadline(time.Now().Add(10 * time.Second))
				var preface [1]byte
				if _, e = io.ReadFull(stream, preface[:]); e != nil || preface[0] != 0 {
					return
				}
				s := NewSession(stream, conn.ConnectionState().TLS, 0, conn, func() { conn.CloseWithError(0, "closed") })
				defer s.Close()
				if s.ServerAuth(g.id, g.Lookup) != nil {
					return
				}
				stream.SetDeadline(time.Time{})
				g.data(s)
			}()
		}
	}()
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-routeDone:
		cancel()
	}
	g.mu.Lock()
	for _, p := range g.peers {
		p.s.Close()
	}
	g.mu.Unlock()
	<-persistDone
	return runErr
}
func (g *Gateway) persist(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	flush := func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		now := time.Now().Unix()
		month := time.Now().UTC().Format("2006-01")
		for _, s := range g.stats {
			s.SampledAt = now
			if s.Month != month {
				s.Month = month
				s.MonthBytes = 0
			}
		}
		_ = WriteJSON(g.Config.Stats, g.stats)
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-tick.C:
			flush()
		}
	}
}
func ParseID(id string) error {
	b, e := hex.DecodeString(id)
	if e != nil || len(b) != 16 {
		return errors.New("rivet: invalid identity")
	}
	return nil
}
