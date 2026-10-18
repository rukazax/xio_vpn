package rivet

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type Session struct {
	lastRead   atomic.Int64
	Wire       *Wire
	State      tls.ConnectionState
	Carrier    uint64
	Datagram   *quic.Conn
	CloseFunc  func()
	ID, IP     string
	handshake  atomic.Int64
	rx, tx     atomic.Uint64
	sendMu     sync.Mutex
	packetID   uint64
	reassembly *Reassembler
	ctx        context.Context
	cancel     context.CancelFunc
	once       sync.Once
}

func NewSession(conn io.ReadWriteCloser, state tls.ConnectionState, carrier uint64, q *quic.Conn, closeFn func()) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{Wire: &Wire{ReadWriteCloser: conn}, State: state, Carrier: carrier, Datagram: q, CloseFunc: closeFn, reassembly: NewReassembler(), ctx: ctx, cancel: cancel}
}
func (s *Session) Close() {
	s.once.Do(func() {
		s.cancel()
		if s.CloseFunc != nil {
			s.CloseFunc()
		}
		s.Wire.Close()
	})
}
func (s *Session) Done() <-chan struct{} { return s.ctx.Done() }
func (s *Session) Counts() (uint64, uint64, int64) {
	return s.rx.Load(), s.tx.Load(), s.handshake.Load()
}
func (s *Session) ClientAuth(c ClientConfig) error {
	exporter, e := Exporter(s.State)
	if e != nil {
		return e
	}
	b, e := s.Wire.Expect(Challenge)
	if e != nil {
		return e
	}
	if len(b) != 48 {
		return ErrProtocol
	}
	gateway, _ := Decode(c.GatewayID, 16)
	if !hmac.Equal(gateway, b[:16]) {
		return ErrProtocol
	}
	secret, _ := Decode(c.Secret, 32)
	id, _ := hex.DecodeString(c.ID)
	params := Params(s.Carrier)
	body := append(append(append([]byte{}, id...), params...), Proof(secret, b[:16], b[16:], exporter, params)...)
	if e = s.Wire.Send(Auth, body); e != nil {
		return e
	}
	sid, e := s.Wire.Expect(AuthOK)
	if e != nil || len(sid) != 16 {
		return ErrProtocol
	}
	conf, e := s.Wire.Expect(Configure)
	if e != nil {
		return e
	}
	if e = DecodeConfig(conf, sid, net.ParseIP(c.IP).To4()); e != nil {
		return e
	}
	hash := sha256.Sum256(conf)
	if e = s.Wire.Send(ConfigACK, hash[:]); e != nil {
		return e
	}
	s.ID = c.ID
	s.IP = c.IP
	s.handshake.Store(time.Now().UnixMilli())
	s.lastRead.Store(time.Now().UnixMilli())
	return nil
}
func (s *Session) ServerAuth(gateway []byte, lookup func(string) (User, []byte, error)) error {
	exporter, e := Exporter(s.State)
	if e != nil {
		return e
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	if e = s.Wire.Send(Challenge, append(append([]byte{}, gateway...), nonce...)); e != nil {
		return e
	}
	body, e := s.Wire.Expect(Auth)
	if e != nil || len(body) < 49 {
		return ErrProtocol
	}
	id := hex.EncodeToString(body[:16])
	params := body[16 : len(body)-32]
	proof := body[len(body)-32:]
	u, secret, lookupErr := lookup(id)
	if lookupErr != nil {
		secret = make([]byte, 32)
	}
	valid := hmac.Equal(proof, Proof(secret, gateway, nonce, exporter, params))
	if lookupErr != nil || !valid || !CheckParams(params, s.Carrier) {
		return errors.New("rivet: authentication failed")
	}
	sid := make([]byte, 16)
	if _, e = rand.Read(sid); e != nil {
		return e
	}
	if e = s.Wire.Send(AuthOK, sid); e != nil {
		return e
	}
	ip := net.ParseIP(u.IP).To4()
	if ip == nil {
		return ErrProtocol
	}
	conf := EncodeConfig(ip, sid)
	if e = s.Wire.Send(Configure, conf); e != nil {
		return e
	}
	ack, e := s.Wire.Expect(ConfigACK)
	if e != nil {
		return e
	}
	hash := sha256.Sum256(conf)
	if !hmac.Equal(ack, hash[:]) {
		return ErrProtocol
	}
	s.ID = id
	s.IP = u.IP
	s.handshake.Store(time.Now().UnixMilli())
	s.lastRead.Store(time.Now().UnixMilli())
	return nil
}
func (s *Session) SendPacket(p []byte) error {
	if s.handshake.Load() == 0 || len(p) > MTU || len(p) < 20 {
		return ErrProtocol
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.Datagram == nil {
		if e := s.Wire.Send(IPPacket, p); e != nil {
			return e
		}
	} else {
		if s.packetID == math.MaxUint64 {
			return ErrProtocol
		}
		s.packetID++
		for _, b := range Fragment(s.packetID, p) {
			if e := s.Datagram.SendDatagram(b); e != nil {
				return e
			}
		}
	}
	s.tx.Add(uint64(len(p)))
	return nil
}
func (s *Session) ReadPacket() ([]byte, error) {
	if s.handshake.Load() == 0 {
		return nil, ErrProtocol
	}
	for {
		var b []byte
		var e error
		if s.Datagram == nil {
			var kind byte
			kind, b, e = s.Wire.ReadFrame()
			if e != nil {
				return nil, e
			}
			s.lastRead.Store(time.Now().UnixMilli())
			if kind == Padding {
				continue
			}
			if kind != IPPacket {
				return nil, ErrProtocol
			}
		} else {
			b, e = s.Datagram.ReceiveDatagram(s.ctx)
			if e != nil {
				return nil, e
			}
			s.lastRead.Store(time.Now().UnixMilli())
			b, e = s.reassembly.Feed(b, time.Now())
			if e != nil {
				return nil, e
			}
			if b == nil {
				continue
			}
		}
		s.rx.Add(uint64(len(b)))
		return b, nil
	}
}

// StartMaintenance is called after AUTH/config only. Padding supplies a bounded
// encrypted keepalive; the H3 control reader must never accept pre-auth data.
func (s *Session) StartMaintenance() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		expiry := time.NewTimer(time.Hour)
		defer expiry.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-expiry.C:
				s.Close()
				return
			case <-ticker.C:
				if time.Now().UnixMilli()-s.lastRead.Load() > 25000 {
					s.Close()
					return
				}
				b := make([]byte, 16)
				if _, e := rand.Read(b); e != nil {
					s.Close()
					return
				}
				if e := s.Wire.Send(Padding, b); e != nil {
					s.Close()
					return
				}
			}
		}
	}()
	if s.Datagram != nil {
		go func() {
			defer s.Close()
			for {
				t, _, e := s.Wire.ReadFrame()
				if e != nil || t != Padding {
					return
				}
				s.lastRead.Store(time.Now().UnixMilli())
			}
		}()
	}
}
func TokenHash(token string) string {
	b, e := base64.StdEncoding.DecodeString(token)
	if e != nil || len(b) != 32 {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
