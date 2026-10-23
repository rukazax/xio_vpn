// XIO adapter. Upstream's indefinitely retrying MakeSession is never invoked.
package cloak

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/common"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
)

type Config = client.RawConfig

func init()                             { log.SetOutput(io.Discard) }
func Decode(raw []byte) (Config, error) { var c Config; e := json.Unmarshal(raw, &c); return c, e }
func Open(ctx context.Context, c Config, dialer common.Dialer) (net.Conn, error) {
	c.NumConn = 1
	c.UDP = false
	c.ProxyMethod = "openvpn"
	c.LocalHost = "127.0.0.1"
	c.LocalPort = "0"
	if c.EncryptionMethod == "" {
		c.EncryptionMethod = "aes-gcm"
	}
	if c.EncryptionMethod == "plain" {
		return nil, errors.New("cloak: encryption required")
	}
	_, remote, auth, e := c.ProcessRawConfig(common.RealWorldState)
	if e != nil {
		return nil, errors.New("cloak: invalid profile")
	}
	var sid [4]byte
	if _, e = io.ReadFull(rand.Reader, sid[:]); e != nil {
		return nil, e
	}
	auth.SessionId = binary.BigEndian.Uint32(sid[:])
	if auth.SessionId == 0 {
		auth.SessionId = 1
	}
	conn, e := dialer.Dial("tcp", remote.RemoteAddr)
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	transport := remote.Transport.CreateTransport()
	key, e := transport.Handshake(conn, auth)
	if e != nil {
		conn.Close()
		return nil, errors.New("cloak: authentication failed")
	}
	_ = conn.SetDeadline(time.Time{})
	ob, e := mux.MakeObfuscator(auth.EncryptionMethod, key)
	if e != nil {
		conn.Close()
		return nil, e
	}
	session := mux.MakeSession(auth.SessionId, mux.SessionConfig{Singleplex: true, Obfuscator: ob, Unordered: false, MsgOnWireSizeLimit: 16401})
	session.AddConnection(transport)
	stream, e := session.OpenStream()
	if e != nil {
		session.Close()
		return nil, e
	}
	return &streamConn{Conn: stream, session: session}, nil
}

type streamConn struct {
	net.Conn
	session *mux.Session
}

func (s *streamConn) Close() error { _ = s.Conn.Close(); return s.session.Close() }
