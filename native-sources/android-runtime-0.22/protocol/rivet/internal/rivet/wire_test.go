package rivet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"net"
	"path/filepath"
	"testing"
	"time"
)

type bufferConn struct{ *bytes.Buffer }

func (b bufferConn) Close() error { return nil }
func TestFramesBounded(t *testing.T) {
	for _, b := range [][]byte{{99, 0, 0, 0, 0, 0}, {1, 1, 0, 0, 0, 0}, {1, 0, 0, 0, 32, 0}, {16, 0, 0, 0, 5, 1}, {32, 0, 0, 0, 0, 0}} {
		w := &Wire{ReadWriteCloser: bufferConn{bytes.NewBuffer(b)}}
		if _, _, e := w.ReadFrame(); e == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	w := &Wire{ReadWriteCloser: bufferConn{bytes.NewBuffer(nil)}}
	if w.Send(Challenge, make([]byte, 4097)) == nil {
		t.Fatal("oversized frame")
	}
}
func TestFragmentsReplayWindow(t *testing.T) {
	p := make([]byte, 1280)
	rand.Read(p)
	parts := Fragment(1, p)
	r := NewReassembler()
	now := time.Now()
	if b, e := r.Feed(parts[1], now); e != nil || b != nil {
		t.Fatal(e)
	}
	b, e := r.Feed(parts[0], now)
	if e != nil || !bytes.Equal(b, p) {
		t.Fatal("reassembly")
	}
	if b, e = r.Feed(parts[0], now); e != nil || b != nil {
		t.Fatal("replay")
	}
	for _, id := range []uint64{math.MaxUint64 - 1, math.MaxUint64} {
		f := Fragment(id, make([]byte, 20))[0]
		if _, e = r.Feed(f, now); e != nil {
			t.Fatal(e)
		}
	}
	f := Fragment(math.MaxUint64-1, make([]byte, 20))[0]
	if b, _ = r.Feed(f, now); b != nil {
		t.Fatal("overflow replay")
	}
}
func TestFragmentOverlapExpiryLimits(t *testing.T) {
	p := make([]byte, 1280)
	r := NewReassembler()
	now := time.Now()
	parts := Fragment(1, p)
	r.Feed(parts[0], now)
	bad := append([]byte{}, parts[1]...)
	binary.BigEndian.PutUint16(bad[11:], 900)
	if _, e := r.Feed(bad, now); e == nil {
		t.Fatal("partial overlap accepted")
	}
	r = NewReassembler()
	r.Feed(parts[0], now)
	if b, e := r.Feed(parts[1], now.Add(2*time.Second)); e != nil || b != nil {
		t.Fatal("expired packet")
	}
	r = NewReassembler()
	for id := uint64(1); id <= 1000; id++ {
		r.Feed(Fragment(id, p)[0], now)
	}
	if len(r.parts) > 64 {
		t.Fatal("unbounded fragments")
	}
}
func TestSealIdentityBinding(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	secret := make([]byte, 32)
	rand.Read(secret)
	sealed, e := Seal(key, secret, "a")
	if e != nil {
		t.Fatal(e)
	}
	got, e := Unseal(key, sealed, "a")
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatal("seal")
	}
	if _, e = Unseal(key, sealed, "b"); e == nil {
		t.Fatal("identity binding")
	}
}
func TestParamsCanonical(t *testing.T) {
	if !CheckParams(Params(0), 0) || CheckParams(Params(0), 1) {
		t.Fatal("carrier downgrade")
	}
	raw := append([]byte{}, Params(0)...)
	raw = append(raw, 0)
	if CheckParams(raw, 0) {
		t.Fatal("trailing bytes")
	}
}
func ipPacket(src, dst [4]byte) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 20)
	b[8] = 64
	b[9] = 17
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:], uint16(^sum))
	return b
}
func TestSourceAndInfrastructureProtection(t *testing.T) {
	b := ipPacket([4]byte{10, 79, 0, 2}, [4]byte{1, 1, 1, 1})
	if CheckIPv4(b, "10.79.0.2", true) != nil {
		t.Fatal("valid IPv4")
	}
	if CheckIPv4(b, "10.79.0.3", true) == nil {
		t.Fatal("source spoof")
	}
	for _, ip := range [][4]byte{{127, 0, 0, 1}, {169, 254, 169, 254}, {10, 79, 0, 3}, {192, 168, 1, 1}, {224, 0, 0, 1}, {100, 100, 100, 200}} {
		if CheckIPv4(ipPacket([4]byte{10, 79, 0, 2}, ip), "10.79.0.2", true) == nil {
			t.Fatal("private destination allowed")
		}
	}
}
func testTLS(t *testing.T, badPin bool) (*tls.Conn, *tls.Conn, ClientConfig) {
	t.Helper()
	dir := t.TempDir()
	pin, e := GenerateInner(dir)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(filepath.Join(dir, "inner.crt"), filepath.Join(dir, "inner.key"))
	if e != nil {
		t.Fatal(e)
	}
	if badPin {
		pin = base64.StdEncoding.EncodeToString(make([]byte, 32))
	}
	serverCfg := InnerTLS("")
	serverCfg.Certificates = []tls.Certificate{pair}
	rawC, rawS := net.Pipe()
	client := tls.Client(rawC, InnerTLS(pin))
	server := tls.Server(rawS, serverCfg)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { rawC.Close(); rawS.Close() })
	secret := make([]byte, 32)
	rand.Read(secret)
	gid := make([]byte, 16)
	rand.Read(gid)
	return client, server, ClientConfig{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Secret: base64.StdEncoding.EncodeToString(secret), GatewayID: base64.StdEncoding.EncodeToString(gid), IP: "10.79.0.2"}
}
func TestHybridAuthenticatedSession(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{true: "wrong-secret", false: "valid"}[wrong], func(t *testing.T) {
			c, s, cfg := testTLS(t, false)
			ch := make(chan error, 1)
			secret, _ := Decode(cfg.Secret, 32)
			gid, _ := Decode(cfg.GatewayID, 16)
			go func() {
				if e := s.HandshakeContext(context.Background()); e != nil {
					ch <- e
					return
				}
				session := NewSession(s, s.ConnectionState(), 1, nil, nil)
				defer session.Close()
				ch <- session.ServerAuth(gid, func(id string) (User, []byte, error) { return User{ID: id, IP: "10.79.0.2"}, secret, nil })
			}()
			if e := c.HandshakeContext(context.Background()); e != nil {
				t.Fatal(e)
			}
			if c.ConnectionState().CurveID != tls.X25519MLKEM768 {
				t.Fatal("non-hybrid exchange")
			}
			session := NewSession(c, c.ConnectionState(), 1, nil, nil)
			defer session.Close()
			if wrong {
				cfg.Secret = base64.StdEncoding.EncodeToString(make([]byte, 32))
			}
			err := session.ClientAuth(cfg)
			if (err != nil) != wrong {
				t.Fatalf("client auth result: %v", err)
			}
			serverErr := <-ch
			if (serverErr != nil) != wrong {
				t.Fatal("server auth")
			}
		})
	}
}
func TestWrongPinRejected(t *testing.T) {
	c, s, _ := testTLS(t, true)
	go s.HandshakeContext(context.Background())
	if c.HandshakeContext(context.Background()) == nil {
		t.Fatal("wrong pin accepted")
	}
}
func TestProofCannotCrossTLSOrCarrier(t *testing.T) {
	k := make([]byte, 32)
	g := make([]byte, 16)
	nonce := make([]byte, 32)
	e1 := make([]byte, 32)
	e2 := make([]byte, 32)
	e2[0] = 1
	p := Proof(k, g, nonce, e1, Params(1))
	if bytes.Equal(p, Proof(k, g, nonce, e2, Params(1))) || bytes.Equal(p, Proof(k, g, nonce, e1, Params(0))) {
		t.Fatal("proof reuse")
	}
}
func FuzzFrame(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 10000 {
			return
		}
		w := &Wire{ReadWriteCloser: bufferConn{bytes.NewBuffer(b)}}
		_, p, _ := w.ReadFrame()
		if len(p) > 4096 {
			t.Fatal("allocation limit")
		}
	})
}
func FuzzFragments(f *testing.F) {
	f.Add(Fragment(1, make([]byte, 20))[0])
	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewReassembler()
		r.Feed(b, time.Now())
		if len(r.parts) > 64 {
			t.Fatal("limit")
		}
	})
}

var _ io.ReadWriteCloser = bufferConn{}
