package rivet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func freeTCP(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func TestBothCarriersFullSessionAndFragmentedPacket(t *testing.T) {
	// The frozen H3 profile only permits this one internal gateway target.
	probe, e := net.ListenPacket("udp4", "127.0.0.1:7444")
	if e != nil {
		t.Skip("isolated integration target port already used")
	}
	probe.Close()
	dir := t.TempDir()
	pin, e := GenerateInner(dir)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := GenerateOuter(dir, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	secret := make([]byte, 32)
	entry := make([]byte, 32)
	master := make([]byte, 32)
	gid := make([]byte, 16)
	id := make([]byte, 16)
	for _, b := range [][]byte{secret, entry, master, gid, id} {
		rand.Read(b)
	}
	uid := hex.EncodeToString(id)
	sealed, e := Seal(master, secret, uid)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "seal.key"), master, 0600)
	WriteJSON(filepath.Join(dir, "users.json"), map[string]User{uid: {ID: uid, Sealed: sealed, IP: "10.79.0.2"}})
	token := base64.StdEncoding.EncodeToString(entry)
	WriteJSON(filepath.Join(dir, "tokens.json"), map[string]string{uid: TokenHash(token)})
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Service</title>"), 0600)
	tcp := freeTCP(t)
	entryAddr := freeTCP(t)
	a, b := net.Pipe()
	defer b.Close()
	gcfg := GatewayConfig{TCP: tcp, UDP: "127.0.0.1:7444", Cert: filepath.Join(dir, "inner.crt"), Key: filepath.Join(dir, "inner.key"), Users: filepath.Join(dir, "users.json"), Seal: filepath.Join(dir, "seal.key"), Stats: filepath.Join(dir, "stats.json"), GatewayID: base64.StdEncoding.EncodeToString(gid)}
	gateway, e := NewGateway(gcfg, a)
	if e != nil {
		t.Fatal(e)
	}
	entryCfg := EntryConfig{Listen: entryAddr, Cert: filepath.Join(dir, "outer.crt"), Key: filepath.Join(dir, "outer.key"), Tokens: filepath.Join(dir, "tokens.json"), GatewayTCP: tcp, GatewayUDP: "127.0.0.1:7444", Page: filepath.Join(dir, "index.html")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDone := make(chan struct{})
	go func() { defer close(gatewayDone); gateway.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-gatewayDone:
		case <-time.After(3 * time.Second):
			t.Error("gateway shutdown deadline")
		}
	})
	go NewEntry(entryCfg).Serve(ctx)
	// Wait for the loopback listener, without routing any host traffic.
	for i := 0; i < 50; i++ {
		c, e := net.DialTimeout("tcp", entryAddr, 50*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, proto := range []string{"rivet-s1", "rivet-h3"} {
		t.Run(proto, func(t *testing.T) {
			cfg := ClientConfig{Protocol: proto, Endpoint: entryAddr, ServerName: "127.0.0.1", Pin: pin, GatewayID: gcfg.GatewayID, ID: uid, Secret: base64.StdEncoding.EncodeToString(secret), EntryToken: token, IP: "10.79.0.2", OuterCA: ca}
			client, e := Dial(ctx, cfg, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			packet := mtuPacket([4]byte{10, 79, 0, 2}, [4]byte{1, 1, 1, 1})
			received := make(chan []byte, 1)
			go func() { buf := make([]byte, 1280); n, _ := b.Read(buf); received <- buf[:n] }()
			if e = client.SendPacket(packet); e != nil {
				t.Fatal(e)
			}
			select {
			case got := <-received:
				if !bytes.Equal(got, packet) {
					t.Fatal("packet modified")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("forwarding deadline")
			}
			response := mtuPacket([4]byte{1, 1, 1, 1}, [4]byte{10, 79, 0, 2})
			go b.Write(response)
			done := make(chan []byte, 1)
			go func() { got, _ := client.ReadPacket(); done <- got }()
			select {
			case got := <-done:
				if !bytes.Equal(got, response) {
					t.Fatal("return packet")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("return deadline")
			}

			good := cfg
			for _, change := range []func(*ClientConfig){
				func(c *ClientConfig) { c.Secret = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
				func(c *ClientConfig) { c.EntryToken = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
				func(c *ClientConfig) { c.ServerName = "wrong.invalid" },
				func(c *ClientConfig) { c.OuterCA = "" },
			} {
				badCfg := good
				change(&badCfg)
				if bad, e := Dial(ctx, badCfg, nil); e == nil {
					bad.Close()
					t.Fatal("invalid authentication accepted")
				}
			}
			// Independent public CA and inner pin authentication, both required.
			cfg.Pin = base64.StdEncoding.EncodeToString(make([]byte, 32))
			if bad, e := Dial(ctx, cfg, nil); e == nil {
				bad.Close()
				t.Fatal("wrong inner pin accepted")
			}

			// Revocation terminates an already authenticated session, not just new logins.
			if e := WriteJSON(filepath.Join(dir, "users.json"), map[string]User{}); e != nil {
				t.Fatal(e)
			}
			revoked := make(chan error, 1)
			go func() { _, e := client.ReadPacket(); revoked <- e }()
			select {
			case e := <-revoked:
				if e == nil {
					t.Fatal("revoked session remained readable")
				}
			case <-time.After(6 * time.Second):
				t.Fatal("revocation exceeded deadline")
			}
			if bad, e := Dial(ctx, good, nil); e == nil {
				bad.Close()
				t.Fatal("revoked credentials accepted")
			}
			if e := WriteJSON(filepath.Join(dir, "users.json"), map[string]User{uid: {ID: uid, Sealed: sealed, IP: "10.79.0.2"}}); e != nil {
				t.Fatal(e)
			}
		})
	}
	_ = io.EOF
}

func mtuPacket(src, dst [4]byte) []byte {
	b := append(ipPacket(src, dst), make([]byte, 1260)...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[10] = 0
	b[11] = 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:], uint16(^sum))
	for i := 28; i < len(b); i++ {
		b[i] = byte(i)
	}
	binary.BigEndian.PutUint16(b[24:], 1260)
	return b
}
