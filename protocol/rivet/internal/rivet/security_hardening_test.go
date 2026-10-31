package rivet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// base64Alias returns a non-canonical spelling of raw that Go's standard
// decoder accepts as the same bytes. ClientConfig must not use string equality
// to detect a reused entry token and client secret.
func base64Alias(t *testing.T, raw []byte) string {
	t.Helper()
	canonical := base64.StdEncoding.EncodeToString(raw)
	end := strings.IndexByte(canonical, '=')
	if end < 0 {
		t.Fatal("fixture is not padded base64")
	}
	pos := end - 1
	index := strings.IndexByte(b64alphabet, canonical[pos])
	if index < 0 {
		t.Fatal("fixture is not base64")
	}
	for delta := 1; delta < 64; delta++ {
		candidate := []byte(canonical)
		candidate[pos] = b64alphabet[(index+delta)%64]
		decoded, err := base64.StdEncoding.DecodeString(string(candidate))
		if err == nil && bytes.Equal(decoded, raw) && string(candidate) != canonical {
			return string(candidate)
		}
	}
	t.Fatal("no non-canonical encoding found")
	return ""
}

func TestClientConfigRejectsBase64AliasedKeyReuse(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	canonical := base64.StdEncoding.EncodeToString(secret)
	alias := base64Alias(t, secret)
	if canonical == alias {
		t.Fatal("fixture did not change the encoding")
	}
	decoded, err := Decode(alias, 32)
	if err != nil || !bytes.Equal(decoded, secret) {
		t.Fatal("fixture alias does not decode to the same secret")
	}
	config := hostnameClientConfig("rivet-s1", "fr-host.fr:8443", "fr-host.fr")
	config.Secret = canonical
	config.EntryToken = alias
	if err := config.Validate(); err == nil {
		t.Fatal("reused key accepted under a different base64 spelling")
	}
}

func TestClientAuthRejectsServerProtocolViolations(t *testing.T) {
	for _, mode := range []string{"short-challenge", "wrong-gateway", "short-auth-ok", "bad-configure", "valid"} {
		t.Run(mode, func(t *testing.T) {
			clientRaw, serverRaw, config := testTLS(t, false)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			serverDone := make(chan error, 1)
			go func() {
				if err := serverRaw.HandshakeContext(ctx); err != nil {
					serverDone <- err
					return
				}
				server := NewSession(serverRaw, serverRaw.ConnectionState(), 1, nil, nil)
				defer server.Close()
				serverDone <- clientAuthServerScript(server, config, mode)
			}()
			if err := clientRaw.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			client := NewSession(clientRaw, clientRaw.ConnectionState(), 1, nil, nil)
			defer client.Close()
			err := client.ClientAuth(config)
			if mode == "valid" {
				if err != nil {
					t.Fatalf("valid server script rejected: %v", err)
				}
				if client.ID != config.ID || client.IP != config.IP || client.handshake.Load() == 0 {
					t.Fatal("authenticated session state was not recorded")
				}
			} else if err == nil {
				t.Fatal("server protocol violation accepted")
			}
			select {
			case serverErr := <-serverDone:
				if mode == "valid" && serverErr != nil {
					t.Fatalf("server script: %v", serverErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("server script did not finish")
			}
		})
	}
}

func clientAuthServerScript(s *Session, config ClientConfig, mode string) error {
	gateway, err := Decode(config.GatewayID, 16)
	if err != nil {
		return err
	}
	challenge := make([]byte, 48)
	copy(challenge, gateway)
	if _, err = rand.Read(challenge[16:]); err != nil {
		return err
	}
	switch mode {
	case "short-challenge":
		return s.Wire.Send(Challenge, challenge[:47])
	case "wrong-gateway":
		challenge[0] ^= 0xff
		return s.Wire.Send(Challenge, challenge)
	}
	if err = s.Wire.Send(Challenge, challenge); err != nil {
		return err
	}
	if _, err = s.Wire.Expect(Auth); err != nil {
		return err
	}
	switch mode {
	case "short-auth-ok":
		return s.Wire.Send(AuthOK, make([]byte, 15))
	case "bad-configure":
		if err = s.Wire.Send(AuthOK, make([]byte, 16)); err != nil {
			return err
		}
		return s.Wire.Send(Configure, []byte{0})
	case "valid":
		sid := make([]byte, 16)
		if _, err = rand.Read(sid); err != nil {
			return err
		}
		if err = s.Wire.Send(AuthOK, sid); err != nil {
			return err
		}
		ip := net.ParseIP(config.IP).To4()
		configuration := EncodeConfig(ip, sid)
		if err = s.Wire.Send(Configure, configuration); err != nil {
			return err
		}
		ack, err := s.Wire.Expect(ConfigACK)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(configuration)
		if !bytes.Equal(ack, hash[:]) {
			return ErrProtocol
		}
		return nil
	default:
		return ErrProtocol
	}
}

func TestServerAuthRejectsForgedAndRevokedCredentials(t *testing.T) {
	cases := []struct {
		name       string
		lookupErr  bool
		revoked    bool
		proof      []byte
		params     []byte
		wantLookup bool
	}{
		{name: "unknown-identity-zero-secret", lookupErr: true, proof: make([]byte, 32), params: Params(1), wantLookup: true},
		{name: "wrong-secret", proof: make([]byte, 32), params: Params(1), wantLookup: true},
		{name: "carrier-downgrade", params: Params(0), wantLookup: false},
		{name: "trailing-parameters", params: append(Params(1), 0), wantLookup: false},
		{name: "revoked-user", revoked: true, params: Params(1), wantLookup: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientRaw, serverRaw, config := testTLS(t, false)
			secret, err := Decode(config.Secret, 32)
			if err != nil {
				t.Fatal(err)
			}
			if tc.proof == nil {
				tc.proof = secret
			}
			gateway, err := Decode(config.GatewayID, 16)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var calls atomic.Int32
			lookup := func(id string) (User, []byte, error) {
				calls.Add(1)
				if tc.lookupErr {
					return User{}, nil, errors.New("unknown identity")
				}
				return User{ID: id, IP: "10.79.0.2", Revoked: tc.revoked}, secret, nil
			}
			serverDone := make(chan error, 1)
			go func() {
				if err := serverRaw.HandshakeContext(ctx); err != nil {
					serverDone <- err
					return
				}
				server := NewSession(serverRaw, serverRaw.ConnectionState(), 1, nil, nil)
				defer server.Close()
				serverDone <- server.ServerAuth(gateway, lookup)
			}()
			if err := clientRaw.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			client := NewSession(clientRaw, clientRaw.ConnectionState(), 1, nil, nil)
			defer client.Close()
			challenge, err := client.Wire.Expect(Challenge)
			if err != nil {
				t.Fatal(err)
			}
			exporter, err := Exporter(client.State)
			if err != nil {
				t.Fatal(err)
			}
			id, err := hex.DecodeString(config.ID)
			if err != nil {
				t.Fatal(err)
			}
			body := append(append(append([]byte{}, id...), tc.params...), Proof(tc.proof, challenge[:16], challenge[16:], exporter, tc.params)...)
			if err = client.Wire.Send(Auth, body); err != nil {
				t.Fatal(err)
			}
			// A rejected authentication must not produce AuthOK or Configure.
			if kind, _, readErr := client.Wire.ReadFrame(); readErr == nil {
				t.Fatalf("server sent frame %d for rejected credentials", kind)
			}
			select {
			case serverErr := <-serverDone:
				if serverErr == nil {
					t.Fatal("forged or revoked credentials accepted")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("server authentication did not finish")
			}
			if got := calls.Load(); (got > 0) != tc.wantLookup {
				t.Fatalf("lookup calls = %d, want call before lookup=%v", got, tc.wantLookup)
			}
		})
	}
}

func TestGatewayLookupRejectsRevokedAndMalformedCredentials(t *testing.T) {
	dir := t.TempDir()
	master := make([]byte, 32)
	secret := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	sealPath := filepath.Join(dir, "seal.key")
	if err := os.WriteFile(sealPath, master, 0600); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 16)
	revoked := strings.Repeat("cd", 16)
	badIP := strings.Repeat("ef", 16)
	wrongID := strings.Repeat("01", 16)
	badSeal := strings.Repeat("23", 16)
	goodSeal, err := Seal(master, secret, id)
	if err != nil {
		t.Fatal(err)
	}
	revokedSeal, err := Seal(master, secret, revoked)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]User{
		id:      {ID: id, Sealed: goodSeal, IP: "10.79.0.2"},
		revoked: {ID: revoked, Sealed: revokedSeal, IP: "10.79.0.3", Revoked: true},
		badIP:   {ID: badIP, Sealed: goodSeal, IP: "127.0.0.1"},
		wrongID: {ID: id, Sealed: goodSeal, IP: "10.79.0.4"},
		badSeal: {ID: badSeal, Sealed: goodSeal, IP: "10.79.0.5"},
	}
	usersPath := filepath.Join(dir, "users.json")
	if err := WriteJSON(usersPath, users); err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGateway(GatewayConfig{
		Seal:      sealPath,
		Users:     usersPath,
		Stats:     filepath.Join(dir, "stats.json"),
		GatewayID: base64.StdEncoding.EncodeToString(make([]byte, 16)),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	user, key, err := gateway.Lookup(id)
	if err != nil || user.ID != id || !bytes.Equal(key, secret) {
		t.Fatalf("valid identity rejected: user=%+v err=%v", user, err)
	}
	for name, identity := range map[string]string{
		"revoked":  revoked,
		"bad-ip":   badIP,
		"wrong-id": wrongID,
		"bad-seal": badSeal,
		"unknown":  strings.Repeat("45", 16),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := gateway.Lookup(identity); err == nil {
				t.Fatal("invalid credential accepted")
			}
		})
	}
}

func TestEntryAllowedCredentialLifecycle(t *testing.T) {
	dir := t.TempDir()
	token := make([]byte, 32)
	other := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	tokenString := base64.StdEncoding.EncodeToString(token)
	otherString := base64.StdEncoding.EncodeToString(other)
	tokens := filepath.Join(dir, "tokens.json")
	if err := WriteJSON(tokens, map[string]string{"user": TokenHash(tokenString)}); err != nil {
		t.Fatal(err)
	}
	entry := NewEntry(EntryConfig{Tokens: tokens})
	request := func(authorization, remote string) *http.Request {
		r := httptest.NewRequest("GET", "https://service.test/api/stream", nil)
		r.Header.Set("Upgrade", "websocket")
		r.RemoteAddr = remote
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		return r
	}
	if !entry.allowed(request("Bearer "+tokenString, "198.51.100.10:1")) {
		t.Fatal("valid token rejected")
	}
	for name, authorization := range map[string]string{
		"missing":      "",
		"wrong-token":  "Bearer " + otherString,
		"lower-bearer": "bearer " + tokenString,
		"not-base64":   "Bearer " + strings.Repeat("!", 44),
		"too-long":     "Bearer " + strings.Repeat("a", 200),
	} {
		t.Run(name, func(t *testing.T) {
			if entry.allowed(request(authorization, "198.51.100.11:1")) {
				t.Fatal("invalid authorization accepted")
			}
		})
	}
	// The first request consumed one token from this address bucket. The bucket
	// starts at 20 and must reject the next request after exactly 20.
	for i := 1; i <= 20; i++ {
		if !entry.allowed(request("Bearer "+tokenString, "198.51.100.12:1")) {
			t.Fatalf("request %d unexpectedly rate-limited", i+1)
		}
	}
	if entry.allowed(request("Bearer "+tokenString, "198.51.100.12:1")) {
		t.Fatal("rate limit was not enforced")
	}
	if err := WriteJSON(tokens, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if entry.allowed(request("Bearer "+tokenString, "198.51.100.13:1")) {
		t.Fatal("revoked token accepted")
	}
	if TokenHash("not-base64") != "" || TokenHash(base64.StdEncoding.EncodeToString(make([]byte, 31))) != "" {
		t.Fatal("malformed token hash accepted")
	}
}

func TestWireReadFrameTruncationAndBounds(t *testing.T) {
	header := func(kind, reserved byte, length uint32) []byte {
		b := make([]byte, 6)
		b[0], b[1] = kind, reserved
		binary.BigEndian.PutUint32(b[2:], length)
		return b
	}
	cases := []struct {
		name         string
		raw          []byte
		wantProtocol bool
		wantKind     byte
		wantLen      int
	}{
		{name: "empty", raw: nil},
		{name: "short-header", raw: header(Challenge, 0, 0)[:5]},
		{name: "short-payload", raw: append(header(Challenge, 0, 10), 1, 2, 3)},
		{name: "challenge-oversized", raw: header(Challenge, 0, 4097), wantProtocol: true},
		{name: "packet-oversized", raw: header(IPPacket, 0, MTU+1), wantProtocol: true},
		{name: "padding-empty", raw: header(Padding, 0, 0), wantProtocol: true},
		{name: "unknown-type", raw: header(7, 0, 0), wantProtocol: true},
		{name: "reserved-byte", raw: header(Challenge, 1, 0), wantProtocol: true},
		{name: "length-overflow", raw: header(Challenge, 0, ^uint32(0)), wantProtocol: true},
		{name: "challenge-max", raw: append(header(Challenge, 0, 4096), make([]byte, 4096)...), wantKind: Challenge, wantLen: 4096},
		{name: "packet-max", raw: append(header(IPPacket, 0, MTU), make([]byte, MTU)...), wantKind: IPPacket, wantLen: MTU},
		{name: "padding-valid", raw: append(header(Padding, 0, 1), 0), wantKind: Padding, wantLen: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := &Wire{ReadWriteCloser: bufferConn{bytes.NewBuffer(tc.raw)}}
			kind, payload, err := wire.ReadFrame()
			if tc.wantProtocol {
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("error = %v, want protocol violation", err)
				}
				return
			}
			if tc.wantKind == 0 {
				if err == nil {
					t.Fatalf("truncated frame accepted: kind=%d len=%d", kind, len(payload))
				}
				return
			}
			if err != nil || kind != tc.wantKind || len(payload) != tc.wantLen {
				t.Fatalf("frame = %d/%d/%v, want %d/%d", kind, len(payload), err, tc.wantKind, tc.wantLen)
			}
		})
	}
}

func TestWireSendBounds(t *testing.T) {
	wire := &Wire{ReadWriteCloser: bufferConn{bytes.NewBuffer(nil)}}
	for name, test := range map[string]struct {
		kind    byte
		payload []byte
	}{
		"challenge-oversized": {Challenge, make([]byte, 4097)},
		"packet-oversized":    {IPPacket, make([]byte, MTU+1)},
		"unknown-type":        {7, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if err := wire.Send(test.kind, test.payload); !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v, want protocol violation", err)
			}
		})
	}
	if err := wire.Send(Challenge, make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
}

func TestReassemblerRejectsTamperAndReplay(t *testing.T) {
	packet := make([]byte, MTU)
	if _, err := rand.Read(packet); err != nil {
		t.Fatal(err)
	}
	parts := Fragment(1, packet)
	now := time.Now()
	reassembler := NewReassembler()
	if got, err := reassembler.Feed(parts[0], now); err != nil || got != nil {
		t.Fatalf("partial fragment failed: %v", err)
	}
	duplicate := append([]byte{}, parts[0]...)
	if got, err := reassembler.Feed(duplicate, now); err != nil || got != nil {
		t.Fatalf("duplicate fragment not idempotent: %v", err)
	}
	tampered := append([]byte{}, parts[0]...)
	tampered[15] ^= 0xff
	if _, err := reassembler.Feed(tampered, now); !errors.Is(err, ErrProtocol) {
		t.Fatalf("tampered duplicate accepted: %v", err)
	}
	reassembler = NewReassembler()
	if _, err := reassembler.Feed(parts[0], now); err != nil {
		t.Fatal(err)
	}
	if got, err := reassembler.Feed(parts[1], now); err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("reassembly failed: %v", err)
	}
	if got, err := reassembler.Feed(parts[0], now); err != nil || got != nil {
		t.Fatalf("completed packet replayed: %v", err)
	}
	bad := []struct {
		name string
		data []byte
	}{
		{name: "short", data: parts[0][:15]},
		{name: "zero-id", data: append([]byte{}, parts[0]...)},
		{name: "length-mismatch", data: append(append([]byte{}, parts[0]...), 0)},
	}
	binary.BigEndian.PutUint64(bad[1].data[1:], 0)
	binary.BigEndian.PutUint16(bad[2].data[9:], 19)
	for _, tc := range bad {
		if _, err := NewReassembler().Feed(tc.data, now); !errors.Is(err, ErrProtocol) {
			t.Fatalf("%s accepted: %v", tc.name, err)
		}
	}
}

func TestSessionRejectsDataBeforeAuthentication(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	session := NewSession(left, tls.ConnectionState{}, 1, nil, nil)
	if _, err := session.ReadPacket(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("pre-auth read: %v", err)
	}
	if err := session.SendPacket(make([]byte, 20)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("pre-auth send: %v", err)
	}
}

func TestSessionCloseUnblocksRead(t *testing.T) {
	left, right := net.Pipe()
	session := NewSession(left, tls.ConnectionState{}, 1, nil, func() { right.Close() })
	session.handshake.Store(1)
	readDone := make(chan error, 1)
	go func() {
		_, err := session.ReadPacket()
		readDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	session.Close()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("closed session returned a packet")
		}
	case <-time.After(time.Second):
		t.Fatal("session close did not unblock the reader")
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("session context was not canceled")
	}
	session.Close()
}

func TestExporterRejectsIncompleteState(t *testing.T) {
	if _, err := Exporter(tls.ConnectionState{}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("incomplete TLS state accepted: %v", err)
	}
}

func TestInnerTLSRejectsExpiredPinnedCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "XIO RIVET gateway"},
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	pin := base64.StdEncoding.EncodeToString(hash[:])
	serverConfig := InnerTLS("")
	serverConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	client := tls.Client(clientRaw, InnerTLS(pin))
	server := tls.Server(serverRaw, serverConfig)
	client.SetDeadline(now.Add(3 * time.Second))
	server.SetDeadline(now.Add(3 * time.Second))
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()
	if err := client.Handshake(); err == nil {
		t.Fatal("expired certificate accepted under a valid pin")
	}
	<-serverDone
}

func TestOuterTrustSelectionAndInnerPin(t *testing.T) {
	config, err := outerTLSConfig(ClientConfig{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if config.RootCAs != nil {
		t.Fatal("empty OuterCA must leave system roots in use")
	}
	dir := t.TempDir()
	ca, err := GenerateOuter(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	config, err = outerTLSConfig(ClientConfig{ServerName: "example.com", OuterCA: ca})
	if err != nil {
		t.Fatal(err)
	}
	if config.RootCAs == nil {
		t.Fatal("explicit OuterCA must replace system roots")
	}
	pinned := InnerTLS(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if !pinned.InsecureSkipVerify || pinned.VerifyConnection == nil {
		t.Fatal("pinned inner TLS must not use system-root verification")
	}
	server := InnerTLS("")
	if server.InsecureSkipVerify || server.VerifyConnection != nil {
		t.Fatal("server inner TLS must not enable client certificate pinning")
	}
}

func TestDecodeConfigRejectsServerOverrides(t *testing.T) {
	sid := make([]byte, 16)
	ip := net.ParseIP("10.79.0.2").To4()
	good := EncodeConfig(ip, sid)
	if err := DecodeConfig(good, sid, ip); err != nil {
		t.Fatal(err)
	}
	otherSID := make([]byte, 16)
	otherSID[0] = 1
	for name, bad := range map[string][]byte{
		"trailing":  append(append([]byte{}, good...), 0),
		"other-sid": EncodeConfig(ip, otherSID),
		"other-ip":  EncodeConfig(net.ParseIP("10.79.0.3").To4(), sid),
	} {
		t.Run(name, func(t *testing.T) {
			if err := DecodeConfig(bad, sid, ip); err == nil {
				t.Fatal("server override accepted")
			}
		})
	}
}

func FuzzCheckIP(f *testing.F) {
	f.Add([]byte{}, "", false)
	f.Add(ipPacket([4]byte{10, 79, 0, 2}, [4]byte{1, 1, 1, 1}), "10.79.0.2", true)
	f.Add(packet6("fd79:1::2", "2001:4860:4860::8888"), "10.79.0.2", true)
	f.Fuzz(func(t *testing.T, packet []byte, source string, publicOnly bool) {
		if len(packet) > 65536 {
			return
		}
		_ = CheckIP(packet, source, publicOnly)
		_ = Destination(packet)
	})
}
