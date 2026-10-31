package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"xio.local/rivet/internal/rivet"
)

func fail(e error) { fmt.Fprintln(os.Stderr, "rivet operation failed:", e); os.Exit(1) }
func random(n int) []byte {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		fail(e)
	}
	return b
}
func jsonOut(v any) {
	if e := json.NewEncoder(os.Stdout).Encode(v); e != nil {
		fail(e)
	}
}
func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("subcommand required"))
	}
	cmd := os.Args[1]
	f := flag.NewFlagSet(cmd, flag.ExitOnError)
	config := f.String("config", "", "configuration path")
	dir := f.String("dir", "/etc/xio-rivet", "owned state directory")
	name := f.String("name", "", "server identity")
	tun := f.String("tun", "xiorivet", "persistent TUN")
	f.Parse(os.Args[2:])
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch cmd {
	case "gateway":
		var c rivet.GatewayConfig
		if e := rivet.ReadJSON(*config, &c); e != nil {
			fail(e)
		}
		dev, e := rivet.OpenTUN(*tun)
		if e != nil {
			fail(e)
		}
		g, e := rivet.NewGateway(c, dev)
		if e != nil {
			dev.Close()
			fail(e)
		}
		if e = g.Serve(ctx); e != nil {
			fail(e)
		}
	case "entry":
		var c rivet.EntryConfig
		if e := rivet.ReadJSON(*config, &c); e != nil {
			fail(e)
		}
		if e := rivet.NewEntry(c).Serve(ctx); e != nil {
			fail(e)
		}
	case "outer":
		public, e := rivet.GenerateOuter(*dir, *name)
		if e != nil {
			fail(e)
		}
		jsonOut(map[string]string{"outerCA": public, "serverName": *name})
	case "init":
		if _, e := os.Stat(filepath.Join(*dir, "public.json")); e == nil {
			var p any
			if e = rivet.ReadJSON(filepath.Join(*dir, "public.json"), &p); e != nil {
				fail(e)
			}
			jsonOut(p)
			return
		}
		if e := os.MkdirAll(*dir, 0700); e != nil {
			fail(e)
		}
		pin, e := rivet.GenerateInner(*dir)
		if e != nil {
			fail(e)
		}
		if e = os.WriteFile(filepath.Join(*dir, "seal.key"), random(32), 0600); e != nil {
			fail(e)
		}
		gid := base64.StdEncoding.EncodeToString(random(16))
		g := rivet.GatewayConfig{TCP: "127.0.0.1:7443", UDP: "127.0.0.1:7444", Cert: filepath.Join(*dir, "inner.crt"), Key: filepath.Join(*dir, "inner.key"), Users: filepath.Join(*dir, "users.json"), Seal: filepath.Join(*dir, "seal.key"), Stats: "/var/lib/xio-rivet/stats.json", GatewayID: gid}
		eCfg := rivet.EntryConfig{Listen: ":8443", Cert: filepath.Join(*dir, "outer.crt"), Key: filepath.Join(*dir, "outer.key"), Tokens: filepath.Join(*dir, "tokens.json"), GatewayTCP: g.TCP, GatewayUDP: g.UDP, Page: filepath.Join(*dir, "index.html")}
		p := map[string]any{"pin": pin, "gatewayId": gid, "version": 1, "port": 8443, "protocols": []string{"rivet-h3", "rivet-s1"}}
		for path, value := range map[string]any{"gateway.json": g, "entry.json": eCfg, "users.json": map[string]rivet.User{}, "tokens.json": map[string]string{}, "public.json": p} {
			if e = rivet.WriteJSON(filepath.Join(*dir, path), value); e != nil {
				fail(e)
			}
		}
		jsonOut(p)
	case "user":
		lock, e := os.OpenFile(filepath.Join(*dir, "users.lock"), os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			fail(e)
		}
		defer lock.Close()
		if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX); e != nil {
			fail(e)
		}

		var req struct {
			Action     string `json:"action"`
			ID         string `json:"id"`
			Secret     string `json:"secret"`
			EntryToken string `json:"entryToken"`
			Slot       int    `json:"slot"`
		}
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, 65537))
		if e != nil || len(raw) > 65536 {
			fail(rivet.ErrProtocol)
		}
		if e = json.Unmarshal(raw, &req); e != nil {
			fail(e)
		}
		if e = rivet.ParseID(req.ID); e != nil {
			fail(e)
		}
		var users map[string]rivet.User
		var tokens map[string]string
		if e = rivet.ReadJSON(filepath.Join(*dir, "users.json"), &users); e != nil {
			fail(e)
		}
		if e = rivet.ReadJSON(filepath.Join(*dir, "tokens.json"), &tokens); e != nil {
			fail(e)
		}
		switch req.Action {
		case "add":
			if _, ok := users[req.ID]; ok {
				fail(fmt.Errorf("identity exists"))
			}
			if req.Slot < 2 || req.Slot > 254 || len(users) >= 4096 {
				fail(rivet.ErrProtocol)
			}
			secret, e := rivet.Decode(req.Secret, 32)
			if e != nil {
				fail(e)
			}
			entry, e := rivet.Decode(req.EntryToken, 32)
			if e != nil {
				fail(e)
			}
			// Compare decoded bytes: a non-canonical base64 spelling of the same
			// 32 bytes must not create a user whose secret equals its entry token.
			if subtle.ConstantTimeCompare(secret, entry) == 1 {
				fail(rivet.ErrProtocol)
			}
			master, e := os.ReadFile(filepath.Join(*dir, "seal.key"))
			if e != nil {
				fail(e)
			}
			sealed, e := rivet.Seal(master, secret, req.ID)
			if e != nil {
				fail(e)
			}
			ip := fmt.Sprintf("10.79.0.%d", req.Slot)
			for _, u := range users {
				if !u.Revoked && u.IP == ip {
					fail(fmt.Errorf("address in use"))
				}
			}
			users[req.ID] = rivet.User{ID: req.ID, IP: ip, Sealed: sealed}
			tokens[req.ID] = rivet.TokenHash(req.EntryToken)
		case "revoke":
			delete(users, req.ID)
			delete(tokens, req.ID)

		default:
			fail(rivet.ErrProtocol)
		}
		if e = rivet.WriteJSON(filepath.Join(*dir, "users.json"), users); e != nil {
			fail(e)
		}
		if e = rivet.WriteJSON(filepath.Join(*dir, "tokens.json"), tokens); e != nil {
			fail(e)
		}
		jsonOut(map[string]bool{"ok": true})
	case "probe":
		var c rivet.ClientConfig
		if e := rivet.ReadJSON(*config, &c); e != nil {
			fail(e)
		}
		probeCtx, end := context.WithTimeout(ctx, 15*time.Second)
		defer end()
		// Explicit diagnostic resolution: the protected VPN path never resolves
		// hostnames with the system resolver.
		s, e := rivet.DialDiagnostic(probeCtx, c, 15*time.Second)
		if e != nil {
			fail(e)
		}
		defer s.Close()
		packet := DNSPacket(net.ParseIP(c.IP).To4())
		if e = s.SendPacket(packet); e != nil {
			fail(e)
		}
		go func() { <-probeCtx.Done(); s.Close() }()
		b, e := s.ReadPacket()
		if e != nil {
			fail(e)
		}
		if len(b) < 40 || b[9] != 17 || b[12] != 1 || b[13] != 1 || b[14] != 1 || b[15] != 1 || b[28] != 0x71 || b[29] != 0x31 {
			fail(rivet.ErrProtocol)
		}
		jsonOut(map[string]any{"protocol": c.Protocol, "dnsResponse": true, "responseBytes": len(b), "tlsVersion": s.State.Version, "curve": s.State.CurveID, "cipherSuite": s.State.CipherSuite, "gatewayPinVerified": true, "handshakeComplete": s.State.HandshakeComplete, "resumed": s.State.DidResume})
	case "new-secret":
		jsonOut(map[string]string{"id": hex.EncodeToString(random(16)), "secret": base64.StdEncoding.EncodeToString(random(32)), "entryToken": base64.StdEncoding.EncodeToString(random(32))})
	default:
		fail(fmt.Errorf("unknown subcommand"))
	}
}
