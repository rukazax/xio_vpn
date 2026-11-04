//go:build linux || android

package mobile

// Opt-in end-to-end check of the cloak data path: a real cloak server
// (github.com/cbeuw/Cloak cmd/ck-server) forwards the client stream to a local
// echo server. Requires XIO_CLOAK_SERVER=/path/to/ck-server; skipped otherwise
// because the vendored cloak module only exposes the client API, so the test
// cannot start a server in-process.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func echoServer(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener, listener.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func TestCloakRoundTripThroughRealServer(t *testing.T) {
	serverBinary := os.Getenv("XIO_CLOAK_SERVER")
	if serverBinary == "" {
		t.Skip("set XIO_CLOAK_SERVER to a ck-server binary to run the cloak round trip")
	}
	_, echoPort := echoServer(t)

	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	uid := make([]byte, 16)
	if _, e := rand.Read(uid); e != nil {
		t.Fatal(e)
	}
	uidText := base64.StdEncoding.EncodeToString(uid)
	listenPort := freePort(t)
	dir := t.TempDir()
	serverConfig := map[string]any{
		"ProxyBook":    map[string]any{"openvpn": []string{"tcp", "127.0.0.1:" + strconv.Itoa(echoPort)}},
		"BindAddr":     []string{"127.0.0.1:" + strconv.Itoa(listenPort)},
		"BypassUID":    []string{uidText},
		"RedirAddr":    "127.0.0.1:1",
		"PrivateKey":   base64.StdEncoding.EncodeToString(key.Bytes()),
		"DatabasePath": filepath.Join(dir, "userinfo.db"),
	}
	encoded, e := json.Marshal(serverConfig)
	if e != nil {
		t.Fatal(e)
	}
	configPath := filepath.Join(dir, "ckserver.json")
	if e := os.WriteFile(configPath, encoded, 0o600); e != nil {
		t.Fatal(e)
	}
	server := exec.Command(serverBinary, "-c", configPath, "-verbosity", "error")
	server.Stdout, server.Stderr = os.Stderr, os.Stderr
	if e := server.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = server.Process.Kill(); _ = server.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)), 200*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cloak server did not listen: %v", e)
		}
		time.Sleep(50 * time.Millisecond)
	}

	profile, e := json.Marshal(map[string]any{"protocol": "cloak", "cloak": map[string]any{
		"Transport":        "direct",
		"ProxyMethod":      "openvpn",
		"EncryptionMethod": "aes-gcm",
		"UID":              uidText,
		"PublicKey":        base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
		"ServerName":       "example.com",
		"RemoteHost":       "127.0.0.1",
		"RemotePort":       strconv.Itoa(listenPort),
		"NumConn":          1,
		"BrowserSig":       "chrome",
		"StreamTimeout":    10,
	}})
	if e != nil {
		t.Fatal(e)
	}
	localPort, e := CloakStart(string(profile), pinnedProtector(true), 5000)
	if e != nil {
		t.Fatal(e)
	}
	defer CloakStop()
	client, e := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(localPort))))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	payload := []byte(fmt.Sprintf("XIO cloak echo via real server (%d)", time.Now().UnixNano()))
	if _, e := client.Write(payload); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, len(payload))
	if _, e := io.ReadFull(client, reply); e != nil {
		t.Fatalf("cloak round trip: %v", e)
	}
	if string(reply) != string(payload) {
		t.Fatalf("cloak echoed %q, want %q", reply, payload)
	}
	t.Logf("cloak round trip OK: %d bytes through real ck-server to echo and back", len(payload))
}
