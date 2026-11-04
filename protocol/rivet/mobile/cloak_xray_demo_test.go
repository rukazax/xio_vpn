//go:build linux || android

package mobile

// Opt-in proof that both protocol stacks carry real data while they live in the
// same process (the helper links both). Requires two helper binaries:
//
//	# a real cloak server (vendored module)
//	(cd vendor/cloak && go build -o /tmp/ck-server ./cmd/ck-server)
//	# the Xray test server used by internal/xrayclient tests
//	go test -c -o /tmp/xrayclient.test ./internal/xrayclient
//	XIO_CLOAK_SERVER=/tmp/ck-server XIO_XRAY_SERVER=/tmp/xrayclient.test \
//	    go test -run TestCloakAndXrayCarryData -v ./mobile/
//
// Run it alone: it clears xrayclient's process-wide protected system dialer,
// which the in-process Xray client would otherwise keep for the rest of the
// process (the test server itself runs in its own process).

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	tmetadata "github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
	"github.com/xtls/xray-core/transport/internet"
	"xio.local/rivet/internal/xrayclient"
)

const demoUser = "b3b2eb49-e41f-41df-9761-0956785a236b"

func selfSignedCertificate(t *testing.T) (certPEM, keyPEM []string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM = strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), "\n")
	keyPEM = strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secret}))), "\n")
	return certPEM, keyPEM
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if e == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not listen on %d: %v", port, e)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// startXrayServer runs the Xray test server (a VLESS+TLS inbound with a
// freedom outbound) from the xrayclient test binary and returns its port.
func startXrayServer(t *testing.T, binary string, certPEM, keyPEM []string) int {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	certJSON, _ := json.Marshal(certPEM)
	keyJSON, _ := json.Marshal(keyPEM)
	config := fmt.Sprintf(
		`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless",`+
			`"settings":{"clients":[{"id":%q}],"decryption":"none"},`+
			`"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificate":%s,"key":%s}]}}}],`+
			`"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1"]}]}}]}`,
		port, demoUser, certJSON, keyJSON)
	server := exec.Command(binary, "-test.run=^TestServerFixture$")
	server.Env = append(os.Environ(), "XIO_TEST_SERVER="+config)
	server.Stderr = os.Stderr
	stdout, e := server.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e := server.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if scanner.Text() == "READY" {
			return port
		}
	}
	t.Fatalf("xray test server never reported READY")
	return 0
}

func xrayClientProfile(port int, certPEM []string) string {
	cert, _ := json.Marshal(certPEM)
	return fmt.Sprintf(`{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"localhost","disableSystemRoot":true,"certificates":[{"certificate":%s,"usage":"verify"}]}}}}`, port, demoUser, cert)
}

func TestCloakAndXrayCarryDataInOneProcess(t *testing.T) {
	cloakBinary := os.Getenv("XIO_CLOAK_SERVER")
	xrayBinary := os.Getenv("XIO_XRAY_SERVER")
	if cloakBinary == "" || xrayBinary == "" {
		t.Skip("set XIO_CLOAK_SERVER and XIO_XRAY_SERVER to run the combined data check")
	}
	// The Xray client would otherwise route its dial through xrayclient's
	// protected dialer, which only allows the session's own endpoint.
	internet.UseAlternativeSystemDialer(nil)

	_, echoPort := echoServer(t)
	certPEM, keyPEM := selfSignedCertificate(t)

	// ---- Xray: protobuf builder -> real TLS -> Xray server -> echo ----
	serverPort := startXrayServer(t, xrayBinary, certPEM, keyPEM)
	xraySession, e := xrayclient.Start(xrayClientProfile(serverPort, certPEM), pinnedProtector(true), 5*time.Second)
	if e != nil {
		t.Fatalf("xray session: %v", e)
	}
	defer xraySession.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	xrayConn, e := xraySession.DialContext(ctx, &tmetadata.Metadata{DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(echoPort)})
	if e != nil {
		t.Fatalf("xray dial: %v", e)
	}
	_ = xrayConn.SetDeadline(time.Now().Add(10 * time.Second))
	xrayPayload := []byte(fmt.Sprintf("XIO xray echo (%d)", time.Now().UnixNano()))
	if _, e := xrayConn.Write(xrayPayload); e != nil {
		t.Fatalf("xray write: %v", e)
	}
	xrayReply := make([]byte, len(xrayPayload))
	if _, e := io.ReadFull(xrayConn, xrayReply); e != nil {
		t.Fatalf("xray read: %v", e)
	}
	xrayConn.Close()
	if string(xrayReply) != string(xrayPayload) {
		t.Fatalf("xray echoed %q, want %q", xrayReply, xrayPayload)
	}
	t.Logf("xray data OK: %d bytes through VLESS+TLS server to echo and back", len(xrayPayload))

	// ---- Cloak, started after Xray in the same process: real ck-server ----
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
	serverConfig, _ := json.Marshal(map[string]any{
		"ProxyBook":    map[string]any{"openvpn": []string{"tcp", "127.0.0.1:" + strconv.Itoa(echoPort)}},
		"BindAddr":     []string{"127.0.0.1:" + strconv.Itoa(listenPort)},
		"BypassUID":    []string{uidText},
		"RedirAddr":    "127.0.0.1:1",
		"PrivateKey":   base64.StdEncoding.EncodeToString(key.Bytes()),
		"DatabasePath": filepath.Join(dir, "userinfo.db"),
	})
	configPath := filepath.Join(dir, "ckserver.json")
	if e := os.WriteFile(configPath, serverConfig, 0o600); e != nil {
		t.Fatal(e)
	}
	cloakServer := exec.Command(cloakBinary, "-c", configPath, "-verbosity", "error")
	cloakServer.Stdout, cloakServer.Stderr = os.Stderr, os.Stderr
	if e := cloakServer.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cloakServer.Process.Kill(); _ = cloakServer.Wait() }()
	waitForPort(t, listenPort)

	profile, _ := json.Marshal(map[string]any{"protocol": "cloak", "cloak": map[string]any{
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
	// Any finalizer left behind by the Xray session's setup would fire here.
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	localPort, e := CloakStart(string(profile), pinnedProtector(true), 5000)
	if e != nil {
		t.Fatal(e)
	}
	defer CloakStop()
	cloakClient, e := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(localPort))))
	if e != nil {
		t.Fatal(e)
	}
	defer cloakClient.Close()
	_ = cloakClient.SetDeadline(time.Now().Add(10 * time.Second))
	cloakPayload := []byte(fmt.Sprintf("XIO cloak echo (%d)", time.Now().UnixNano()))
	if _, e := cloakClient.Write(cloakPayload); e != nil {
		t.Fatalf("cloak write: %v", e)
	}
	cloakReply := make([]byte, len(cloakPayload))
	if _, e := io.ReadFull(cloakClient, cloakReply); e != nil {
		t.Fatalf("cloak read: %v", e)
	}
	if string(cloakReply) != string(cloakPayload) {
		t.Fatalf("cloak echoed %q, want %q", cloakReply, cloakPayload)
	}
	t.Logf("cloak data OK after xray started: %d bytes through real ck-server to echo and back", len(cloakPayload))
}
