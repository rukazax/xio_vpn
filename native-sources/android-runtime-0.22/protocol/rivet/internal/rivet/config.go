package rivet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type User struct {
	ID      string `json:"id"`
	Sealed  string `json:"sealed"`
	IP      string `json:"ip"`
	Revoked bool   `json:"revoked"`
}
type GatewayConfig struct {
	TCP       string `json:"tcp"`
	UDP       string `json:"udp"`
	Cert      string `json:"cert"`
	Key       string `json:"key"`
	Users     string `json:"users"`
	Seal      string `json:"seal"`
	Stats     string `json:"stats"`
	GatewayID string `json:"gatewayId"`
}
type EntryConfig struct {
	Listen     string `json:"listen"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	Tokens     string `json:"tokens"`
	GatewayTCP string `json:"gatewayTcp"`
	GatewayUDP string `json:"gatewayUdp"`
	Page       string `json:"page"`
}
type ClientConfig struct {
	OuterCA    string `json:"outerCA,omitempty"`
	Protocol   string `json:"protocol"`
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"serverName"`
	Pin        string `json:"pin"`
	GatewayID  string `json:"gatewayId"`
	ID         string `json:"id"`
	Secret     string `json:"secret"`
	EntryToken string `json:"entryToken"`
	IP         string `json:"ip"`
}

func ReadJSON(path string, out any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(b) > 1024*1024 {
		return ErrProtocol
	}
	return json.Unmarshal(b, out)
}
func WriteJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	mode := os.FileMode(0600)
	var owner os.FileInfo
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
		owner = info
	}
	tmp := path + ".new"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	if e = os.Chmod(tmp, mode); e != nil {
		return e
	}
	if owner != nil && os.Geteuid() == 0 {
		if e = preserveFileOwner(tmp, owner); e != nil {
			return e
		}
	}
	return os.Rename(tmp, path)
}
func Decode(s string, n int) ([]byte, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != n {
		return nil, ErrProtocol
	}
	return b, nil
}
func (c ClientConfig) Validate() error {
	if c.OuterCA != "" {
		if len(c.OuterCA) > 8192 {
			return ErrProtocol
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.OuterCA)) {
			return ErrProtocol
		}
	}
	if c.Secret == c.EntryToken {
		return ErrProtocol
	}
	if c.Protocol != "rivet-s1" && c.Protocol != "rivet-h3" {
		return ErrProtocol
	}
	host, port, e := net.SplitHostPort(c.Endpoint)
	if e != nil || host == "" || port == "" || c.ServerName == "" {
		return ErrProtocol
	}
	for s, n := range map[string]int{c.Pin: 32, c.GatewayID: 16, c.Secret: 32, c.EntryToken: 32} {
		if _, e = Decode(s, n); e != nil {
			return e
		}
	}
	id, e := hex.DecodeString(c.ID)
	if e != nil || len(id) != 16 {
		return ErrProtocol
	}
	ip := net.ParseIP(c.IP).To4()
	if ip == nil || ip[0] != 10 || ip[1] != 79 || ip[2] != 0 || ip[3] < 2 || ip[3] > 254 {
		return ErrProtocol
	}
	return nil
}
func InnerTLS(pin string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"rivet/1"}, SessionTicketsDisabled: true}
	if pin != "" {
		expected, _ := Decode(pin, 32)
		cfg.InsecureSkipVerify = true // Independent SPKI authentication replaces PKI only for the INNER channel.
		cfg.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) != 1 {
				return ErrProtocol
			}
			cert := s.PeerCertificates[0]
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return ErrProtocol
			}
			h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(h[:], expected) != 1 {
				return errors.New("rivet: gateway pin mismatch")
			}
			if s.Version != tls.VersionTLS13 || s.CurveID != tls.X25519MLKEM768 || s.NegotiatedProtocol != "rivet/1" || s.DidResume {
				return ErrProtocol
			}
			return nil
		}
	}
	return cfg
}
func GenerateInner(dir string) (string, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return "", e
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "XIO RIVET gateway"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(180 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return "", e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return "", e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(dir, "inner.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(dir, "inner.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); e != nil {
		return "", e
	}
	parsed, _ := x509.ParseCertificate(raw)
	h := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(h[:]), nil
}
func Seal(master, secret []byte, id string) (string, error) {
	b, e := aes.NewCipher(master)
	if e != nil {
		return "", e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(a.Seal(nonce, nonce, secret, []byte(id))), nil
}
func Unseal(master []byte, s, id string) ([]byte, error) {
	b, e := aes.NewCipher(master)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	raw, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(raw) < a.NonceSize() {
		return nil, ErrProtocol
	}
	out, e := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], []byte(id))
	if e != nil || len(out) != 32 {
		return nil, ErrProtocol
	}
	return out, nil
}

// GenerateOuter is the explicit private-CA fallback for a VPS without a public
// certificate. The anchor is scoped to this connection, never installed globally.
func GenerateOuter(dir, name string) (string, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return "", e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return "", e
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	if ip := net.ParseIP(name); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{name}
	}
	raw, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return "", e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return "", e
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	if e = os.WriteFile(filepath.Join(dir, "outer.crt"), pemCert, 0600); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(dir, "outer.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); e != nil {
		return "", e
	}
	return string(pemCert), nil
}
