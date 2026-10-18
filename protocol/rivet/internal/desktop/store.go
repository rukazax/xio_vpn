package desktop

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
)

type secureStore struct {
	dir string
	key []byte
	mu  sync.Mutex
}

func newStore(raw string) (*secureStore, error) {
	base, e := os.UserCacheDir()
	if e != nil {
		return nil, e
	}
	id := sha256.Sum256([]byte(raw))
	d := filepath.Join(base, "XIO", "tailscale", hex.EncodeToString(id[:12]))
	if e = os.MkdirAll(d, 0700); e != nil {
		return nil, e
	}
	p := filepath.Join(d, "device.key")
	key, e := os.ReadFile(p)
	if os.IsNotExist(e) {
		key = make([]byte, 32)
		_, e = rand.Read(key)
		if e == nil {
			e = os.WriteFile(p, key, 0600)
		}
	}
	if e != nil {
		return nil, e
	}
	return &secureStore{dir: d, key: key}, nil
}
func (s *secureStore) path(k string) string {
	h := sha256.Sum256([]byte(k))
	return filepath.Join(s.dir, hex.EncodeToString(h[:])+".bin")
}
func (s *secureStore) gcm() (cipher.AEAD, error) {
	a, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(a)
}
func (s *secureStore) Load(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, e := s.gcm()
	if e != nil {
		return ""
	}
	b, e := os.ReadFile(s.path(k))
	if e != nil || len(b) < a.NonceSize() {
		return ""
	}
	v, e := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte(k))
	if e != nil {
		return ""
	}
	return string(v)
}
func (s *secureStore) Save(k, v string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, e := s.gcm()
	if e != nil {
		return false
	}
	n := make([]byte, a.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return false
	}
	b := a.Seal(n, n, []byte(v), []byte(k))
	p := s.path(k)
	if os.WriteFile(p+".tmp", b, 0600) != nil {
		return false
	}
	return os.Rename(p+".tmp", p) == nil
}
