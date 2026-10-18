package rivet

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	Challenge = 1
	Auth      = 2
	AuthOK    = 3
	Configure = 4
	ConfigACK = 5
	Close     = 6
	IPPacket  = 16
	Padding   = 32
	MTU       = 1280
)

var ErrProtocol = errors.New("rivet: protocol violation")
var enc cbor.EncMode
var dec cbor.DecMode

func init() {
	enc, _ = cbor.CanonicalEncOptions().EncMode()
	dec, _ = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, MaxNestedLevels: 4, MaxArrayElements: 32, MaxMapPairs: 16}).DecMode()
}

type Wire struct {
	io.ReadWriteCloser
	mu sync.Mutex
}

func (w *Wire) Send(t byte, p []byte) error {
	limit := 4096
	if t == IPPacket {
		limit = MTU
	}
	if len(p) > limit || !validType(t) {
		return ErrProtocol
	}
	h := []byte{t, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[2:], uint32(len(p)))
	w.mu.Lock()
	defer w.mu.Unlock()
	if d, ok := w.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
		d.SetWriteDeadline(time.Now().Add(5 * time.Second))
		defer d.SetWriteDeadline(time.Time{})
	}
	if err := writeAll(w.ReadWriteCloser, h); err != nil {
		return err
	}
	return writeAll(w.ReadWriteCloser, p)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func validType(t byte) bool {
	return t == Challenge || t == Auth || t == AuthOK || t == Configure || t == ConfigACK || t == Close || t == IPPacket || t == Padding
}
func (w *Wire) ReadFrame() (byte, []byte, error) {
	var h [6]byte
	if _, e := io.ReadFull(w, h[:]); e != nil {
		return 0, nil, e
	}
	n := binary.BigEndian.Uint32(h[2:])
	limit := uint32(4096)
	if h[0] == IPPacket {
		limit = MTU
	}
	if !validType(h[0]) || h[1] != 0 || n > limit {
		return 0, nil, ErrProtocol
	}
	if h[0] == Padding && (n < 1 || n > 4096) {
		return 0, nil, ErrProtocol
	}
	p := make([]byte, int(n))
	_, e := io.ReadFull(w, p)
	return h[0], p, e
}
func (w *Wire) Expect(t byte) ([]byte, error) {
	kind, p, e := w.ReadFrame()
	if e != nil {
		return nil, e
	}
	if kind != t {
		return nil, ErrProtocol
	}
	return p, nil
}
func Params(carrier uint64) []byte {
	b, _ := enc.Marshal(map[uint64]uint64{0: 1, 1: carrier, 2: 1, 3: MTU})
	return b
}
func CheckParams(b []byte, carrier uint64) bool { return bytes.Equal(b, Params(carrier)) }
func Proof(secret, gateway, nonce, exporter, params []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("RIVET-1-client-auth"))
	m.Write(gateway)
	m.Write(nonce)
	m.Write(exporter)
	h := sha256.Sum256(params)
	m.Write(h[:])
	return m.Sum(nil)
}
func Exporter(s tls.ConnectionState) ([]byte, error) {
	if !s.HandshakeComplete || s.Version != tls.VersionTLS13 || s.CurveID != tls.X25519MLKEM768 || s.NegotiatedProtocol != "rivet/1" || s.DidResume {
		return nil, ErrProtocol
	}
	return s.ExportKeyingMaterial("EXPORTER-RIVET-1-auth", nil, 32)
}
func EncodeConfig(ip []byte, sid []byte) []byte {
	b, _ := enc.Marshal(map[uint64]any{0: uint64(1), 1: sid, 2: [][]any{{uint64(4), ip, uint64(32)}}, 3: [][]any{{uint64(4), []byte{0, 0, 0, 0}, uint64(0)}}, 4: [][]any{{uint64(4), []byte{1, 1, 1, 1}}}, 5: uint64(MTU), 6: uint64(MTU), 7: uint64(3600), 8: uint64(64), 9: uint64(262144), 10: uint64(1000)})
	return b
}
func DecodeConfig(b, sid, ip []byte) error {
	// This IPv4-only implementation accepts exactly its frozen configuration.
	// Deterministic bytes reject unknown fields, reordered/nonminimal CBOR and
	// malicious server-assigned DNS/routes; no arbitrary gateway routes are trusted.
	if !bytes.Equal(b, EncodeConfig(ip, sid)) {
		return ErrProtocol
	}
	return nil
}

// Reassembler uses fixed small packets, a 4096-ID replay window, strict overlap
// rejection and bounded time/memory. It is instantiated only after authentication.
type partial struct {
	data, seen []byte
	count      int
	at         time.Time
}
type Reassembler struct {
	parts map[uint64]*partial
	done  map[uint64]bool
	high  uint64
}

func NewReassembler() *Reassembler {
	return &Reassembler{parts: map[uint64]*partial{}, done: map[uint64]bool{}}
}
func Fragment(id uint64, p []byte) [][]byte {
	var out [][]byte
	for off := 0; off < len(p); off += 1000 {
		end := min(off+1000, len(p))
		b := make([]byte, 15+end-off)
		b[0] = IPPacket
		binary.BigEndian.PutUint64(b[1:], id)
		binary.BigEndian.PutUint16(b[9:], uint16(len(p)))
		binary.BigEndian.PutUint16(b[11:], uint16(off))
		binary.BigEndian.PutUint16(b[13:], uint16(end-off))
		copy(b[15:], p[off:end])
		out = append(out, b)
	}
	return out
}
func (r *Reassembler) Feed(b []byte, now time.Time) ([]byte, error) {
	for id, p := range r.parts {
		if now.Sub(p.at) >= time.Second {
			delete(r.parts, id)
			r.done[id] = true
		}
	}
	if len(b) < 16 || b[0] != IPPacket {
		return nil, ErrProtocol
	}
	id := binary.BigEndian.Uint64(b[1:])
	n := int(binary.BigEndian.Uint16(b[9:]))
	off := int(binary.BigEndian.Uint16(b[11:]))
	count := int(binary.BigEndian.Uint16(b[13:]))
	if id == 0 || n < 20 || n > MTU || count < 1 || len(b) != 15+count || off+count > n {
		return nil, ErrProtocol
	}
	if r.high > 4096 && id <= r.high-4096 {
		return nil, nil
	}
	if r.done[id] {
		return nil, nil
	}
	if id > r.high {
		r.high = id
		for key := range r.done {
			if id > 4096 && key <= id-4096 {
				delete(r.done, key)
			}
		}
		for key := range r.parts {
			if id > 4096 && key <= id-4096 {
				delete(r.parts, key)
			}
		}
	}
	p := r.parts[id]
	if p == nil {
		if len(r.parts) >= 64 {
			return nil, nil
		}
		p = &partial{data: make([]byte, n), seen: make([]byte, n), at: now}
		r.parts[id] = p
	}
	if len(p.data) != n {
		delete(r.parts, id)
		r.done[id] = true
		return nil, ErrProtocol
	}
	duplicate := true
	for j := 0; j < count; j++ {
		if p.seen[off+j] == 0 {
			duplicate = false
		} else if p.data[off+j] != b[15+j] {
			delete(r.parts, id)
			r.done[id] = true
			return nil, ErrProtocol
		}
	}
	if duplicate {
		return nil, nil
	}
	for j := 0; j < count; j++ {
		if p.seen[off+j] != 0 {
			delete(r.parts, id)
			r.done[id] = true
			return nil, ErrProtocol
		}
	}
	copy(p.data[off:], b[15:])
	for j := 0; j < count; j++ {
		p.seen[off+j] = 1
	}
	p.count += count
	if p.count == n {
		delete(r.parts, id)
		r.done[id] = true
		return p.data, nil
	}
	return nil, nil
}
