package rivet

// Benchmarks for the packet hot path. They contrast the allocating shape of the
// original helpers with the shape the session now uses, so the allocation work
// removed by the optimisation stays measurable.

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

type copySink struct{ buf []byte }

func (s *copySink) send(b []byte) error {
	s.buf = append(s.buf[:0], b...)
	return nil
}

func benchPacket() []byte {
	p := make([]byte, MTU)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[9] = 17
	return p
}

// BenchmarkFragmentSend is the previous send loop: Fragment allocates the
// fragment slice array plus one buffer per fragment.
func BenchmarkFragmentSend(b *testing.B) {
	p := benchPacket()
	sink := &copySink{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, f := range Fragment(uint64(i)+1, p) {
			if e := sink.send(f); e != nil {
				b.Fatal(e)
			}
		}
	}
}

// BenchmarkFragmentReusedSend is the current send loop: one reusable per-session
// buffer and no allocation for the fragment array.
func BenchmarkFragmentReusedSend(b *testing.B) {
	p := benchPacket()
	sink := &copySink{}
	var buf [fragmentHeader + fragmentPayload]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id := uint64(i) + 1
		for off := 0; off < len(p); off += fragmentPayload {
			end := min(off+fragmentPayload, len(p))
			f := buf[:fragmentHeader+end-off]
			fragmentHeaderInto(f, id, len(p), off, end-off)
			copy(f[fragmentHeader:], p[off:end])
			if e := sink.send(f); e != nil {
				b.Fatal(e)
			}
		}
	}
}

// BenchmarkCheckIPv6NAT64 covers the IPv6 public-destination check that runs for
// every packet of an authenticated session, including the NAT64 branch.
func BenchmarkCheckIPv6NAT64(b *testing.B) {
	p := make([]byte, 1280)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
	p[6] = 17
	p[7] = 64
	// Source: fd79:0:0:1::2 (the authenticated user slot for 10.79.0.2).
	p[8], p[9], p[23] = 0xfd, 0x79, 2
	// Destination: 64:ff9b::5db8:d822, a public IPv4 inside the NAT64 prefix.
	copy(p[24:40], netip.MustParseAddr("64:ff9b::cb00:7101").AsSlice())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if e := CheckIP(p, "", true); e != nil {
			b.Fatal(e)
		}
	}
}

// BenchmarkMustParsePrefixPerPacket measures the expression the hot path used to
// evaluate for every IPv6 packet before the prefix was hoisted to a package var.
func BenchmarkMustParsePrefixPerPacket(b *testing.B) {
	dst := netip.MustParseAddr("64:ff9b::cb00:7101")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !netip.MustParsePrefix("64:ff9b::/96").Contains(dst) {
			b.Fatal("prefix")
		}
	}
}

// BenchmarkMonthFormatPerPacket measures the counters' month lookup as it was
// before it was cached for a minute.
func BenchmarkMonthFormatPerPacket(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if time.Now().UTC().Format("2006-01") == "" {
			b.Fatal("month")
		}
	}
}

func BenchmarkMonthCached(b *testing.B) {
	g := &Gateway{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if g.monthUTC(time.Now()) == "" {
			b.Fatal("month")
		}
	}
}
