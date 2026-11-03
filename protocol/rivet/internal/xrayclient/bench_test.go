package xrayclient

// Benchmark of the UDP receive buffer allocation. The pump used to allocate a
// fresh 64 KiB buffer per datagram; the pool version reuses one per in-flight
// packet instead. consume is noinline so the buffer provably escapes and the
// measurement is not optimised away.

import "testing"

const datagramSize = 1280

var (
	sinkByte  byte
	sinkSlice []byte
)

// consume retains the buffer, so a "fresh buffer per packet" really is a heap
// allocation instead of a stack object the compiler could reuse.
//
//go:noinline
func consume(b []byte) { sinkSlice = b }

// peek only reads, so the pooled variant is not forced to escape.
//
//go:noinline
func peek(b []byte) { sinkByte = b[len(b)-1] }

func BenchmarkDatagramBufferFresh(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 65535)
		buf[datagramSize-1] = 1
		consume(buf)
	}
}

func BenchmarkDatagramBufferPooled(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		slot := datagramPool.Get().(*[]byte)
		buf := (*slot)[:65535]
		buf[datagramSize-1] = 1
		peek(buf)
		datagramPool.Put(slot)
	}
}
