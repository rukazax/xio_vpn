//go:build linux || android

package mobile

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func readHeap() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

// openedTun opens a throwaway TUN interface for one cycle. It skips instead of
// failing when the sandbox has no TUN, so the plateau test still runs on hosts
// that cannot create one.
func openedTun(t *testing.T, name string) (int64, bool) {
	t.Helper()
	fd, e := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if e != nil {
		return 0, false
	}
	ifr, e := unix.NewIfreq(name)
	if e != nil {
		unix.Close(fd)
		return 0, false
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if e := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); e != nil {
		unix.Close(fd)
		return 0, false
	}
	return int64(fd), true
}

func cycleSettings(t *testing.T) string {
	t.Helper()
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return "private_key=" + hex.EncodeToString(key.Bytes()) + "\nreplace_peers=true\n"
}

type allowAll struct{}

func (allowAll) Protect(int64) bool    { return true }
func (allowAll) Resolve(string) string { return "192.0.2.1" }

// TestReclaimReturnsTeardownPages pins the mechanism the plateau depends on: the
// garbage a tunnel leaves behind is not reachable, so a teardown must hand its
// pages back to the OS instead of leaving them committed until the next
// collection goal. A teardown without the reclaim keeps HeapReleased flat.
func TestReclaimReturnsTeardownPages(t *testing.T) {
	// The shape and size of the AmneziaWG queue garbage: one 64 KiB message
	// buffer per queued packet.
	const buffers, size = 512, 64 * 1024
	hold := make([][]byte, buffers)
	for i := range hold {
		hold[i] = make([]byte, size)
		hold[i][0] = byte(i)
	}
	before := readHeap()
	runtime.KeepAlive(hold)
	hold = nil
	reclaimAfterTeardown()
	after := readHeap()
	released := int64(after.HeapReleased) - int64(before.HeapReleased)
	t.Logf("heap_alloc %d KiB -> %d KiB, heap_inuse %d KiB, released +%d KiB",
		before.HeapAlloc/1024, after.HeapAlloc/1024, after.HeapInuse/1024, released/1024)
	if after.HeapInuse > 8*1024*1024 {
		t.Fatalf("teardown left %d KiB committed", after.HeapInuse/1024)
	}
	if released < int64(buffers*size)/2 {
		t.Fatalf("teardown returned %d KiB to the OS, want at least %d KiB", released/1024, buffers*size/2/1024)
	}
}

// TestAwgCycleHeapStaysBounded is the regression for the reported leak: repeated
// Start/Stop must reach a plateau instead of growing with the cycle count. The
// heap is sampled right after each teardown without forcing a collection, so an
// uncollected teardown leaves a slope and a reclaimed one stays flat.
func TestAwgCycleHeapStaysBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("needs 40 activation cycles")
	}
	const cycles = 40
	var at10, at40 uint64
	for i := 1; i <= cycles; i++ {
		name := fmt.Sprintf("xioleak%d", i%4)
		fd, ok := openedTun(t, name)
		if !ok {
			t.Skip("TUNSETIFF unavailable")
		}
		h := AwgTurnOn(name, fd, cycleSettings(t), allowAll{})
		if h < 0 {
			t.Fatalf("cycle %d: activation rejected", i)
		}
		// Queue work the way a real session does: the device copies every packet
		// into a 64 KiB message buffer that the teardown makes unreachable.
		bufs := make([][]byte, 64)
		for j := range bufs {
			bufs[j] = make([]byte, 64*1024)
			bufs[j][0] = byte(j)
		}
		time.Sleep(5 * time.Millisecond)
		AwgTurnOff(h)
		runtime.KeepAlive(bufs)
		bufs = nil
		switch i {
		case 10:
			at10 = readHeap().HeapAlloc
			t.Logf("cycle 10: heap_alloc=%d KiB", at10/1024)
		case 40:
			at40 = readHeap().HeapAlloc
			t.Logf("cycle 40: heap_alloc=%d KiB", at40/1024)
		}
	}
	growth := int64(at40) - int64(at10)
	t.Logf("growth over 30 cycles: %d KiB", growth/1024)
	// A plateau, not a slope: 30 cycles of 4 MiB of teardown garbage each may not
	// leave more than two such cycles' worth behind.
	if growth > 8*1024*1024 {
		t.Fatalf("heap grew %d KiB between cycle 10 and cycle 40", growth/1024)
	}
}
