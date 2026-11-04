//go:build linux || android

package mobile

// Regression tests for the fd lifetime bug that made the cloak bridge fail when
// an earlier AWG activation in the same process had been rejected.
//
// Root cause (see TestAwgFailureKeepsRecycledDescriptorUsable for the minimal
// reproduction): tun.CreateUnmonitoredTUNFromFD wraps the descriptor in an
// *os.File and, when the descriptor turns out not to be a TUN, returns without
// closing it. AwgTurnOn closed the caller's descriptor, but the abandoned
// *os.File stayed reachable only from a GC finalizer, so the same descriptor
// number was closed a second time later — after the kernel had recycled it for
// another socket. The cloak bridge then lost its listener (accept4: EBADF or
// EINVAL) or its dial socket (silent i/o timeout), depending on which socket
// had received the recycled number.

import (
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// recycleListenerFD opens listeners until one lands on want, so a stale
// finalizer closing that number would be caught deterministically.
func recycleListenerFD(t *testing.T, want int) (net.Listener, int) {
	t.Helper()
	for attempt := 0; attempt < 16; attempt++ {
		ln, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		raw, e := ln.(*net.TCPListener).SyscallConn()
		if e != nil {
			ln.Close()
			t.Fatal(e)
		}
		fd := -1
		if e := raw.Control(func(descriptor uintptr) { fd = int(descriptor) }); e != nil {
			ln.Close()
			t.Fatal(e)
		}
		if fd == want {
			return ln, fd
		}
		ln.Close()
	}
	t.Skipf("could not recycle descriptor %d in this process", want)
	return nil, 0
}

// TestAwgFailureKeepsRecycledDescriptorUsable is the deterministic form of the
// flake: after a rejected AWG activation, force the GC and check that a
// listener which received the recycled descriptor number still accepts.
func TestAwgFailureKeepsRecycledDescriptorUsable(t *testing.T) {
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fds[1])
	if AwgTurnOn("test", int64(fds[0]), "invalid", stalledResolver{make(chan struct{})}) != -1 {
		t.Fatal("non-TUN descriptor accepted")
	}
	var stat unix.Stat_t
	if e := unix.Fstat(fds[0], &stat); e != unix.EBADF {
		unix.Close(fds[0])
		t.Fatalf("rejected activation kept the caller's descriptor: %v", e)
	}

	listener, listenerFD := recycleListenerFD(t, fds[0])
	defer listener.Close()
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	if e := unix.Fstat(listenerFD, &stat); e != nil {
		t.Fatalf("descriptor %d recycled by the test listener was closed by a stale finalizer: %v", listenerFD, e)
	}
	go func() {
		c, e := net.Dial("tcp", listener.Addr().String())
		if e != nil {
			return
		}
		_, _ = c.Write([]byte("probe"))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	remote, e := listener.Accept()
	if e != nil {
		t.Fatalf("recycled listener stopped accepting: %v", e)
	}
	remote.Close()
}

// TestCloakForwardsAfterAwgAndXray covers the production interaction: a
// rejected AWG activation, a listener that receives the recycled descriptor
// number, an Xray session started in the same process, a GC cycle, and then a
// cloak session that must still reach that listener and push bytes through it.
func TestCloakForwardsAfterAwgAndXray(t *testing.T) {
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fds[1])
	if AwgTurnOn("test", int64(fds[0]), "invalid", stalledResolver{make(chan struct{})}) != -1 {
		t.Fatal("non-TUN descriptor accepted")
	}
	// The destination must own the descriptor number the AWG path just freed,
	// otherwise a stale finalizer closing that number would be harmless and the
	// test could not see the regression.
	remote, _ := recycleListenerFD(t, fds[0])
	defer remote.Close()
	port := remote.Addr().(*net.TCPAddr).Port

	if e := XrayStart(xrayRealityProfile, pinnedProtector(true), 5000); e != nil {
		t.Fatalf("xray session: %v", e)
	}
	defer XrayStop()
	if status := XrayStatus(); status == `{"active":false,"secure":false}` {
		t.Fatalf("xray session did not start: %s", status)
	}
	// Xray startup allocates; force the GC so any finalizer left behind by the
	// rejected activation fires while the recycled number is in use.
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}

	localPort, e := CloakStart(cloakFixture(t, port), pinnedProtector(true), 3000)
	if e != nil {
		t.Fatal(e)
	}
	defer CloakStop()
	client, e := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(localPort))))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if _, e = client.Write([]byte("OpenVPN fixture")); e != nil {
		t.Fatal(e)
	}
	_ = remote.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	physical, e := remote.Accept()
	if e != nil {
		t.Fatalf("cloak did not reach the physical destination after AWG+Xray: %v", e)
	}
	defer physical.Close()
	_ = physical.SetDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 64)
	n, e := physical.Read(buffer)
	if n == 0 {
		t.Fatalf("cloak forwarded no bytes to the physical destination: %v", e)
	}
}

// xrayRealityProfile is a complete REALITY profile: the session is started but
// never dialled, which is enough to exercise the config builder and the Xray
// instance lifecycle in this process.
const xrayRealityProfile = `{"protocol":"xray","outbound":{"protocol":"vless","tag":"proxy",` +
	`"settings":{"vnext":[{"address":"vpn.example.com","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","encryption":"none","flow":"xtls-rprx-vision"}]}]},` +
	`"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","fingerprint":"chrome",` +
	`"publicKey":"MZb4wq3Z9jV7kY1nR2tP6xL8cD5hG0sA4eF7uJ2mQ9o","shortId":"0123456789abcdef","spiderX":"/"}}}}`
