//go:build linux || android

package mobile

import (
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"golang.org/x/sys/unix"
	"testing"
)

func TestAwgRejectedTunDoesNotLeakDescriptor(t *testing.T) {
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fds[1])
	if AwgTurnOn("test", int64(fds[0]), "invalid", stalledResolver{make(chan struct{})}) != -1 {
		AwgTurnOff(1)
		t.Fatal("non-TUN descriptor accepted")
	}
	var stat unix.Stat_t
	if e := unix.Fstat(fds[0], &stat); e != unix.EBADF {
		unix.Close(fds[0])
		t.Fatal("failed activation leaked descriptor")
	}
	if AwgGetSocketV4(999) != -1 || AwgGetSocketV6(999) != -1 || AwgGetConfig(999) != "" {
		t.Fatal("invalid handle exposed state")
	}
	AwgTurnOff(999)
}

type rejectingProtector struct{}

func (rejectingProtector) Protect(int64) bool    { return false }
func (rejectingProtector) Resolve(string) string { return "" }
func TestAwgSocketProtectionBeforeOpenCompletes(t *testing.T) {
	bind := &protectedAwgBind{Bind: conn.NewStdNetBind(), p: rejectingProtector{}}
	if _, _, e := bind.Open(0); e == nil {
		bind.Close()
		t.Fatal("unprotected sockets became available")
	}
	// Failure closes the bind, making the same underlying object reusable.
	bind.p = stalledResolver{make(chan struct{})}
	if _, _, e := bind.Open(0); e != nil {
		t.Fatal(e)
	}
	defer bind.Close()
	if fd, e := bind.PeekLookAtSocketFd4(); e != nil || fd < 0 {
		t.Fatal("protected descriptor unavailable")
	}
}
