//go:build linux || android

package rivet

import (
	"golang.org/x/sys/unix"
	"os"
	"unsafe"
)

func OpenTUN(name string) (*os.File, error) {
	if len(name) < 1 || len(name) > 15 {
		return nil, ErrProtocol
	}
	fd, e := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	var req [40]byte
	copy(req[:16], name)
	*(*uint16)(unsafe.Pointer(&req[16])) = unix.IFF_TUN | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		unix.Close(fd)
		return nil, errno
	}
	// Register with Go's poller only after TUNSETIFF. An unconfigured TUN
	// descriptor is not pollable; os.OpenFile before ioctl can permanently
	// poison its poll state and make a restarted gateway lose its reader.
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}
