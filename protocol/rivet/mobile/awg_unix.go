//go:build linux || android

// SPDX-License-Identifier: Apache-2.0
// Adapted from AmneziaWG Android api-android.go, copyright 2017-2022
// Jason A. Donenfeld. One gomobile runtime owns all four XIO engines.
package mobile

import (
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
	"runtime/debug"
)

// AwgTurnOn owns tunFD on every path. Creation is reserved independently of
// the registry mutex; IPC, Up and native close can never block cancellation.
func AwgTurnOn(name string, tunFD int64, settings string, p Protector) int64 {
	if tunFD < 0 || tunFD > 2147483647 {
		return -1
	}
	if p == nil || len(settings) > 200000 || !awgReserveCreation() {
		unix.Close(int(tunFD))
		return -1
	}
	// tun.CreateUnmonitoredTUNFromFD wraps the descriptor in an *os.File before
	// it can fail (a descriptor that is not a TUN fails inside on TUNGETIFF)
	// and returns without closing that file. The descriptor number then stays
	// owned by an unreachable *os.File, and its GC finalizer closes the number
	// at an arbitrary later moment. By then the number can already belong to an
	// unrelated socket, which the finalizer then closes: that is how the cloak
	// bridge used to lose its listener, and its dials their sockets, when
	// another test in the same process had failed an AWG activation first.
	// Handing the constructor a duplicate makes its abandoned close harmless:
	// only that finalizer ever closes the duplicate, so nobody else can hold
	// the number when it fires. The caller's descriptor is still consumed on
	// every path, as documented and as the descriptor-leak test asserts.
	fd, e := unix.FcntlInt(uintptr(tunFD), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		unix.Close(int(tunFD))
		awgAbortCreation()
		return -1
	}
	unix.Close(int(tunFD))
	t, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		// fd belongs to the *os.File the constructor abandoned; closing it here
		// would be the same double close this duplicate exists to avoid.
		awgAbortCreation()
		return -1
	}
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	d := device.NewDevice(t, &protectedAwgBind{Bind: conn.NewStdNetBind(), p: p}, logger)
	if d.IpcSet(settings) != nil {
		awgCloseDevice(d)
		awgAbortCreation()
		return -1
	}
	d.DisableSomeRoamingForBrokenMobileSemantics()
	if d.Up() != nil {
		awgCloseDevice(d)
		awgAbortCreation()
		return -1
	}
	handle := awgPublishDevice(d)
	if handle < 0 {
		awgCloseDevice(d)
		awgAbortCreation()
	}
	return handle
}

// AwgTurnOff joins native close and the pending operation before capacity is
// released. Concurrent/stale calls cannot release a newer device's reservation.
func AwgTurnOff(handle int64) { awgTurnOff(handle) }

func AwgGetConfig(handle int64) string {
	d := awgDevice(handle)
	if d == nil {
		return ""
	}
	value, e := d.IpcGet()
	if e != nil {
		return ""
	}
	return value
}

func AwgGetSocketV4(handle int64) int64 { return awgSocket(handle, false) }
func AwgGetSocketV6(handle int64) int64 { return awgSocket(handle, true) }
func awgSocket(handle int64, v6 bool) int64 {
	d := awgDevice(handle)
	if d == nil {
		return -1
	}
	bind, ok := d.Bind().(conn.PeekLookAtSocketFd)
	if !ok {
		return -1
	}
	var fd int
	var e error
	if v6 {
		fd, e = bind.PeekLookAtSocketFd6()
	} else {
		fd, e = bind.PeekLookAtSocketFd4()
	}
	if e != nil {
		return -1
	}
	return int64(fd)
}
func AwgVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/amnezia-vpn/amneziawg-go/v3" {
				return dep.Version
			}
		}
	}
	return "unknown"
}

// Protect sockets before Device.Up can emit its first handshake, and after
// rebind/mark updates, rather than waiting for the JNI call to return.
type protectedAwgBind struct {
	conn.Bind
	p Protector
}

func (b *protectedAwgBind) protect() error {
	peek, ok := b.Bind.(conn.PeekLookAtSocketFd)
	if !ok {
		return errors.New("socket access unavailable")
	}
	n := 0
	for _, get := range []func() (int, error){peek.PeekLookAtSocketFd4, peek.PeekLookAtSocketFd6} {
		fd, e := get()
		if e != nil || fd < 0 {
			continue
		}
		n++
		if !b.p.Protect(int64(fd)) {
			return errors.New("socket protection failed")
		}
	}
	if n == 0 {
		return errors.New("no protected sockets")
	}
	return nil
}
func (b *protectedAwgBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	funcs, actual, e := b.Bind.Open(port)
	if e != nil {
		return nil, 0, e
	}
	if e = b.protect(); e != nil {
		b.Bind.Close()
		return nil, 0, e
	}
	return funcs, actual, nil
}
func (b *protectedAwgBind) SetMark(mark uint32) error {
	if e := b.Bind.SetMark(mark); e != nil {
		return e
	}
	return b.protect()
}
func (b *protectedAwgBind) PeekLookAtSocketFd4() (int, error) {
	return b.Bind.(conn.PeekLookAtSocketFd).PeekLookAtSocketFd4()
}
func (b *protectedAwgBind) PeekLookAtSocketFd6() (int, error) {
	return b.Bind.(conn.PeekLookAtSocketFd).PeekLookAtSocketFd6()
}
