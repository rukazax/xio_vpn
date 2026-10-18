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
	"sync"
)

var awgHandles = struct {
	sync.Mutex
	next    int64
	devices map[int64]*device.Device
}{devices: map[int64]*device.Device{}}

// AwgTurnOn takes ownership of tunFD, including failure paths.
func AwgTurnOn(name string, tunFD int64, settings string, p Protector) int64 {
	if tunFD < 0 || tunFD > 2147483647 {
		return -1
	}
	awgHandles.Lock()
	defer awgHandles.Unlock()
	if p == nil || len(awgHandles.devices) > 0 || len(settings) > 200000 {
		unix.Close(int(tunFD))
		return -1
	}
	t, _, err := tun.CreateUnmonitoredTUNFromFD(int(tunFD))
	if err != nil {
		unix.Close(int(tunFD))
		return -1
	}
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	d := device.NewDevice(t, &protectedAwgBind{Bind: conn.NewStdNetBind(), p: p}, logger)
	if d.IpcSet(settings) != nil {
		d.Close()
		return -1
	}
	d.DisableSomeRoamingForBrokenMobileSemantics()
	if d.Up() != nil {
		d.Close()
		return -1
	}
	awgHandles.next++
	if awgHandles.next > 2147483647 {
		awgHandles.next = 1
	}
	awgHandles.devices[awgHandles.next] = d
	return awgHandles.next
}
func AwgTurnOff(handle int64) {
	awgHandles.Lock()
	defer awgHandles.Unlock()
	if d := awgHandles.devices[handle]; d != nil {
		delete(awgHandles.devices, handle)
		d.Close()
	}
}
func AwgGetConfig(handle int64) string {
	awgHandles.Lock()
	defer awgHandles.Unlock()
	d := awgHandles.devices[handle]
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
	awgHandles.Lock()
	defer awgHandles.Unlock()
	d := awgHandles.devices[handle]
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
