//go:build !windows

package tailclient

import (
	"golang.org/x/sys/unix"
	"os"
)

func (d *Device) Attach(fd int) error {
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "xio-tailnet-tun")
	if err := d.attachIO(f, f); err != nil {
		f.Close()
		return err
	}
	return nil
}
