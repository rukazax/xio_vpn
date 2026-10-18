package tailclient

import (
	"errors"
	"tailscale.com/net/netns"
)

func setProtect(p Protector) {
	netns.SetAndroidProtectFunc(func(fd int) error {
		if p == nil || !p.Protect(int64(fd)) {
			return errors.New("tailscale: socket protection failed")
		}
		return nil
	})
}
