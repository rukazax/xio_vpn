//go:build !windows

package rivet

import (
	"os"
	"syscall"
)

func preserveFileOwner(path string, info os.FileInfo) error {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return os.Chown(path, int(st.Uid), int(st.Gid))
	}
	return nil
}
