package desktop

import (
	"os"

	"golang.org/x/sys/unix"
)

type helperFileClaim struct {
	file *os.File
}

func (c *helperFileClaim) Close() error { return c.file.Close() }

func claimProductHelper(identity string) (HelperClaim, error) {
	return claimHelperFile("/run/xio-policy-"+identity+".lock", 0)
}

func claimProductResource() (HelperClaim, error) {
	return claimHelperFile("/run/xio-resource-"+deviceName+".lock", 0)
}

// claimHelperFile is the path-injected primitive that owned temporary fixtures
// exercise. The lock file must be a single regular file with no group/world
// access, owned by the expected uid, and must never be unlinked: another process
// may already hold its inode open. Flock ownership disappears with the process.
func claimHelperFile(path string, owner uint32) (HelperClaim, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_NOFOLLOW|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		if err == unix.ELOOP {
			return nil, policyUnknown("unsafe helper ownership file")
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	fail := true
	defer func() {
		if fail {
			_ = file.Close()
		}
	}()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != owner || stat.Mode&0077 != 0 || stat.Nlink != 1 {
		return nil, policyUnknown("unsafe helper ownership file")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, policyBusy("cooperating helper already owns store")
	}
	fail = false
	return &helperFileClaim{file: file}, nil
}
