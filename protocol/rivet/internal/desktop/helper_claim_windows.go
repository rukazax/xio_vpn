package desktop

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type helperFileClaim struct {
	handle windows.Handle
}

func (c *helperFileClaim) Close() error { return windows.CloseHandle(c.handle) }

// claimProductHelper is the per-store cooperating claim. It uses an
// exclusive-share file rather than a mutex: mutex ownership is thread-affine and a
// claim held by a Go goroutine's OS thread would be abandoned when that thread
// exits, so the file handle (a process-lifetime object) is the correct primitive.
// A second helper for the same store fails the open with a sharing violation;
// process death releases it.
func claimProductHelper(identity string) (HelperClaim, error) {
	base, err := ensureWindowsStateDir()
	if err != nil {
		return nil, err
	}
	return claimWindowsFile(filepath.Join(base, "policy-"+identity+".claim"), "cooperating helper already owns store")
}

// claimProductResource is the shared exclusion over the fixed OS resource
// namespace (xio019). Distinct Full/Client stores still share it.
func claimProductResource() (HelperClaim, error) {
	base, err := ensureWindowsStateDir()
	if err != nil {
		return nil, err
	}
	return claimWindowsFile(filepath.Join(base, "resource-"+deviceName+".claim"), "cooperating helper already owns the shared resource namespace")
}

func ensureWindowsStateDir() (string, error) {
	base := windowsStateDir()
	if base == "" {
		return "", policyUnknown("ProgramData is unavailable")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return "", err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return "", err
	}
	if err := windows.SetNamedSecurityInfo(base, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return "", err
	}
	return base, nil
}

func claimWindowsFile(path, busyMessage string) (HelperClaim, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, policyBusy("%s", busyMessage)
		}
		return nil, err
	}
	return &helperFileClaim{handle: handle}, nil
}
