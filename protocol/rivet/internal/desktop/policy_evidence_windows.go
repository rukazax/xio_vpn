package desktop

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// windowsStateDir is the existing privileged bookkeeping directory used by the
// Windows setup path. Evidence only reads inside it.
func windowsStateDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		return ""
	}
	return filepath.Join(base, "XIO")
}

func observePlatformResources() ResourceEvidence {
	base := windowsStateDir()
	if base == "" {
		return ResourcesUnknown
	}
	return observeWindowsResources(
		func() (bool, error) { return windowsTunnelLockHeld(filepath.Join(base, "tunnel.lock")) },
		func() resourceObservation {
			return observeWindowsFirewallReceipt(filepath.Join(base, "firewall.receipt"))
		},
		func() resourceObservation { return observeWindowsSharingReceipt(filepath.Join(base, "sharing.json")) },
	)
}

// windowsTunnelLockHeld opens the existing per-tunnel lock with shared access.
// A live tunnel holds it with no sharing, so the open fails with a sharing
// violation: that is owned, not an error. A free or absent lock is clean. The
// probe never creates, truncates or deletes the file.
func windowsTunnelLockHeld(path string) (bool, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
			return false, nil
		case errors.Is(err, windows.ERROR_SHARING_VIOLATION), errors.Is(err, windows.ERROR_LOCK_VIOLATION):
			return true, nil
		}
		return false, err
	}
	_ = windows.CloseHandle(handle)
	return false, nil
}

// observeWindowsFirewallReceipt accepts only the exact legacy owned-rule
// receipt. A malformed receipt is Unknown (unsafe), never Clean: the setup path
// itself refuses it instead of guessing.
func observeWindowsFirewallReceipt(path string) resourceObservation {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return resourceObservation{complete: true}
	}
	if err != nil {
		return resourceObservation{}
	}
	if !validLegacyFirewallReceipt(string(data)) {
		return resourceObservation{}
	}
	return resourceObservation{complete: true, owned: true}
}

// observeWindowsSharingReceipt: the existing ICS path removes its receipt when
// sharing is disabled, so a present receipt is a leftover owned configuration
// that needs the existing explicit recovery, not silent cleanup.
func observeWindowsSharingReceipt(path string) resourceObservation {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return resourceObservation{complete: true}
	}
	if err != nil || !info.Mode().IsRegular() {
		return resourceObservation{}
	}
	return resourceObservation{complete: true, owned: true}
}

func observeWindowsResources(tunnelLock func() (bool, error), firewall, sharing func() resourceObservation) ResourceEvidence {
	observations := []resourceObservation{firewall(), sharing()}
	held, err := tunnelLock()
	if err != nil {
		return ResourcesUnknown
	}
	observations = append(observations, resourceObservation{complete: true, owned: held})
	interfaces, err := net.Interfaces()
	if err != nil {
		return ResourcesUnknown
	}
	device := resourceObservation{complete: true}
	for _, iface := range interfaces {
		if strings.EqualFold(iface.Name, deviceName) {
			device.owned = true
		}
	}
	observations = append(observations, device)
	return classifyResources(observations...)
}
