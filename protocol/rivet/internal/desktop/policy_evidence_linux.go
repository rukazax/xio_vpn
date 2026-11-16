package desktop

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// linuxOwnershipJournal is the root-owned journal written by the existing Linux
// setup path (network_linux.go). Reading it is the only use here: the evidence
// adapter never calls prepareNetwork, cleanupLinuxOwned or any other cleanup.
const linuxOwnershipJournal = "/run/xio-client.lock"

func observePlatformResources() ResourceEvidence {
	return observeLinuxResources(
		net.Interfaces,
		func() resourceObservation { return observeLinuxJournal(linuxOwnershipJournal, 0) },
		runNetworkCommand,
	)
}

// observeLinuxJournal validates the ownership receipt exactly like the setup
// path does (regular, root-owned, not group/world accessible, single link) and
// accepts only the exact marker or an empty journal. Anything else is Unknown.
func observeLinuxJournal(path string, owner uint32) resourceObservation {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return resourceObservation{complete: true}
	}
	if err != nil {
		return resourceObservation{}
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != owner || stat.Mode&0077 != 0 || stat.Nlink != 1 {
		return resourceObservation{}
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return resourceObservation{}
	}
	switch string(data) {
	case "":
		return resourceObservation{complete: true}
	case "XIO019-routing-owned\n":
		return resourceObservation{complete: true, owned: true}
	default:
		return resourceObservation{}
	}
}

// observeLinuxResources classifies the existing device, the dedicated routing
// table, the reserved rule priorities and the ownership journal. Every query
// must succeed and parse; a failure is Unknown, not an empty (clean) result.
func observeLinuxResources(interfaces func() ([]net.Interface, error), journal func() resourceObservation, run commandRunner) ResourceEvidence {
	observations := []resourceObservation{journal()}
	found, err := interfaces()
	if err != nil {
		return ResourcesUnknown
	}
	device := resourceObservation{complete: true}
	for _, iface := range found {
		if iface.Name == deviceName {
			device.owned = true
		}
	}
	observations = append(observations, device)
	for _, family := range []string{"-4", "-6"} {
		for _, kind := range []string{"rule", "route"} {
			args := []string{family, "-j", kind, "show"}
			if kind == "route" {
				args = append(args, "table", "all")
			}
			out, err := run("/usr/sbin/ip", args...)
			var rows []map[string]any
			if err != nil || json.Unmarshal(out, &rows) != nil || rows == nil {
				return ResourcesUnknown
			}
			observation := resourceObservation{complete: true}
			for _, row := range rows {
				switch kind {
				case "rule":
					priority := fmt.Sprint(row["priority"])
					if priority == "18018" || priority == "18019" {
						observation.owned = true
					}
				case "route":
					if fmt.Sprint(row["table"]) == routeTable || fmt.Sprint(row["dev"]) == deviceName {
						observation.owned = true
					}
				}
			}
			observations = append(observations, observation)
		}
	}
	return classifyResources(observations...)
}
