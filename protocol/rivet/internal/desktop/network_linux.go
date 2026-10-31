package desktop

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type networkState struct {
	preserveJournal      bool
	owned                bool
	journal              *os.File
	lock                 int
	applied              []networkCommand
	run                  commandRunner
	mu                   sync.Mutex
	cache                map[string]string
	resolvers            []string
	physical4, physical6 bool
}

func isAdmin() bool          { return os.Geteuid() == 0 }
func platformFwmark() string { return "fwmark=" + strconv.Itoa(mark) + "\n" }
func (n *networkState) command(name string, args ...string) ([]byte, error) {
	if n.run != nil {
		return n.run(name, args...)
	}
	return runNetworkCommand(name, args...)
}
func prepareNetwork() (*networkState, error) {
	fd, e := unix.Open("/run/xio-client.lock", unix.O_CREAT|unix.O_NOFOLLOW|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		unix.Close(fd)
		return nil, errors.New("another XIO tunnel is active")
	}
	n := &networkState{lock: fd, cache: map[string]string{}, resolvers: []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"}}
	fail := true
	defer func() {
		if fail {
			n.close()
		}
	}()
	// A root-owned journal survives a killed helper. Remove only the exact
	// routes/rules reserved by this client before accepting another tunnel.
	f := os.NewFile(uintptr(fd), "XIO route journal")
	n.journal = f
	info, e := f.Stat()
	if e != nil || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe route journal")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return nil, errors.New("unsafe route journal owner")
	}
	data, _ := io.ReadAll(io.LimitReader(f, 4096))
	if string(data) == "XIO019-routing-owned\n" {
		n.preserveJournal = true
		if e := cleanupLinuxOwned(n.command); e != nil {
			return nil, e
		}
		n.preserveJournal = false
	}
	if e := f.Truncate(0); e != nil {
		return nil, e
	}
	_, _ = f.Seek(0, 0)
	// Keep ownership with n; os.File must not close the lock from its finalizer.
	n.journal = f
	if _, e = net.InterfaceByName(deviceName); e == nil {
		return nil, errors.New("the XIO interface already exists")
	}
	for _, family := range []string{"-4", "-6"} {
		out, e := n.command("/usr/sbin/ip", family, "route", "show", "table", routeTable)
		if e == nil && len(strings.TrimSpace(string(out))) > 0 {
			return nil, errors.New("routing table is already used")
		}
		b, e := n.command("/usr/sbin/ip", family, "-j", "rule", "show")
		if e != nil {
			return nil, e
		}
		var rows []struct {
			Priority int `json:"priority"`
		}
		if json.Unmarshal(b, &rows) != nil {
			return nil, ErrProfile
		}
		for _, row := range rows {
			if row.Priority == 18018 || row.Priority == 18019 {
				return nil, errors.New("routing rule is already used")
			}
		}
		defaults, err := n.command("/usr/sbin/ip", family, "-j", "route", "show", "default", "table", "main")
		var routes []struct{ Type string }
		if err == nil && json.Unmarshal(defaults, &routes) == nil {
			for _, route := range routes {
				if route.Type == "" || route.Type == "unicast" {
					if family == "-4" {
						n.physical4 = true
					} else {
						n.physical6 = true
					}
				}
			}
		}
	}
	if !n.physical4 && !n.physical6 {
		return nil, errors.New("no physical IPv4 or IPv6 default route")
	}
	if b, e := n.command("/usr/bin/resolvectl", "dns"); e == nil {
		servers := physicalDNSServers(string(b))
		if len(servers) > 0 {
			n.resolvers = servers
		}
	}
	fail = false
	return n, nil
}
func (n *networkState) Protect(fd int64) bool {
	return fd >= 0 && unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark) == nil
}
func (n *networkState) Resolve(host string) string {
	if a, e := netip.ParseAddr(host); e == nil {
		return reachableAddresses(a.Unmap().String(), n.physical4, n.physical6)
	}
	n.mu.Lock()
	v := n.cache[host]
	n.mu.Unlock()
	if v != "" {
		return v
	}
	v = reachableAddresses(resolvePhysical(host, n.resolvers, familyProtect(n.Protect)), n.physical4, n.physical6)
	if v != "" {
		n.mu.Lock()
		n.cache[host] = v
		n.mu.Unlock()
	}
	return v
}
func (n *networkState) bypass(ip netip.Addr) error { return nil } // SO_MARK excludes only engine/control sockets.
func (n *networkState) configure(p Profile) error {
	n.owned = true
	if _, e := n.journal.WriteAt([]byte("XIO019-routing-owned\n"), 0); e != nil {
		return e
	}
	if e := n.journal.Sync(); e != nil {
		return e
	}
	if e := applyNetworkPlan(linuxNetworkPlan(p), n.command, &n.applied); e != nil {
		return errors.New("could not configure owned VPN routing or DNS")
	}
	return nil
}
func (n *networkState) close() {
	undoNetworkPlan(n.applied, n.command)
	n.applied = nil
	if n.lock >= 0 {
		if n.journal != nil {
			if n.owned {
				n.preserveJournal = cleanupLinuxOwned(n.command) != nil
			}
			if !n.preserveJournal {
				_ = n.journal.Truncate(0)
				_ = n.journal.Sync()
			}
			_ = n.journal.Close()
			n.journal = nil
		} else {
			unix.Close(n.lock)
		}
		n.lock = -1
	}
}
