package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type networkState struct {
	setup                *setupLease
	cleanupCtx           context.Context
	lookup               physicalLookup
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
	return n.setup.command(n.run, name, args...)
}
func (n *networkState) cleanupCommand(name string, args ...string) ([]byte, error) {
	// Never inherit the revoked setup context. The owner joins before unlock.
	parent := n.cleanupCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n.run != nil {
		return n.run(name, args...)
	}
	return runNetworkCommandContext(ctx, name, args...)
}
func prepareNetwork(leases ...*setupLease) (*networkState, error) {
	var setup *setupLease
	if len(leases) > 0 {
		setup = leases[0]
	}
	if err := setup.check(); err != nil {
		return nil, err
	}
	fd := -1
	var e error
	e = setup.effect(func() error {
		fd, e = unix.Open("/run/xio-client.lock", unix.O_CREAT|unix.O_NOFOLLOW|unix.O_RDWR|unix.O_CLOEXEC, 0600)
		return e
	})
	if e != nil {
		return nil, e
	}
	if e = setup.effect(func() error { return unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) }); e != nil {
		unix.Close(fd)
		return nil, errors.New("another XIO tunnel is active")
	}
	n := &networkState{setup: setup, lock: fd, cache: map[string]string{}, resolvers: []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"}}
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
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		n.cleanupCtx = ctx
		e := cleanupLinuxOwned(n.cleanupCommand)
		cancel()
		n.cleanupCtx = nil
		if e != nil {
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
	if err := setup.effect(func() error { _, e = net.InterfaceByName(deviceName); return nil }); err != nil {
		return nil, err
	}
	if e == nil {
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
	if fd < 0 {
		return false
	}
	return n.setup.effect(func() error { return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark) }) == nil
}
func (n *networkState) Resolve(host string) string {
	return n.ResolveContext(context.Background(), host)
}
func (n *networkState) ResolveContext(parent context.Context, host string) string {
	ctx, done, err := n.setup.admit(4 * time.Second)
	if err != nil {
		return ""
	}
	defer done()
	if parent.Err() != nil {
		return ""
	}
	stop := context.AfterFunc(parent, done)
	defer stop()
	if a, e := netip.ParseAddr(host); e == nil {
		return reachableAddresses(a.Unmap().String(), n.physical4, n.physical6)
	}
	n.mu.Lock()
	v := n.cache[host]
	n.mu.Unlock()
	if v != "" {
		return v
	}
	lookup := n.lookup
	if lookup == nil {
		lookup = protectedLookup(familyProtect(n.Protect))
	}
	v = reachableAddresses(resolvePhysicalContext(ctx, host, n.resolvers, setupLookup(n.setup, lookup)), n.physical4, n.physical6)
	if v != "" {
		if err := n.setup.publish(func() { n.mu.Lock(); n.cache[host] = v; n.mu.Unlock() }); err != nil {
			return ""
		}
	}
	return v
}
func (n *networkState) bypass(ip netip.Addr) error { return nil } // SO_MARK excludes only engine/control sockets.
func (n *networkState) configure(p Profile) error {
	if err := n.setup.check(); err != nil {
		return err
	}
	n.owned = true
	if e := n.setup.effect(func() error { _, err := n.journal.WriteAt([]byte("XIO019-routing-owned\n"), 0); return err }); e != nil {
		return e
	}
	if e := n.setup.effect(n.journal.Sync); e != nil {
		return e
	}
	if e := applyNetworkPlan(linuxNetworkPlan(p), n.run, &n.applied, n.setup); e != nil {
		return fmt.Errorf("could not configure owned VPN routing or DNS: %w", e)
	}
	return nil
}
func (n *networkState) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n.cleanupCtx = ctx
	defer func() { n.cleanupCtx = nil }()
	undoNetworkPlan(n.applied, n.cleanupCommand)
	n.applied = nil
	if n.lock >= 0 {
		if n.journal != nil {
			if n.owned {
				n.preserveJournal = cleanupLinuxOwned(n.cleanupCommand) != nil
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
