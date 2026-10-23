package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const routeTable = "28691"
const mark = 0x580019

type networkState struct {
	owned   bool
	journal *os.File
	lock    int
	rules   []struct {
		family string
		pref   string
	}
	table    bool
	dns      bool
	mu       sync.Mutex
	cache    map[string]string
	resolver string
}

func isAdmin() bool          { return os.Geteuid() == 0 }
func platformFwmark() string { return "fwmark=" + strconv.Itoa(mark) + "\n" }
func ip(args ...string) error {
	p := exec.Command("/usr/sbin/ip", args...)
	if _, e := p.Output(); e != nil {
		return errors.New("could not configure owned VPN routing")
	}
	return nil
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
	n := &networkState{lock: fd, cache: map[string]string{}, resolver: "1.1.1.1:53"}
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
		n.cleanupOwned()
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
		out, e := exec.Command("/usr/sbin/ip", family, "route", "show", "table", routeTable).CombinedOutput()
		if e == nil && len(strings.TrimSpace(string(out))) > 0 {
			return nil, errors.New("routing table is already used")
		}
		b, e := exec.Command("/usr/sbin/ip", family, "-j", "rule", "show").Output()
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
	}
	if b, e := exec.Command("/usr/bin/resolvectl", "dns").Output(); e == nil {
		for _, word := range strings.Fields(string(b)) {
			if a, e := netip.ParseAddr(word); e == nil && a.Is4() && !a.IsLoopback() {
				n.resolver = net.JoinHostPort(a.String(), "53")
				break
			}
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
		return a.String()
	}
	n.mu.Lock()
	v := n.cache[host]
	n.mu.Unlock()
	if v != "" {
		return v
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
			ok := false
			err := c.Control(func(fd uintptr) { ok = n.Protect(int64(fd)) })
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("physical DNS socket could not be protected")
			}
			return nil
		}}
		return d.DialContext(ctx, network, n.resolver)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ips, e := resolver.LookupNetIP(ctx, "ip4", host)
	if e != nil || len(ips) == 0 {
		return ""
	}
	v = ips[0].String()
	n.mu.Lock()
	n.cache[host] = v
	n.mu.Unlock()
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

	for _, a := range p.Addresses {
		if e := ip("-4", "addr", "add", a.String(), "dev", deviceName); e != nil {
			return e
		}
	}
	if e := ip("link", "set", "dev", deviceName, "mtu", strconv.Itoa(p.MTU), "up"); e != nil {
		return e
	}
	if e := ip("-4", "route", "add", "default", "dev", deviceName, "table", routeTable); e != nil {
		return e
	}
	n.table = true
	if e := ip("-6", "route", "add", "blackhole", "default", "table", routeTable); e != nil {
		return e
	}
	for _, family := range []string{"-4", "-6"} {
		if e := ip(family, "rule", "add", "pref", "18018", "fwmark", "0x80000/0xff0000", "lookup", "main"); e != nil {
			return e
		}
		n.rules = append(n.rules, struct{ family, pref string }{family, "18018"})
		if e := ip(family, "rule", "add", "pref", "18019", "not", "fwmark", "0x580019", "lookup", routeTable); e != nil {
			return e
		}
		n.rules = append(n.rules, struct{ family, pref string }{family, "18019"})
	}
	args := []string{"dns", deviceName}
	for _, a := range p.DNS {
		args = append(args, a.String())
	}
	if e := exec.Command("/usr/bin/resolvectl", args...).Run(); e != nil {
		return errors.New("systemd-resolved could not configure VPN DNS")
	}
	n.dns = true
	if e := exec.Command("/usr/bin/resolvectl", "domain", deviceName, "~.").Run(); e != nil {
		return e
	}
	return nil
}
func (n *networkState) close() {
	if n.dns {
		_ = exec.Command("/usr/bin/resolvectl", "revert", deviceName).Run()
	}
	for i := len(n.rules) - 1; i >= 0; i-- {
		r := n.rules[i]
		if r.pref == "18018" {
			_ = ip(r.family, "rule", "del", "pref", r.pref, "fwmark", "0x80000/0xff0000", "lookup", "main")
		} else {
			_ = ip(r.family, "rule", "del", "pref", r.pref, "not", "fwmark", "0x580019", "lookup", routeTable)
		}
	}
	n.rules = nil
	if n.table {
		_ = ip("-4", "route", "flush", "table", routeTable)
		_ = ip("-6", "route", "flush", "table", routeTable)
		n.table = false
	}
	if n.lock >= 0 {
		if n.journal != nil {
			if n.owned {
				n.cleanupOwned()
			}
			_ = n.journal.Truncate(0)
			_ = n.journal.Sync()
			_ = n.journal.Close()
			n.journal = nil
		} else {
			unix.Close(n.lock)
		}
		n.lock = -1
	}
}

func (n *networkState) cleanupOwned() {
	for _, family := range []string{"-4", "-6"} {
		_ = ip(family, "rule", "del", "pref", "18018", "fwmark", "0x80000/0xff0000", "lookup", "main")
		_ = ip(family, "rule", "del", "pref", "18019", "not", "fwmark", "0x580019", "lookup", routeTable)
	}
	_ = ip("-4", "route", "del", "default", "dev", deviceName, "table", routeTable)
	_ = ip("-6", "route", "del", "blackhole", "default", "table", routeTable)
	_ = exec.Command("/usr/bin/resolvectl", "revert", deviceName).Run()
}
