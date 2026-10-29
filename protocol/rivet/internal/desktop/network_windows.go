package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const firewallRule = "XIO-019-IPv6-block" // Winsock IP_UNICAST_IF / IPV6_UNICAST_IF use option 31.

type networkState struct {
	lock          windows.Handle
	physical      winipcfg.LUID
	physicalIndex uint32
	gateway       netip.Addr
	routes        []*winipcfg.MibIPforwardRow2
	firewallName  string
	journal       string
	firewall      bool
	cache         map[string]string
	mu            sync.Mutex
}

func isAdmin() bool          { return windows.GetCurrentProcessToken().IsElevated() }
func platformFwmark() string { return "" }
func prepareNetwork() (*networkState, error) {
	base := filepath.Join(os.Getenv("ProgramData"), "XIO")
	if e := os.MkdirAll(base, 0700); e != nil {
		return nil, e
	}
	// Protect privileged bookkeeping against other local users.
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		return nil, e
	}
	if e = windows.SetNamedSecurityInfo(base, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, func() *windows.ACL { acl, _, _ := sd.DACL(); return acl }(), nil); e != nil {
		return nil, e
	}
	path, e := windows.UTF16PtrFromString(filepath.Join(base, "tunnel.lock"))
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, errors.New("another XIO tunnel is active")
	}
	n := &networkState{lock: h, cache: map[string]string{}, journal: filepath.Join(base, "firewall.receipt")}
	if b, e := os.ReadFile(n.journal); e == nil {
		old := string(b)
		if len(old) == len(firewallRule)+17 && strings.HasPrefix(old, firewallRule+"-") {
			if _, e := hex.DecodeString(old[len(firewallRule)+1:]); e == nil {
				_ = netsh("advfirewall", "firewall", "delete", "rule", "name="+old)
			}
		}
		_ = os.Remove(n.journal)
	}
	nonce := make([]byte, 8)
	if _, e := rand.Read(nonce); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	n.firewallName = firewallRule + "-" + hex.EncodeToString(nonce)
	fail := true
	defer func() {
		if fail {
			n.close()
		}
	}()
	if _, e := net.InterfaceByName(deviceName); e == nil {
		return nil, errors.New("the XIO interface already exists")
	}
	rows, e := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if e != nil {
		return nil, e
	}
	best := uint64(^uint32(0)) * 2
	for _, row := range rows {
		if row.DestinationPrefix.Prefix().Bits() != 0 || !row.NextHop.Addr().Is4() {
			continue
		}
		iface, e := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if e != nil {
			continue
		}
		metric := uint64(row.Metric) + uint64(iface.Metric)
		if metric < best {
			best = metric
			n.physical = row.InterfaceLUID
			n.physicalIndex = row.InterfaceIndex
			n.gateway = row.NextHop.Addr()
		}
	}
	if n.physical == 0 {
		return nil, errors.New("no physical IPv4 default route")
	}
	fail = false
	return n, nil
}
func (n *networkState) Protect(fd int64) bool {
	if fd < 0 {
		return false
	}
	h := windows.Handle(fd)
	sa, e := windows.Getsockname(h)
	if e != nil {
		return false
	}
	if _, ok := sa.(*windows.SockaddrInet6); ok {
		return windows.SetsockoptInt(h, windows.IPPROTO_IPV6, 31, int(n.physicalIndex)) == nil
	}
	return windows.SetsockoptInt(h, windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(n.physicalIndex))) == nil
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
	d := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		ok := false
		e := c.Control(func(fd uintptr) { ok = n.Protect(int64(fd)) })
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("physical DNS socket could not be protected")
		}
		return nil
	}}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, network, "1.1.1.1:53")
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
func (n *networkState) bypass(ip netip.Addr) error {
	return n.add(n.physical, netip.PrefixFrom(ip, 32), n.gateway, 1, true)
}
func (n *networkState) add(luid winipcfg.LUID, dest netip.Prefix, next netip.Addr, metric uint32, existing bool) error {
	if _, e := luid.Route(dest, next); e == nil {
		if existing {
			return nil
		}
		return errors.New("the VPN route already exists")
	}
	if e := luid.AddRoute(dest, next, metric); e != nil {
		return e
	}
	row, e := luid.Route(dest, next)
	if e != nil {
		return e
	}
	n.routes = append(n.routes, row)
	return nil
}
func netsh(args ...string) error {
	dir := os.Getenv("SystemRoot")
	p := exec.Command(filepath.Join(dir, "System32", "netsh.exe"), args...)
	// Capture the child's output instead of letting it inherit a null device: netsh is
	// flaky while Windows is still classifying the fresh Wintun adapter, and the text it
	// prints is the only way to tell "access denied" from "service busy".
	out, e := p.CombinedOutput()
	if e == nil {
		return nil
	}
	// Transient failures happen right after the adapter appears; retry a few times before
	// giving up, so a momentary firewall reconfiguration does not abort the connection.
	backoff := 120 * time.Millisecond
	for attempt := 1; attempt <= 4; attempt++ {
		time.Sleep(backoff)
		backoff *= 2
		p = exec.Command(filepath.Join(dir, "System32", "netsh.exe"), args...)
		out, e = p.CombinedOutput()
		if e == nil {
			return nil
		}
	}
	detail := strings.TrimSpace(string(out))
	if len(detail) > 300 {
		detail = detail[:300]
	}
	if detail == "" {
		detail = "<no output>"
	}
	return fmt.Errorf("Windows VPN firewall setup failed (netsh %s: %v): %s",
		strings.Join(args, " "), e, detail)
}
func (n *networkState) configure(p Profile) error {
	iface, e := net.InterfaceByName(deviceName)
	if e != nil {
		return e
	}
	luid, e := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if e != nil {
		return e
	}
	if e = luid.SetIPAddressesForFamily(windows.AF_INET, p.Addresses); e != nil {
		return e
	}
	if e = luid.SetDNS(windows.AF_INET, p.DNS, []string{}); e != nil {
		return e
	}
	// Only our new adapter is configured. IPv6 user traffic is blocked while
	// this IPv4-only client is connected; no OS security setting is disabled.
	// netsh rejects a zero-length prefix ("::/0"), so the same range is
	// expressed as two halves, mirroring the IPv4 routes below.
	if e = os.WriteFile(n.journal, []byte(n.firewallName), 0600); e != nil {
		return e
	}
	n.firewall = true
	if e = netsh("advfirewall", "firewall", "add", "rule", "name="+n.firewallName, "dir=out", "action=block", "remoteip=::/1,8000::/1", "enable=yes", "profile=any"); e != nil {
		return e
	}
	n.firewall = true
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if e = n.add(luid, netip.MustParsePrefix(prefix), netip.IPv4Unspecified(), 1, false); e != nil {
			return e
		}
	}
	return nil
}
func (n *networkState) close() {
	for i := len(n.routes) - 1; i >= 0; i-- {
		_ = n.routes[i].Delete()
	}
	n.routes = nil
	if n.firewall {
		_ = netsh("advfirewall", "firewall", "delete", "rule", "name="+n.firewallName)
		n.firewall = false
		_ = os.Remove(n.journal)
	}
	if n.lock != 0 {
		windows.CloseHandle(n.lock)
		n.lock = 0
	}
}
