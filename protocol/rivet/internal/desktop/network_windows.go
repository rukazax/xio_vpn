package desktop

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	firewall "xio.local/rivet/internal/xiofirewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const firewallRule = "XIO-019-IPv6-block" // Keep the owned-receipt namespace across upgrades.

// SO_PROTOCOL_INFO(W) reports the socket's address family even before bind.
// getsockname fails with WSAEINVAL on the unbound socket that Go hands to
// net.Dialer.Control, so it can only be a fallback for already-bound sockets.
const soProtocolInfo = 0x2005
const ipUnicastIf = 31

type physicalRoute struct {
	luid    winipcfg.LUID
	index   uint32
	gateway netip.Addr
}

// All network mutations used by configure/bypass/close are injectable; unit
// tests must never touch a real adapter, routing table, or firewall.
type windowsNetworkOps struct {
	interfaceByName func(string) (*net.Interface, error)
	luidFromIndex   func(uint32) (winipcfg.LUID, error)
	addresses       func(winipcfg.LUID, winipcfg.AddressFamily, []netip.Prefix) error
	settings        func(winipcfg.LUID, winipcfg.AddressFamily, int) error
	dns             func(winipcfg.LUID, winipcfg.AddressFamily, []netip.Addr) error
	route           func(winipcfg.LUID, netip.Prefix, netip.Addr) (*winipcfg.MibIPforwardRow2, error)
	addRoute        func(winipcfg.LUID, netip.Prefix, netip.Addr, uint32) error
	deleteRoute     func(*winipcfg.MibIPforwardRow2) error
	enableFirewall  func(uint64, bool, []netip.Addr) error
	disableFirewall func()
	table           func(winipcfg.AddressFamily) ([]winipcfg.MibIPforwardRow2, error)
	ifTable         func() ([]winipcfg.MibIfRow2, error)
	ifMetric        func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error)
	family          func(windows.Handle) (int, error)
	getsockname     func(windows.Handle) (windows.Sockaddr, error)
	setsockopt      func(windows.Handle, int, int, int) error
}

var nativeWindowsNetworkOps = windowsNetworkOps{
	interfaceByName: net.InterfaceByName,
	luidFromIndex:   winipcfg.LUIDFromIndex,
	addresses: func(l winipcfg.LUID, f winipcfg.AddressFamily, a []netip.Prefix) error {
		return l.SetIPAddressesForFamily(f, a)
	},
	settings: func(l winipcfg.LUID, f winipcfg.AddressFamily, mtu int) error {
		row, err := l.IPInterface(f)
		if err != nil {
			return err
		}
		row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		row.DadTransmits = 0
		row.ManagedAddressConfigurationSupported = false
		row.OtherStatefulConfigurationSupported = false
		row.UseAutomaticMetric = false
		row.Metric = 0
		row.NLMTU = uint32(mtu)
		return row.Set()
	},
	dns: func(l winipcfg.LUID, f winipcfg.AddressFamily, a []netip.Addr) error { return l.SetDNS(f, a, nil) },
	route: func(l winipcfg.LUID, p netip.Prefix, a netip.Addr) (*winipcfg.MibIPforwardRow2, error) {
		return l.Route(p, a)
	},
	addRoute:        func(l winipcfg.LUID, p netip.Prefix, a netip.Addr, m uint32) error { return l.AddRoute(p, a, m) },
	deleteRoute:     func(r *winipcfg.MibIPforwardRow2) error { return r.Delete() },
	enableFirewall:  firewall.EnableFirewall,
	disableFirewall: firewall.DisableFirewall,
	table:           winipcfg.GetIPForwardTable2,
	ifTable: func() ([]winipcfg.MibIfRow2, error) {
		return winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	},
	ifMetric: func(l winipcfg.LUID, f winipcfg.AddressFamily) (uint32, error) {
		row, err := l.IPInterface(f)
		if err != nil {
			return 0, err
		}
		return row.Metric, nil
	},
	family:      socketFamily,
	getsockname: windows.Getsockname,
	setsockopt:  windows.SetsockoptInt,
}

func socketFamily(h windows.Handle) (int, error) {
	var info windows.WSAProtocolInfo
	n := int32(unsafe.Sizeof(info))
	if e := windows.Getsockopt(h, windows.SOL_SOCKET, soProtocolInfo, (*byte)(unsafe.Pointer(&info)), &n); e != nil {
		return 0, e
	}
	return int(info.AddressFamily), nil
}

// routeChoice is one route-table row with the interface metric folded in, so
// endpoint selection is a pure function tests can drive without an adapter.
type routeChoice struct {
	prefix netip.Prefix
	next   netip.Addr
	luid   winipcfg.LUID
	index  uint32
	metric uint32
}

func buildRouteChoices(rows []winipcfg.MibIPforwardRow2, metric func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error), family winipcfg.AddressFamily) []routeChoice {
	choices := make([]routeChoice, 0, len(rows))
	metrics := map[winipcfg.LUID]uint32{}
	for _, row := range rows {
		p := row.DestinationPrefix.Prefix()
		if !p.IsValid() || row.InterfaceLUID == 0 {
			continue
		}
		m, ok := metrics[row.InterfaceLUID]
		if !ok {
			m, _ = metric(row.InterfaceLUID, family)
			metrics[row.InterfaceLUID] = m
		}
		choices = append(choices, routeChoice{p, row.NextHop.Addr().Unmap(), row.InterfaceLUID, row.InterfaceIndex, row.Metric + m})
	}
	return choices
}

// endpointRoute selects the OS route for one endpoint: longest matching prefix
// first, then the lowest combined route+interface metric, then the lowest
// interface index. A default route owned by an unrelated VPN adapter therefore
// cannot capture an endpoint that the LAN route already covers.
func endpointRoute(entries []routeChoice, dest netip.Addr) (routeChoice, bool) {
	var best routeChoice
	found := false
	for _, e := range entries {
		if !e.prefix.Contains(dest) {
			continue
		}
		if !found || betterEndpointRoute(e, best) {
			best, found = e, true
		}
	}
	return best, found
}

func betterEndpointRoute(a, b routeChoice) bool {
	if x, y := a.prefix.Bits(), b.prefix.Bits(); x != y {
		return x > y
	}
	if a.metric != b.metric {
		return a.metric < b.metric
	}
	return a.index < b.index
}

type networkState struct {
	lock                 windows.Handle
	physical4, physical6 physicalRoute
	table4, table6       []routeChoice
	device               winipcfg.LUID
	routes               []*winipcfg.MibIPforwardRow2
	journal              string
	firewall             bool
	cache                map[string]string
	resolvers            []string
	mu                   sync.Mutex
	ops                  *windowsNetworkOps
}

func (n *networkState) api() *windowsNetworkOps {
	if n.ops != nil {
		return n.ops
	}
	return &nativeWindowsNetworkOps
}
func (n *networkState) physicalFor(a netip.Addr) physicalRoute {
	if a.Is6() {
		return n.physical6
	}
	return n.physical4
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
	if e := cleanupLegacyFirewall(n.journal, removeOwnedFirewall); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	fail := true
	defer func() {
		if fail {
			n.close()
		}
	}()
	if _, e := net.InterfaceByName(deviceName); e == nil {
		return nil, errors.New("the XIO interface already exists")
	}
	ifaces, e := n.api().ifTable()
	if e != nil {
		return nil, errors.New("cannot enumerate network interfaces for route protection")
	}
	hardware := hardwareInterfaces(ifaces)
	if len(hardware) == 0 {
		return nil, errors.New("no active hardware network interface")
	}
	var fallback4, fallback6 []winipcfg.MibIPforwardRow2
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, e := winipcfg.GetIPForwardTable2(family)
		if e != nil {
			continue
		}
		// A third-party VPN adapter owns a default route, and often a more
		// specific route to the very endpoint we dial, with a lower metric than
		// the physical link. Rows of non-hardware adapters are therefore dropped
		// before any choice is made, so a tunnel cannot select the tunnel.
		rows, ok := hardwareRows(rows, hardware)
		if !ok {
			continue
		}
		if family == windows.AF_INET {
			fallback4 = rows
		} else {
			fallback6 = rows
		}
		choices := buildRouteChoices(rows, n.api().ifMetric, family)
		physical := choosePhysicalRoute(rows, family, n.api().ifMetric)
		if family == windows.AF_INET {
			n.physical4 = physical
			n.table4 = choices
		} else {
			n.physical6 = physical
			n.table6 = choices
		}
	}
	// A physical link can carry the endpoint prefix without a default route of
	// that family (typical for IPv6 on a LAN). Fall back to the best on-link
	// prefix route so family-wide protection still has a physical target.
	if n.physical4.luid == 0 {
		n.physical4 = onlinkPhysicalRoute(fallback4, windows.AF_INET, n.api().ifMetric)
	}
	if n.physical6.luid == 0 {
		n.physical6 = onlinkPhysicalRoute(fallback6, windows.AF_INET6, n.api().ifMetric)
	}
	if n.physical4.luid == 0 && n.physical6.luid == 0 {
		return nil, errors.New("no physical IPv4 or IPv6 default route")
	}
	seen := map[string]bool{}
	for _, physical := range []physicalRoute{n.physical4, n.physical6} {
		if physical.luid == 0 {
			continue
		}
		servers, _ := physical.luid.DNS()
		for _, a := range servers {
			a = a.Unmap()
			if a.IsLoopback() || a.IsUnspecified() || n.physicalFor(a).luid == 0 {
				continue
			}
			if a.Is6() && a.IsLinkLocalUnicast() {
				if physical.index != n.physical6.index {
					continue
				}
				a = a.WithZone(strconv.Itoa(int(physical.index)))
			}
			server := net.JoinHostPort(a.String(), "53")
			if !seen[server] {
				n.resolvers = append(n.resolvers, server)
				seen[server] = true
			}
		}
	}
	if len(n.resolvers) == 0 {
		if n.physical4.luid != 0 {
			n.resolvers = append(n.resolvers, "1.1.1.1:53")
		}
		if n.physical6.luid != 0 {
			n.resolvers = append(n.resolvers, "[2606:4700:4700::1111]:53")
		}
	}
	fail = false
	return n, nil
}
func choosePhysicalRoute(rows []winipcfg.MibIPforwardRow2, family winipcfg.AddressFamily, metric func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error)) physicalRoute {
	var result physicalRoute
	best := ^uint64(0)
	for _, row := range rows {
		a := row.NextHop.Addr()
		if row.DestinationPrefix.Prefix().Bits() != 0 || a.Is4() != (family == windows.AF_INET) {
			continue
		}
		m, e := metric(row.InterfaceLUID, family)
		if e != nil {
			continue
		}
		cost := uint64(row.Metric) + uint64(m)
		if cost < best {
			best = cost
			result = physicalRoute{row.InterfaceLUID, row.InterfaceIndex, a}
		}
	}
	return result
}

// hardwareInterfaces returns the LUIDs of adapters that are real links:
// third-party VPN tunnels (WireGuard/AmneziaVPN report IF_TYPE_TUNNEL),
// Hyper-V virtual switches, loopback, and any adapter Windows does not flag as
// hardware are excluded. An unrelated VPN that owns a lower-metric default
// route, or a more specific route to the endpoint, must never decide which
// physical link carries our tunnel.
func hardwareInterfaces(ifaces []winipcfg.MibIfRow2) map[winipcfg.LUID]bool {
	hardware := map[winipcfg.LUID]bool{}
	for _, iface := range ifaces {
		if iface.Type == winipcfg.IfTypeTunnel || iface.Type == winipcfg.IfTypeSoftwareLoopback {
			continue
		}
		if iface.InterfaceAndOperStatusFlags&winipcfg.IAOSFHardwareInterface == 0 {
			continue
		}
		if iface.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		hardware[iface.InterfaceLUID] = true
	}
	return hardware
}

// hardwareRows keeps only forwarding rows of hardware links. ok is false when
// no such row remains; the caller must then leave the family unconfigured
// instead of reusing the full table, because that fallback would hand route
// selection back to the VPN adapter this filter exists to exclude.
func hardwareRows(rows []winipcfg.MibIPforwardRow2, hardware map[winipcfg.LUID]bool) ([]winipcfg.MibIPforwardRow2, bool) {
	kept := make([]winipcfg.MibIPforwardRow2, 0, len(rows))
	for _, row := range rows {
		if hardware[row.InterfaceLUID] {
			kept = append(kept, row)
		}
	}
	return kept, len(kept) > 0
}

// onlinkPhysicalRoute picks the best on-link prefix route of a hardware link.
// It is the fallback for a family that has no default route of its own. Only a
// row with an unspecified next hop is genuinely on-link; a prefix route that
// points at a gateway would require an address the family may not have.
func onlinkPhysicalRoute(rows []winipcfg.MibIPforwardRow2, family winipcfg.AddressFamily, metric func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error)) physicalRoute {
	var result physicalRoute
	bestBits := -1
	bestCost := ^uint64(0)
	for _, row := range rows {
		a := row.NextHop.Addr().Unmap()
		if !a.IsUnspecified() || a.Is4() != (family == windows.AF_INET) {
			continue
		}
		p := row.DestinationPrefix.Prefix()
		if !p.IsValid() || p.Bits() == 0 || p.Bits() == p.Addr().BitLen() {
			continue
		}
		if p.Addr().IsUnspecified() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsMulticast() {
			continue
		}
		m, e := metric(row.InterfaceLUID, family)
		if e != nil {
			continue
		}
		cost := uint64(row.Metric) + uint64(m)
		if p.Bits() > bestBits || p.Bits() == bestBits && (cost < bestCost || cost == bestCost && result.index != 0 && row.InterfaceIndex < result.index) {
			bestBits = p.Bits()
			bestCost = cost
			result = physicalRoute{row.InterfaceLUID, row.InterfaceIndex, a}
		}
	}
	return result
}

// Protect pins a socket to the physical interface of its address family. Go
// invokes net.Dialer.Control before bind/connect, so the socket has no local
// address yet and getsockname reports WSAEINVAL; SO_PROTOCOL_INFO supplies the
// family in that state.
func (n *networkState) Protect(fd int64) bool {
	return n.protect(fd, physicalRoute{}, 0)
}

// ProtectAddr pins a socket to the route selected for its destination. Callers
// that know the dial target use this instead of the family default; a
// mismatched or unavailable route fails closed.
func (n *networkState) ProtectAddr(fd int64, address string) bool {
	route, is6, ok := n.endpointAddressRoute(address)
	if !ok {
		return n.Protect(fd)
	}
	family := winipcfg.AddressFamily(windows.AF_INET)
	if is6 {
		family = windows.AF_INET6
	}
	return n.protect(fd, route, family)
}

func (n *networkState) protect(fd int64, hint physicalRoute, hintFamily winipcfg.AddressFamily) bool {
	if fd < 0 {
		return false
	}
	h := windows.Handle(fd)
	family, e := n.api().family(h)
	if e != nil {
		// Fallback for providers that reject SO_PROTOCOL_INFO; only a bound
		// socket can still report its family this way.
		sa, se := n.api().getsockname(h)
		if se != nil {
			return false
		}
		switch sa.(type) {
		case *windows.SockaddrInet6:
			family = windows.AF_INET6
		case *windows.SockaddrInet4:
			family = windows.AF_INET
		default:
			return false
		}
	}
	if hintFamily != 0 && hintFamily != winipcfg.AddressFamily(family) {
		return false
	}
	// Winsock uses option 31 for both families, but only IPv4 is network-order.
	switch family {
	case windows.AF_INET6:
		index := n.physical6.index
		if hint.index != 0 {
			index = hint.index
		}
		return index != 0 && n.api().setsockopt(h, windows.IPPROTO_IPV6, ipUnicastIf, int(index)) == nil
	case windows.AF_INET:
		index := n.physical4.index
		if hint.index != 0 {
			index = hint.index
		}
		return index != 0 && n.api().setsockopt(h, windows.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(index))) == nil
	}
	return false
}

// routeFor returns the physical route the OS would use for a destination. Rows
// belonging to our own TUN are skipped so protection maps back to the physical
// link, never into the tunnel it is meant to avoid.
func (n *networkState) routeFor(dest netip.Addr) (routeChoice, bool) {
	dest = dest.Unmap()
	if !dest.IsValid() || dest.IsUnspecified() || dest.IsMulticast() || dest.IsLoopback() {
		return routeChoice{}, false
	}
	entries := n.table4
	if dest.Is6() {
		entries = n.table6
	}
	if len(entries) == 0 {
		return routeChoice{}, false
	}
	filtered := entries
	if n.device != 0 {
		filtered = make([]routeChoice, 0, len(entries))
		for _, e := range entries {
			if e.luid != n.device {
				filtered = append(filtered, e)
			}
		}
	}
	return endpointRoute(filtered, dest)
}

func (n *networkState) endpointAddressRoute(address string) (physicalRoute, bool, bool) {
	host := address
	if h, _, e := net.SplitHostPort(address); e == nil {
		host = h
	}
	a, e := netip.ParseAddr(strings.Trim(host, "[]"))
	if e != nil {
		return physicalRoute{}, false, false
	}
	a = a.Unmap()
	choice, ok := n.routeFor(a)
	if !ok {
		return physicalRoute{}, false, false
	}
	return physicalRoute{choice.luid, choice.index, choice.next}, a.Is6(), true
}

// DescribeRoute reports the endpoint decision for diagnostics.
func (n *networkState) DescribeRoute(address string) string {
	route, is6, ok := n.endpointAddressRoute(address)
	if !ok {
		return "no-route"
	}
	family := "ipv4"
	if is6 {
		family = "ipv6"
	}
	return fmt.Sprintf("%s ifIndex=%d luid=%d nextHop=%s", family, route.index, route.luid, route.gateway)
}
func (n *networkState) Resolve(host string) string {
	if a, e := netip.ParseAddr(host); e == nil {
		a = a.Unmap()
		if _, ok := n.routeFor(a); !ok {
			return ""
		}
		return a.String()
	}
	n.mu.Lock()
	v := n.cache[host]
	blocked := n.firewall
	n.mu.Unlock()
	if v != "" {
		return v
	}
	// Endpoints are resolved before full-tunnel/firewall setup. Do not open an
	// uncached physical DNS path after installing leak protection.
	if blocked {
		return ""
	}
	v = reachableAddresses(resolvePhysical(host, n.resolvers, n.ProtectAddr), len(n.table4) > 0, len(n.table6) > 0)
	if v != "" {
		n.mu.Lock()
		n.cache[host] = v
		n.mu.Unlock()
	}
	return v
}
func (n *networkState) bypass(ip netip.Addr) error {
	ip = ip.Unmap()
	choice, ok := n.routeFor(ip)
	if !ok {
		return errors.New("no physical route for endpoint")
	}
	prefix := netip.PrefixFrom(ip, ip.BitLen())
	// A pre-existing more-specific route belongs to the OS or another client.
	// Never add a competing row and never track that row for cleanup.
	for _, entry := range n.table(ip) {
		if entry.luid == choice.luid && entry.prefix == prefix {
			return nil
		}
	}
	if e := n.add(choice.luid, prefix, choice.next, 1, false); e != nil {
		return e
	}
	return nil
}

func (n *networkState) table(ip netip.Addr) []routeChoice {
	if ip.Is6() {
		return n.table6
	}
	return n.table4
}
func (n *networkState) add(luid winipcfg.LUID, dest netip.Prefix, next netip.Addr, metric uint32, existing bool) error {
	if _, e := n.api().route(luid, dest, next); e == nil {
		if existing {
			return nil
		}
		return errors.New("the VPN route already exists")
	}
	// Store the exact deletion selectors without a racy post-add lookup. A
	// failed lookup after AddRoute used to leave a successful route untracked.
	row := &winipcfg.MibIPforwardRow2{InterfaceLUID: luid}
	if e := row.DestinationPrefix.SetPrefix(dest); e != nil {
		return e
	}
	if e := row.NextHop.SetAddr(next); e != nil {
		return e
	}
	if e := n.api().addRoute(luid, dest, next, metric); e != nil {
		return e
	}
	n.routes = append(n.routes, row)
	return nil
}

// Accept only the old random owned-rule namespace. A failed removal keeps the
// receipt for retry; verified absence is success. Dynamic WFP needs no receipt.
func cleanupLegacyFirewall(path string, remove func(string) error) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	name := string(b)
	if len(name) != len(firewallRule)+17 || !strings.HasPrefix(name, firewallRule+"-") {
		return errors.New("invalid owned firewall receipt")
	}
	if _, err = hex.DecodeString(name[len(firewallRule)+1:]); err != nil {
		return errors.New("invalid owned firewall receipt")
	}
	if err = remove(name); err != nil {
		return err
	}
	return os.Remove(path)
}
func removeOwnedFirewall(name string) error {
	return runFirewallScript(ipv6FirewallCleanupScript(name))
}
func runFirewallScript(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", "-")
	p.Stdin = strings.NewReader(script)
	if e := p.Run(); e != nil {
		return errors.New("Windows VPN IPv6 leak protection failed")
	}
	return nil
}
func (n *networkState) configure(p Profile) error {
	iface, e := n.api().interfaceByName(deviceName)
	if e != nil {
		return e
	}
	luid, e := n.api().luidFromIndex(uint32(iface.Index))
	if e != nil {
		return e
	}
	n.device = luid
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		// Both families belong to the NEW adapter only; physical settings stay intact.
		if e = n.api().settings(luid, family, p.MTU); e != nil {
			return e
		}
		if e = n.api().addresses(luid, family, p.Addresses); e != nil {
			return e
		}
		if e = n.api().dns(luid, family, p.DNS); e != nil {
			return e
		}
	}
	// Reuse WireGuard's maintained WFP implementation instead of weakening the
	// old global IPv6 block with a snapshot of physical interface aliases.
	// Its dynamic session permits only this helper, loopback, the TUN, DHCP,
	// and narrowly typed NDP, and blocks other physical IPv4/IPv6 traffic.
	// Newly created adapters are covered automatically; no OS firewall policy
	// is disabled or replaced, and process exit releases only our WFP objects.
	// Do not use the optional DNS-IP permit list: it would permit plaintext DNS
	// on physical links. DNS, like all payload, must cross the TUN interface.
	if e = n.api().enableFirewall(uint64(luid), false, nil); e != nil {
		return e
	}
	n.mu.Lock()
	n.firewall = true
	n.mu.Unlock()
	// Half-defaults capture either family, including an unprovisioned family
	// (which the engine drops). The dynamic WFP guard covers both IP families.
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		dest := netip.MustParsePrefix(prefix)
		next := netip.IPv4Unspecified()
		if dest.Addr().Is6() {
			next = netip.IPv6Unspecified()
		}
		if e = n.add(luid, dest, next, 1, false); e != nil {
			return e
		}
	}
	return nil
}
func (n *networkState) close() {
	for i := len(n.routes) - 1; i >= 0; i-- {
		_ = n.api().deleteRoute(n.routes[i])
	}
	n.routes = nil
	if n.firewall {
		n.api().disableFirewall()
		n.mu.Lock()
		n.firewall = false
		n.mu.Unlock()
	}
	if n.lock != 0 {
		windows.CloseHandle(n.lock)
		n.lock = 0
	}
}

