package desktop

import (
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
	"testing"
)

type windowsMock struct {
	t             *testing.T
	ops           windowsNetworkOps
	routes        map[string]*winipcfg.MibIPforwardRow2
	events        []string
	failAt, calls int
}

func routeKey(l winipcfg.LUID, p netip.Prefix, a netip.Addr) string {
	return fmt.Sprintf("%d/%s/%s", l, p, a)
}
func (m *windowsMock) mutation(event string) error {
	m.events = append(m.events, event)
	m.calls++
	if m.failAt >= 0 && m.calls-1 == m.failAt {
		return errors.New("injected mutation failure")
	}
	return nil
}
func newWindowsMock(t *testing.T) *windowsMock {
	m := &windowsMock{t: t, routes: map[string]*winipcfg.MibIPforwardRow2{}, failAt: -1}
	m.ops = windowsNetworkOps{
		interfaceByName: func(name string) (*net.Interface, error) {
			if name != deviceName {
				t.Fatal("not our adapter")
			}
			return &net.Interface{Index: 99, Name: deviceName}, nil
		},
		luidFromIndex: func(index uint32) (winipcfg.LUID, error) {
			if index != 99 {
				t.Fatal("not our adapter index")
			}
			return 99, nil
		},
		settings: func(l winipcfg.LUID, f winipcfg.AddressFamily, mtu int) error {
			if l != 99 || mtu != 1280 {
				t.Fatal("physical MTU/settings changed")
			}
			return m.mutation(fmt.Sprintf("settings:%d", f))
		},
		addresses: func(l winipcfg.LUID, f winipcfg.AddressFamily, a []netip.Prefix) error {
			if l != 99 || len(a) != 2 {
				t.Fatal("physical addresses changed or IPv6 dropped")
			}
			return m.mutation(fmt.Sprintf("addresses:%d", f))
		},
		dns: func(l winipcfg.LUID, f winipcfg.AddressFamily, a []netip.Addr) error {
			if l != 99 || len(a) != 2 {
				t.Fatal("physical DNS changed or IPv6 dropped")
			}
			return m.mutation(fmt.Sprintf("dns:%d", f))
		},
		route: func(l winipcfg.LUID, p netip.Prefix, a netip.Addr) (*winipcfg.MibIPforwardRow2, error) {
			if row := m.routes[routeKey(l, p, a)]; row != nil {
				return row, nil
			}
			return nil, errors.New("not found")
		},
		addRoute: func(l winipcfg.LUID, p netip.Prefix, a netip.Addr, metric uint32) error {
			if p.Addr().Is4() != a.Is4() {
				t.Fatal("route next-hop family mismatch")
			}
			if err := m.mutation("add:" + routeKey(l, p, a)); err != nil {
				return err
			}
			row := &winipcfg.MibIPforwardRow2{InterfaceLUID: l}
			_ = row.DestinationPrefix.SetPrefix(p)
			_ = row.NextHop.SetAddr(a)
			m.routes[routeKey(l, p, a)] = row
			return nil
		},
		deleteRoute: func(row *winipcfg.MibIPforwardRow2) error {
			key := routeKey(row.InterfaceLUID, row.DestinationPrefix.Prefix(), row.NextHop.Addr())
			m.events = append(m.events, "delete:"+key)
			delete(m.routes, key)
			return nil
		},
		enableFirewall: func(luid uint64, unrestricted bool, dns []netip.Addr) error {
			if luid != 99 || unrestricted || len(dns) != 0 {
				t.Fatal("WFP guard did not restrict to our TUN without physical DNS permits")
			}
			return m.mutation("firewall:add")
		},
		disableFirewall: func() { m.events = append(m.events, "firewall:delete") },
		family: func(h windows.Handle) (int, error) {
			if h == 6 {
				return windows.AF_INET6, nil
			}
			return windows.AF_INET, nil
		},
		table: func(family winipcfg.AddressFamily) ([]winipcfg.MibIPforwardRow2, error) {
			return nil, nil
		},
		ifMetric: func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error) { return 0, nil },
	}
	return m
}
func mockedWindowsState(t *testing.T, m *windowsMock) *networkState {
	return &networkState{
		ops:        &m.ops,
		cache:      map[string]string{},
		journal:    filepath.Join(t.TempDir(), "firewall.receipt"),
		physical4:  physicalRoute{4, 4, netip.MustParseAddr("192.0.2.1")},
		physical6:  physicalRoute{6, 6, netip.MustParseAddr("fe80::1")},
		table4:     []routeChoice{{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("192.0.2.1"), 4, 4, 10}},
		table6:     []routeChoice{{netip.MustParsePrefix("::/0"), netip.MustParseAddr("fe80::1"), 6, 6, 10}},
	}
}
func TestWindowsDualstackConfigureAndOwnedCleanup(t *testing.T) {
	p, err := ParseProfile("awg", dualstackAWG)
	if err != nil {
		t.Fatal(err)
	}
	m := newWindowsMock(t)
	n := mockedWindowsState(t, m)
	// An existing host bypass is not ours and must survive disconnect.
	foreign := &winipcfg.MibIPforwardRow2{InterfaceLUID: 4}
	_ = foreign.DestinationPrefix.SetPrefix(netip.MustParsePrefix("203.0.113.9/32"))
	_ = foreign.NextHop.SetAddr(n.physical4.gateway)
	key := routeKey(4, foreign.DestinationPrefix.Prefix(), n.physical4.gateway)
	m.routes[key] = foreign
	// The OS route table already carries that /32; bypass must adopt it as
	// foreign state instead of installing and later deleting a duplicate.
	n.table4 = append(n.table4, routeChoice{netip.MustParsePrefix("203.0.113.9/32"), netip.MustParseAddr("192.0.2.1"), 4, 4, 10})
	if err = n.bypass(netip.MustParseAddr("203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	if err = n.bypass(netip.MustParseAddr("2001:db8::42")); err != nil {
		t.Fatal(err)
	}
	if len(n.routes) != 1 || n.routes[0].DestinationPrefix.Prefix().Bits() != 128 || n.routes[0].InterfaceLUID != 6 {
		t.Fatal("IPv6 bypass did not use /128 and physical6")
	}
	if err = n.configure(p); err != nil {
		t.Fatal(err)
	}
	events := strings.Join(m.events, "\n")
	for _, required := range []string{"settings:2", "settings:23", "addresses:2", "addresses:23", "dns:2", "dns:23", "99/0.0.0.0/1/0.0.0.0", "99/128.0.0.0/1/0.0.0.0", "99/::/1/::", "99/8000::/1/::"} {
		if !strings.Contains(events, required) {
			t.Fatalf("missing %s", required)
		}
	}
	if strings.Index(events, "firewall:add") > strings.Index(events, "add:99/") {
		t.Fatal("IPv6 routes activated before leak guard")
	}
	n.close()
	if len(m.routes) != 1 || m.routes[key] != foreign {
		t.Fatal("cleanup removed foreign route or leaked an owned IPv6 route")
	}
	if _, err = os.Stat(n.journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful cleanup left receipt")
	}
}
func TestWindowsConfigureRollbackEveryFailurePoint(t *testing.T) {
	p, _ := ParseProfile("awg", dualstackAWG)
	for failAt := 0; failAt < 11; failAt++ {
		m := newWindowsMock(t)
		m.failAt = failAt
		n := mockedWindowsState(t, m)
		if err := n.configure(p); err == nil {
			t.Fatalf("failure point %d ignored", failAt)
		}
		n.close()
		if len(m.routes) != 0 {
			t.Fatalf("failure point %d leaked owned routes", failAt)
		}
		if _, err := os.Stat(n.journal); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failure point %d receipt not cleaned", failAt)
		}
	}
}
func TestWindowsLegacyFirewallReceiptIsOwnedAndRetryable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "firewall.receipt")
	name := "XIO-019-IPv6-block-0011223344556677"
	if err := os.WriteFile(path, []byte(name), 0600); err != nil {
		t.Fatal(err)
	}
	fail := true
	remove := func(value string) error {
		if value != name {
			t.Fatal("unowned firewall rule removal")
		}
		if fail {
			return errors.New("injected cleanup failure")
		}
		return nil
	}
	if cleanupLegacyFirewall(path, remove) == nil {
		t.Fatal("cleanup failure ignored")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("receipt lost on cleanup failure")
	}
	fail = false
	if err := cleanupLegacyFirewall(path, remove); err != nil {
		t.Fatal(err)
	}
	if err := cleanupLegacyFirewall(path, remove); err != nil {
		t.Fatal("absence must be success")
	}
	_ = os.WriteFile(path, []byte("Administrator firewall rule"), 0600)
	if cleanupLegacyFirewall(path, remove) == nil {
		t.Fatal("unowned receipt accepted")
	}
}
func TestWindowsSocketProtectionUsesSeparateFamilyInterface(t *testing.T) {
	m := newWindowsMock(t)
	n := mockedWindowsState(t, m)
	var options []string
	m.ops.setsockopt = func(_ windows.Handle, level, option, value int) error {
		options = append(options, fmt.Sprintf("%d:%d:%d", level, option, value))
		return nil
	}
	if !n.Protect(4) || !n.Protect(6) || n.Protect(-1) {
		t.Fatal("socket protection failed")
	}
	if strings.Join(options, ",") != fmt.Sprintf("%d:31:%d,%d:31:6", windows.IPPROTO_IP, int(bits.ReverseBytes32(4)), windows.IPPROTO_IPV6) {
		t.Fatal("wrong family/interface or byte order")
	}
	n.physical4 = physicalRoute{}
	if n.Protect(4) || !n.Protect(6) {
		t.Fatal("missing IPv4 interface accepted or usable IPv6 interface rejected")
	}
	n.table4 = nil
	if n.Resolve("203.0.113.42") != "" || n.Resolve("2001:db8::42") != "2001:db8::42" {
		t.Fatal("route-less family accepted")
	}
	n.firewall = true
	n.cache["cached.example"] = "2001:db8::42"
	if n.Resolve("cached.example") != "2001:db8::42" || n.Resolve("uncached.example") != "" {
		t.Fatal("physical DNS opened after firewall activation")
	}
}
func TestWindowsDefaultRouteSelectionIsPerFamily(t *testing.T) {
	var rows []winipcfg.MibIPforwardRow2
	for i, tc := range []struct {
		prefix, next string
		metric       uint32
	}{{"0.0.0.0/0", "192.0.2.1", 10}, {"::/0", "fe80::1", 20}, {"::/0", "fe80::2", 5}, {"2001:db8::/32", "fe80::3", 0}} {
		row := winipcfg.MibIPforwardRow2{InterfaceLUID: winipcfg.LUID(i + 1), InterfaceIndex: uint32(i + 1), Metric: tc.metric}
		_ = row.DestinationPrefix.SetPrefix(netip.MustParsePrefix(tc.prefix))
		_ = row.NextHop.SetAddr(netip.MustParseAddr(tc.next))
		rows = append(rows, row)
	}
	metric := func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error) { return 5, nil }
	v4 := choosePhysicalRoute(rows, windows.AF_INET, metric)
	v6 := choosePhysicalRoute(rows, windows.AF_INET6, metric)
	if v4.luid != 1 || v6.luid != 3 || v6.gateway.String() != "fe80::2" {
		t.Fatal("IPv6 default reused IPv4 interface or ignored metric")
	}
}

// Live topology variant: a third-party VPN tunnel owns both the metric-0
// default route and a /32 covering the endpoint. Only hardware rows may reach
// route selection; otherwise the tunnel would protect itself through itself.
func TestWindowsHardwareFilterExcludesForeignVPNRoute(t *testing.T) {
	ifaces := []winipcfg.MibIfRow2{
		{InterfaceLUID: 2, InterfaceIndex: 2, Type: winipcfg.IfTypeTunnel, OperStatus: winipcfg.IfOperStatusUp},
		{InterfaceLUID: 15, InterfaceIndex: 15, Type: winipcfg.IfTypeEthernetCSMACD, InterfaceAndOperStatusFlags: winipcfg.IAOSFHardwareInterface, OperStatus: winipcfg.IfOperStatusUp},
		// An up virtual switch without the hardware flag (Hyper-V, VMware).
		{InterfaceLUID: 16, InterfaceIndex: 16, Type: winipcfg.IfTypeEthernetCSMACD, OperStatus: winipcfg.IfOperStatusUp},
		{InterfaceLUID: 1, InterfaceIndex: 1, Type: winipcfg.IfTypeSoftwareLoopback, OperStatus: winipcfg.IfOperStatusUp},
	}
	hardware := hardwareInterfaces(ifaces)
	if len(hardware) != 1 || !hardware[15] {
		t.Fatalf("hardware set %v kept a tunnel, loopback, or virtual switch", hardware)
	}
	rows := []winipcfg.MibIPforwardRow2{
		forwardRow("0.0.0.0/0", "10.8.1.16", 2, 2, 0),
		forwardRow("203.0.113.5/32", "10.8.1.16", 2, 2, 0),
		forwardRow("0.0.0.0/0", "192.168.88.1", 15, 15, 25),
		forwardRow("192.168.88.0/24", "0.0.0.0", 15, 15, 25),
	}
	kept, ok := hardwareRows(rows, hardware)
	if !ok || len(kept) != 2 {
		t.Fatalf("hardware filter kept %d rows ok=%v", len(kept), ok)
	}
	metric := func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error) { return 5, nil }
	physical := choosePhysicalRoute(kept, windows.AF_INET, metric)
	if physical.index != 15 || physical.gateway != netip.MustParseAddr("192.168.88.1") {
		t.Fatalf("physical route followed the foreign VPN: %+v", physical)
	}
	epoint := netip.MustParseAddr("203.0.113.5")
	if choice, ok := endpointRoute(buildRouteChoices(kept, metric, windows.AF_INET), epoint); !ok || choice.index != 15 || choice.luid != 15 {
		t.Fatalf("endpoint route used the foreign VPN: %+v ok=%v", choice, ok)
	}
}

// Empty or unreadable hardware state must never restore the unfiltered table.
func TestWindowsHardwareFilterFailsClosed(t *testing.T) {
	rows := []winipcfg.MibIPforwardRow2{forwardRow("0.0.0.0/0", "10.8.1.16", 2, 2, 0)}
	vpnOnly := []winipcfg.MibIfRow2{{InterfaceLUID: 2, InterfaceIndex: 2, Type: winipcfg.IfTypeTunnel, OperStatus: winipcfg.IfOperStatusUp}}
	if hardware := hardwareInterfaces(vpnOnly); len(hardware) != 0 {
		t.Fatalf("tunnel adapter accepted as hardware: %v", hardware)
	} else if _, ok := hardwareRows(rows, hardware); ok {
		t.Fatal("empty hardware set fell back to the full route table")
	}
	// A hardware link that owns no rows of this family leaves the family unset.
	hardware := map[winipcfg.LUID]bool{15: true}
	if kept, ok := hardwareRows(rows, hardware); ok || len(kept) != 0 {
		t.Fatalf("foreign rows survived hardware filtering: %v ok=%v", kept, ok)
	}
}

// The no-default-route fallback must use a genuinely on-link prefix: an
// unspecified next hop, a non-host, non-default prefix of the right family.
func TestWindowsOnlinkFallbackRequiresUnspecifiedNextHop(t *testing.T) {
	rows := []winipcfg.MibIPforwardRow2{
		forwardRow("::/0", "::", 15, 15, 1),
		forwardRow("2001:db8:1::/64", "fe80::1", 15, 15, 1),
		forwardRow("2001:db8:2::/64", "::", 15, 15, 50),
		forwardRow("2001:db8:2:1::/64", "::", 2, 2, 0),
		forwardRow("2001:db8:3::/64", "::", 2, 2, 0),
		forwardRow("2001:db8:4::42/128", "::", 15, 15, 1),
		forwardRow("192.168.88.0/24", "0.0.0.0", 16, 16, 1),
	}
	metric := func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error) { return 0, nil }
	kept, ok := hardwareRows(rows, map[winipcfg.LUID]bool{15: true, 16: true})
	if !ok || len(kept) != 5 {
		t.Fatalf("hardware filter kept %d rows ok=%v", len(kept), ok)
	}
	r := onlinkPhysicalRoute(kept, windows.AF_INET6, metric)
	if r.index != 15 || r.luid != 15 || !r.gateway.IsUnspecified() || r.gateway.Is4() {
		t.Fatalf("on-link IPv6 fallback chose %+v", r)
	}
	if v4 := onlinkPhysicalRoute(kept, windows.AF_INET, metric); v4.index != 16 || v4.gateway != netip.MustParseAddr("0.0.0.0") {
		t.Fatalf("on-link IPv4 fallback chose %+v", v4)
	}
	// A metric lookup failure excludes the row rather than inventing a cost.
	failing := func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error) { return 0, errors.New("gone") }
	if r := onlinkPhysicalRoute(kept, windows.AF_INET6, failing); r.luid != 0 {
		t.Fatalf("unmeasurable interface selected: %+v", r)
	}
}

// Parse only: none of the generated firewall commands are executed.
func TestWindowsFirewallScriptsParseWithoutExecuting(t *testing.T) {
	powershell := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if _, err := os.Stat(powershell); err != nil {
		t.Skip("Windows PowerShell parser is unavailable")
	}
	parser := "$source=[Console]::In.ReadToEnd(); $tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Output $_.Message }; exit 1 }; exit 0"
	name := "XIO-019-IPv6-block-0011223344556677"
	for _, script := range []string{ipv6FirewallCleanupScript(name)} {
		p := exec.Command(powershell, "-NoProfile", "-NonInteractive", "-Command", parser)
		p.Stdin = strings.NewReader(script)
		if output, err := p.CombinedOutput(); err != nil {
			t.Fatalf("PowerShell syntax: %v: %s", err, output)
		}
	}
}
