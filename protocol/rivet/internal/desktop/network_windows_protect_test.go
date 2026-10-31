//go:build windows

package desktop

import (
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Regression: Go calls net.Dialer.Control before bind/connect, so getsockname
// returns WSAEINVAL (10022) and socket protection failed on every dial.
func TestWindowsProtectDetectsFamilyOnUnboundSocket(t *testing.T) {
	ph := newProtectHarness()
	for _, tc := range []struct {
		family       int
		level, value int
	}{{windows.AF_INET, windows.IPPROTO_IP, int(bits.ReverseBytes32(15))}, {windows.AF_INET6, windows.IPPROTO_IPV6, 22}} {
		sh, err := windows.Socket(tc.family, windows.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !ph.Protect(int64(sh)) {
			windows.CloseHandle(sh)
			t.Fatalf("family %d: protection refused on an unbound socket", tc.family)
		}
		windows.CloseHandle(sh)
		if got := ph.take(); len(got) != 1 || got[0] != fmt.Sprintf("%d:31:%d", tc.level, tc.value) {
			t.Fatalf("family %d: wrong option %v", tc.family, got)
		}
	}
}

func TestWindowsProtectInsideDialerControlAllowsLoopback(t *testing.T) {
	ph := newProtectHarness()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	refusals := 0
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		ok := false
		if e := c.Control(func(fd uintptr) { ok = ph.Protect(int64(fd)) }); e != nil {
			return e
		}
		if !ok {
			refusals++
			return fmt.Errorf("physical DNS socket could not be protected")
		}
		return nil
	}}
	conn, err := d.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial through Control failed (refusals=%d): %v", refusals, err)
	}
	conn.Close()
}

// Reported live topology: an unrelated VPN adapter owns the metric-0 default
// route while the endpoint sits in the LAN prefix on Ethernet.
func TestWindowsEndpointRoutePrefersLongestPrefix(t *testing.T) {
	rows := []winipcfg.MibIPforwardRow2{
		forwardRow("0.0.0.0/0", "10.8.1.16", 2, 2, 0),
		forwardRow("0.0.0.0/0", "192.168.88.1", 15, 15, 1),
		forwardRow("192.168.88.0/24", "0.0.0.0", 15, 15, 25),
	}
	metric := func(winipcfg.LUID, winipcfg.AddressFamily) (uint32, error) { return 5, nil }
	entries := buildRouteChoices(rows, metric, windows.AF_INET)
	if choice, ok := endpointRoute(entries, netip.MustParseAddr("192.168.88.17")); !ok || choice.index != 15 || choice.next != netip.MustParseAddr("0.0.0.0") {
		t.Fatalf("LAN endpoint selected %+v ok=%v, want Ethernet on-link", choice, ok)
	}
	if choice, ok := endpointRoute(entries, netip.MustParseAddr("203.0.113.5")); !ok || choice.index != 2 {
		t.Fatalf("default-route endpoint selected %+v ok=%v", choice, ok)
	}
	st := &networkState{table4: entries, physical4: physicalRoute{2, 2, netip.MustParseAddr("10.8.1.16")}}
	if got := st.DescribeRoute("192.168.88.17:443"); !strings.Contains(got, "ifIndex=15") {
		t.Fatalf("diagnostics did not report Ethernet: %s", got)
	}
}

func TestWindowsRouteForSkipsOwnTunAndFailsClosed(t *testing.T) {
	st := &networkState{
		device: 99,
		table4: []routeChoice{
			{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParseAddr("0.0.0.0"), 99, 99, 0},
			{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("192.168.88.1"), 15, 15, 1},
		},
	}
	if choice, ok := st.routeFor(netip.MustParseAddr("203.0.113.5")); !ok || choice.index != 15 {
		t.Fatalf("own TUN route captured the endpoint: %+v ok=%v", choice, ok)
	}
	st.table4 = []routeChoice{{netip.MustParsePrefix("192.168.88.0/24"), netip.MustParseAddr("0.0.0.0"), 15, 15, 1}}
	if err := st.bypass(netip.MustParseAddr("203.0.113.5")); err == nil {
		t.Fatal("bypass accepted an endpoint with no physical route")
	}
	if st.DescribeRoute("203.0.113.5:443") != "no-route" {
		t.Fatal("diagnostics invented a route")
	}
}

func TestWindowsBypassUsesEndpointRouteAndKeepsForeignRoute(t *testing.T) {
	m := newWindowsMock(t)
	st := mockedWindowsState(t, m)
	// Ethernet carries the LAN prefix; the metric-0 default sits on the VPN adapter.
	st.table4 = []routeChoice{
		{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("10.8.1.16"), 2, 2, 0},
		{netip.MustParsePrefix("192.168.88.0/24"), netip.MustParseAddr("0.0.0.0"), 15, 15, 26},
	}
	prefix := netip.MustParsePrefix("192.168.88.17/32")
	onlink := netip.MustParseAddr("0.0.0.0")
	foreign := &winipcfg.MibIPforwardRow2{InterfaceLUID: 15}
	_ = foreign.DestinationPrefix.SetPrefix(prefix)
	_ = foreign.NextHop.SetAddr(onlink)
	m.routes[routeKey(15, prefix, onlink)] = foreign
	// An existing /32 for the endpoint is visible in the snapshot.
	st.table4 = append(st.table4, routeChoice{prefix, onlink, 15, 15, 24178})
	if err := st.bypass(netip.MustParseAddr("192.168.88.17")); err != nil {
		t.Fatal(err)
	}
	if len(st.routes) != 0 {
		t.Fatal("bypass claimed a pre-existing route for cleanup")
	}
	st.close()
	if _, ok := m.routes[routeKey(15, prefix, onlink)]; !ok {
		t.Fatal("cleanup removed a route it did not create")
	}
	// A fresh endpoint in the same prefix installs an on-link /32 via Ethernet.
	if err := st.bypass(netip.MustParseAddr("192.168.88.99")); err != nil {
		t.Fatal(err)
	}
	if len(st.routes) != 1 || st.routes[0].InterfaceLUID != 15 || st.routes[0].NextHop.Addr() != onlink {
		t.Fatalf("bypass did not follow the endpoint route: %+v", st.routes)
	}
}

func TestWindowsProtectAddrPinsEndpointInterface(t *testing.T) {
	ph := newProtectHarness()
	ph.table4 = []routeChoice{{netip.MustParsePrefix("192.168.88.0/24"), netip.MustParseAddr("0.0.0.0"), 15, 15, 26}}
	// The IPv6 physical interface is 22, so an IPv4 endpoint must use index 15.
	sh, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(sh)
	if !ph.ProtectAddr(int64(sh), "192.168.88.17:443") {
		t.Fatal("endpoint protection refused")
	}
	if got := ph.take(); len(got) != 1 || got[0] != fmt.Sprintf("%d:31:%d", windows.IPPROTO_IP, int(bits.ReverseBytes32(15))) {
		t.Fatalf("endpoint interface not used: %v", got)
	}
	// Family mismatch fails closed instead of pinning the wrong interface.
	sh6, err := windows.Socket(windows.AF_INET6, windows.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(sh6)
	if ph.ProtectAddr(int64(sh6), "192.168.88.17:443") {
		t.Fatal("IPv4 endpoint accepted on an IPv6 socket")
	}
}

func TestWindowsSocketProtectFailsClosedWithoutInterface(t *testing.T) {
	ph := newProtectHarness()
	ph.physical4 = physicalRoute{}
	ph.physical6 = physicalRoute{}
	for _, family := range []int{windows.AF_INET, windows.AF_INET6} {
		sh, err := windows.Socket(family, windows.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		if ph.Protect(int64(sh)) {
			windows.CloseHandle(sh)
			t.Fatalf("family %d: unprotected socket accepted", family)
		}
		windows.CloseHandle(sh)
	}
}

// protectHarness uses the native family probe but records setsockopt so the
// test host's interfaces and routing table are never touched.
type protectHarness struct {
	*networkState
	rmu     sync.Mutex
	options []string
}

func newProtectHarness() *protectHarness {
	ops := nativeWindowsNetworkOps
	ph := &protectHarness{networkState: &networkState{
		cache:     map[string]string{},
		ops:       &ops,
		physical4: physicalRoute{4, 15, netip.MustParseAddr("192.168.88.1")},
		physical6: physicalRoute{6, 22, netip.MustParseAddr("fe80::1")},
	}}
	ops.setsockopt = func(_ windows.Handle, level, option, value int) error {
		ph.rmu.Lock()
		ph.options = append(ph.options, fmt.Sprintf("%d:%d:%d", level, option, value))
		ph.rmu.Unlock()
		return nil
	}
	return ph
}

func (ph *protectHarness) take() []string {
	ph.rmu.Lock()
	defer ph.rmu.Unlock()
	values := ph.options
	ph.options = nil
	return values
}

func forwardRow(prefix, next string, luid, index, metric uint32) winipcfg.MibIPforwardRow2 {
	row := winipcfg.MibIPforwardRow2{InterfaceLUID: winipcfg.LUID(luid), InterfaceIndex: index, Metric: metric}
	_ = row.DestinationPrefix.SetPrefix(netip.MustParsePrefix(prefix))
	_ = row.NextHop.SetAddr(netip.MustParseAddr(next))
	return row
}

