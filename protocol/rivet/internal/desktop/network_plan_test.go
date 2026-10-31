package desktop

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestLinuxDualstackPlanAndUnsupportedFamilyBlackhole(t *testing.T) {
	for _, tc := range []struct {
		addresses []netip.Prefix
		v4, v6    bool
	}{
		{[]netip.Prefix{netip.MustParsePrefix("10.77.0.2/32"), netip.MustParsePrefix("fd77::2/128")}, true, true},
		{[]netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}, true, false},
		{[]netip.Prefix{netip.MustParsePrefix("fd77::2/128")}, false, true},
	} {
		p := Profile{Addresses: tc.addresses, DNS: []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}, MTU: 1280}
		plan := linuxNetworkPlan(p)
		var commands []string
		for _, c := range plan {
			commands = append(commands, strings.Join(c.args, " "))
		}
		joined := strings.Join(commands, "\n")
		if strings.Contains(joined, "-4 addr add fd") || strings.Contains(joined, "-6 addr add 10.") {
			t.Fatal("wrong address family")
		}
		for _, family := range []string{"-4", "-6"} {
			expected := family + " route add default dev " + deviceName + " table " + routeTable
			if family == "-4" && !tc.v4 || family == "-6" && !tc.v6 {
				expected = family + " route add blackhole default table " + routeTable
			}
			if !strings.Contains(joined, expected) {
				t.Fatalf("missing safe route: %s", expected)
			}
			if !strings.Contains(joined, family+" rule add pref 18019 not fwmark 0x580019 lookup "+routeTable) {
				t.Fatal("missing socket-mark bypass policy")
			}
		}
		if strings.Index(joined, "-6 route add") > strings.Index(joined, "-4 rule add") {
			t.Fatal("policy activated before both family routes exist")
		}
		if !strings.Contains(joined, "dns "+deviceName+" 2606:4700:4700::1111") || !strings.Contains(joined, "domain "+deviceName+" ~.") {
			t.Fatal("IPv6 DNS or catch-all DNS domain lost")
		}
	}
}

func TestLinuxInjectedCommandRollbackEveryFailurePoint(t *testing.T) {
	p, _ := ParseProfile("awg", dualstackAWG)
	plan := linuxNetworkPlan(p)
	for failAt := -1; failAt < len(plan); failAt++ {
		var applied []networkCommand
		var forward, rollback []string
		run := func(program string, args ...string) ([]byte, error) {
			forward = append(forward, program+" "+strings.Join(args, " "))
			if failAt >= 0 && len(forward)-1 == failAt {
				return nil, errors.New("injected command failure")
			}
			return nil, nil
		}
		err := applyNetworkPlan(plan, run, &applied)
		if (err != nil) != (failAt >= 0) {
			t.Fatal("failure was swallowed")
		}
		undoNetworkPlan(applied, func(program string, args ...string) ([]byte, error) {
			rollback = append(rollback, program+" "+strings.Join(args, " "))
			return nil, nil
		})
		var expected []string
		for i := len(applied) - 1; i >= 0; i-- {
			if len(applied[i].undo) > 0 {
				expected = append(expected, applied[i].program+" "+strings.Join(applied[i].undo, " "))
			}
		}
		if !reflect.DeepEqual(rollback, expected) {
			t.Fatalf("rollback order %v", rollback)
		}
		if strings.Contains(strings.Join(rollback, "\n"), "flush") {
			t.Fatal("cleanup must not flush unrelated table entries")
		}
		if failAt == len(plan)-2 && !strings.Contains(strings.Join(rollback, "\n"), "revert "+deviceName) {
			t.Fatal("partly failed DNS setup not reverted")
		}
	}
}

func TestOuterFamilyFilter(t *testing.T) {
	raw := "203.0.113.42,2001:db8::42"
	for _, tc := range []struct {
		v4, v6 bool
		want   string
	}{{true, true, raw}, {true, false, "203.0.113.42"}, {false, true, "2001:db8::42"}, {false, false, ""}} {
		if got := reachableAddresses(raw, tc.v4, tc.v6); got != tc.want {
			t.Fatalf("family filter: %q != %q", got, tc.want)
		}
	}
}

func TestLinuxCleanupVerifiesBothFamiliesAndPreservesForeignRows(t *testing.T) {
	for _, tc := range []struct {
		name, kind, body string
		fail             bool
	}{
		{"empty", "", "[]", false},
		{"foreign-rule", "rule", "[{\"priority\":18019,\"fwmark\":\"0x123456\",\"table\":123}]", false},
		{"foreign-route", "route", "[{\"dst\":\"default\",\"dev\":\"eth0\",\"table\":123}]", false},
		{"owned-rule", "rule", "[{\"priority\":18019,\"fwmark\":\"0x580019\",\"table\":28691}]", true},
		{"owned-route", "route", "[{\"dst\":\"default\",\"dev\":\"xio019\",\"table\":28691}]", true},
		{"invalid-query", "rule", "invalid", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var commands []string
			err := cleanupLinuxOwned(func(program string, args ...string) ([]byte, error) {
				command := strings.Join(args, " ")
				commands = append(commands, command)
				if len(args) > 2 && args[1] == "-j" {
					if args[0] == "-6" && args[2] == tc.kind {
						return []byte(tc.body), nil
					}
					return []byte("[]"), nil
				}
				// Deletion of absent rows may report an error; verification is authoritative.
				return nil, errors.New("already absent")
			})
			if (err != nil) != tc.fail {
				t.Fatalf("cleanup proof: %v", err)
			}
			joined := strings.Join(commands, "\n")
			for _, required := range []string{"-6 route del default dev xio019 table 28691", "-6 route del blackhole default table 28691", "-4 rule del pref 18019 not fwmark 0x580019 lookup 28691", "revert xio019"} {
				if !strings.Contains(joined, required) {
					t.Fatalf("incomplete owned cleanup: %s", required)
				}
			}
			if strings.Contains(joined, "flush") || strings.Contains(joined, "del default dev eth0") {
				t.Fatal("unowned state changed")
			}
		})
	}
}
