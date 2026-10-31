package desktop

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"xio.local/rivet/internal/physical"
)

type commandRunner func(string, ...string) ([]byte, error)

func runNetworkCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func (p Profile) hasFamily(ipv6 bool) bool {
	for _, a := range p.Addresses {
		if a.Addr().Is6() == ipv6 {
			return true
		}
	}
	return false
}

func reachableAddresses(raw string, ipv4, ipv6 bool) string {
	values, err := physical.Addresses(raw)
	if err != nil {
		return ""
	}
	var result []string
	for _, value := range values {
		a := netip.MustParseAddr(value)
		if a.Is4() && ipv4 || a.Is6() && ipv6 {
			result = append(result, value)
		}
	}
	return strings.Join(result, ",")
}

// resolvectl prints per-link servers without a zone. Preserve Link N across
// continuation lines; an unscoped link-local resolver is never usable safely.
func physicalDNSServers(output string) []string {
	var servers []string
	seen := map[string]bool{}
	scope := ""
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Global:" {
			scope = ""
		}
		if fields[0] == "Link" {
			scope = ""
			if len(fields) > 1 {
				if index, err := strconv.Atoi(fields[1]); err == nil && index > 0 {
					scope = fields[1]
				}
			}
		}
		for _, word := range fields {
			a, err := netip.ParseAddr(word)
			if err != nil || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
				continue
			}
			a = a.Unmap()
			if a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "" {
				if scope == "" {
					continue
				}
				a = a.WithZone(scope)
			}
			server := net.JoinHostPort(a.String(), "53")
			if !seen[server] {
				servers = append(servers, server)
				seen[server] = true
			}
		}
	}
	return servers
}

// The resolver contract is a bounded comma-separated list, shared with the
// mobile/physical dialers. Query A AND AAAA over protected physical DNS sockets.
type physicalLookup func(context.Context, string, string, string) ([]netip.Addr, error)

// socketProtect pins a socket to a physical interface. The second argument is
// the numeric dial target, so the platform can select that endpoint's route
// instead of the family's default route.
type socketProtect func(fd int64, address string) bool

// familyProtect adapts a family-only protector to the endpoint-aware contract.
func familyProtect(protect func(int64) bool) socketProtect {
	return func(fd int64, _ string) bool { return protect(fd) }
}

func protectedLookup(protect socketProtect) physicalLookup {
	return func(ctx context.Context, network, host, server string) ([]netip.Addr, error) {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, transport, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second, Control: func(_, _ string, c syscall.RawConn) error {
				ok := false
				if err := c.Control(func(fd uintptr) { ok = protect(int64(fd), server) }); err != nil {
					return err
				}
				if !ok {
					return errors.New("physical DNS socket could not be protected")
				}
				return nil
			}}
			return d.DialContext(ctx, transport, server)
		}}
		return resolver.LookupNetIP(ctx, network, host)
	}
}

func resolvePhysical(host string, servers []string, protect socketProtect) string {
	return resolvePhysicalWith(host, servers, protectedLookup(protect))
}

func resolvePhysicalWith(host string, servers []string, lookup physicalLookup) string {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	for _, server := range servers {
		query, done := context.WithTimeout(ctx, 1500*time.Millisecond)
		ips, err := lookup(query, "ip", host, server)
		done()
		if err == nil && len(ips) > 0 {
			// Bound each family first, then interleave BEFORE the overall cap.
			// A DNS answer with 16 A records followed by one AAAA (or the
			// reverse) must not erase the only alternate-family candidate.
			primary, secondary := []string{}, []string{}
			first4 := ips[0].Unmap().Is4()
			seen := map[netip.Addr]bool{}
			for _, a := range ips {
				a = a.Unmap()
				if seen[a] {
					continue
				}
				if a.Is4() == first4 {
					if len(primary) < 16 {
						primary = append(primary, a.String())
						seen[a] = true
					}
				} else {
					if len(secondary) < 16 {
						secondary = append(secondary, a.String())
						seen[a] = true
					}
				}
			}
			values := make([]string, 0, 16)
			for i := 0; len(values) < 16 && (i < len(primary) || i < len(secondary)); i++ {
				if i < len(primary) {
					values = append(values, primary[i])
				}
				if i < len(secondary) && len(values) < 16 {
					values = append(values, secondary[i])
				}
			}
			if addresses, err := physical.Addresses(strings.Join(values, ",")); err == nil {
				return strings.Join(addresses, ",")
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return ""
}

const routeTable = "28691"
const mark = 0x580019

type networkCommand struct {
	program string
	args    []string
	undo    []string
}

func applyNetworkPlan(plan []networkCommand, run commandRunner, applied *[]networkCommand) error {
	for _, command := range plan {
		// Also undo a partially successful failing command (notably DNS).
		*applied = append(*applied, command)
		if _, err := run(command.program, command.args...); err != nil {
			return err
		}
	}
	return nil
}
func undoNetworkPlan(applied []networkCommand, run commandRunner) {
	for i := len(applied) - 1; i >= 0; i-- {
		c := applied[i]
		if len(c.undo) > 0 {
			_, _ = run(c.program, c.undo...)
		}
	}
}

// Kept platform independent so route/DNS ordering and rollback can be tested
// without a TUN, privileges, or executing ip/resolvectl on the test host.
func linuxNetworkPlan(p Profile) []networkCommand {
	var plan []networkCommand
	add := func(program string, args, undo []string) {
		plan = append(plan, networkCommand{program, args, undo})
	}
	for _, a := range p.Addresses {
		family := "-4"
		if a.Addr().Is6() {
			family = "-6"
		}
		add("/usr/sbin/ip", []string{family, "addr", "add", a.String(), "dev", deviceName}, []string{family, "addr", "del", a.String(), "dev", deviceName})
	}
	add("/usr/sbin/ip", []string{"link", "set", "dev", deviceName, "mtu", strconv.Itoa(p.MTU), "up"}, nil)
	for _, family := range []string{"-4", "-6"} {
		route := []string{"default", "dev", deviceName, "table", routeTable}
		if !p.hasFamily(family == "-6") {
			// Never let an unsupported inner family fall through to the main table.
			route = []string{"blackhole", "default", "table", routeTable}
		}
		add("/usr/sbin/ip", append([]string{family, "route", "add"}, route...), append([]string{family, "route", "del"}, route...))
	}
	for _, family := range []string{"-4", "-6"} {
		for _, rule := range [][]string{
			{"pref", "18018", "fwmark", "0x80000/0xff0000", "lookup", "main"},
			{"pref", "18019", "not", "fwmark", "0x580019", "lookup", routeTable},
		} {
			add("/usr/sbin/ip", append([]string{family, "rule", "add"}, rule...), append([]string{family, "rule", "del"}, rule...))
		}
	}
	args := []string{"dns", deviceName}
	for _, a := range p.DNS {
		args = append(args, a.String())
	}
	add("/usr/bin/resolvectl", args, []string{"revert", deviceName})
	add("/usr/bin/resolvectl", []string{"domain", deviceName, "~."}, nil)
	return plan
}
