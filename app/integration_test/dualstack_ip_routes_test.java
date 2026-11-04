package app.xio.xio;

import java.net.InetAddress;
import java.util.List;

/** Host-only production CIDR checks: no Android, VPN, DNS or network changes. */
public final class dualstack_ip_routes_test {
    private static int checks;
    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
    private static boolean covers(List<String> routes, String literal) throws Exception {
        byte[] address = InetAddress.getByName(literal).getAddress();
        for (String route : routes) {
            String[] fields = route.split("/");
            byte[] network = InetAddress.getByName(fields[0]).getAddress();
            if (network.length != address.length) continue;
            int prefix = Integer.parseInt(fields[1]);
            boolean matches = true;
            for (int bit = 0; bit < prefix; bit++) {
                int mask = 1 << (7 - bit % 8);
                if ((address[bit / 8] & mask) != (network[bit / 8] & mask)) matches = false;
            }
            if (matches) return true;
        }
        return false;
    }
    public static void main(String[] args) throws Exception {
        List<String> normalized = IpRoutes.normalize(List.of("192.0.2.129/24", "192.0.2.0/24", "2001:db8::abcd/64"));
        check(normalized.size() == 2, "deduplicate normalized IPv4 CIDRs");
        check(normalized.contains("192.0.2.0/24"), "IPv4 literal parsing");
        check(covers(normalized, "2001:db8::1"), "IPv6 literal parsing");
        check(IpRoutes.normalize(List.of("203.0.113.4")).equals(List.of("203.0.113.4/32")), "IPv4 host mask");
        check(IpRoutes.normalize(List.of("2001:db8::1")).get(0).endsWith("/128"), "IPv6 host mask");
        List<String> defaults = List.of("0.0.0.0/0", "::/0");
        List<String> included = IpRoutes.select(defaults, List.of("192.0.2.0/24", "2001:db8::/32"), true);
        check(covers(included, "192.0.2.99") && covers(included, "2001:db8::1"), "dualstack include");
        check(!covers(included, "198.51.100.1") && !covers(included, "2001:db9::1"), "include must not leak scope");
        List<String> excluded = IpRoutes.select(defaults, List.of("192.0.2.0/24", "2001:db8::/32"), false);
        check(!covers(excluded, "192.0.2.0") && !covers(excluded, "192.0.2.255"), "excluded IPv4 boundaries");
        check(!covers(excluded, "2001:db8::1"), "excluded IPv6");
        check(covers(excluded, "192.0.1.255") && covers(excluded, "192.0.3.0"), "IPv4 complement");
        check(covers(excluded, "2001:db7::1") && covers(excluded, "2001:db9::1"), "IPv6 complement");
        List<String> v4Profile = List.of("10.77.0.0/24");
        check(IpRoutes.select(v4Profile, List.of("::/0"), true).isEmpty(), "never add IPv6 to IPv4-only profile");
        check(IpRoutes.select(List.of("fd79:1::/64"), List.of("0.0.0.0/0"), true).isEmpty(), "never add IPv4 to IPv6-only profile");
        check(!covers(IpRoutes.select(v4Profile, defaults, true), "10.78.0.1"), "never widen profile routes");
        check(covers(IpRoutes.select(v4Profile, List.of("::/0"), false), "10.77.0.1"), "cross-family exclusion retains profile");
        check(IpRoutes.select(defaults, defaults, false).isEmpty(), "excluding both defaults leaves no routes");
        for (String invalid : List.of("example.com", "192.0.2.256", "192.0.2", "01.2.3.4", "1.2.3.4/33", "::/129", "fe80::1%wlan0", "1.2.3.4/-1", "1.2.3.4/0/0")) {
            boolean rejected = false;
            try { IpRoutes.normalize(List.of(invalid)); }
            catch (IllegalArgumentException expected) { rejected = true; }
            check(rejected, "reject non-literal/invalid route: " + invalid);
        }
        System.out.println("XIO_DUALSTACK_CIDR_PASS checks=" + checks + " scope=production-CIDR-algebra-only;device-VPN-not-tested");
    }
}
