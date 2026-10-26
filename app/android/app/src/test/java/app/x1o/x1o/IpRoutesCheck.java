package app.xio.xio;
import java.util.List;
import java.util.Random;

/** Standalone checks run with javac/java on the same production CIDR class. */
public class IpRoutesCheck {
    static void check(boolean value) { if (!value) throw new AssertionError(); }
    static boolean contains(List<String> routes, String ip) { return !IpRoutes.select(routes, List.of(ip), true).isEmpty(); }
    public static void main(String[] args) {
        var full = List.of("0.0.0.0/0", "::/0");
        check(IpRoutes.normalize(List.of("192.168.1.99/24", "192.168.1.0/24")).equals(List.of("192.168.1.0/24")));
        check(IpRoutes.select(List.of("10.0.0.0/24"), List.of("0.0.0.0/0"), true).equals(List.of("10.0.0.0/24")));
        check(IpRoutes.select(List.of("10.0.0.0/24"), List.of("192.168.0.0/16"), true).isEmpty());
        check(IpRoutes.select(full, full, false).isEmpty());
        var cut = IpRoutes.select(full, List.of("10.0.0.0/8", "2001:db8::/32"), false);
        check(!contains(cut, "10.1.2.3")); check(contains(cut, "9.1.2.3"));
        check(!contains(cut, "2001:db8::1")); check(contains(cut, "2001:db9::1"));
        var host = IpRoutes.select(full, List.of("0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), false);
        check(!contains(host, "0.0.0.0")); check(!contains(host, "255.255.255.255"));
        check(!contains(host, "::")); check(!contains(host, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")); check(contains(host, "::1"));
        for (String invalid : List.of("example.org", "1.2.3.999", "127.1", "1.2.3.4/33", "::/129", "::1%eth0", "192.168.01.1", "::/", "1.2.3.4/-1")) {
            boolean failed = false; try { IpRoutes.normalize(List.of(invalid)); } catch (IllegalArgumentException e) { failed = true; } check(failed);
        }
        Random random = new Random(1);
        for (int i = 0; i < 80; ++i) {
            int prefix = random.nextInt(9) + 24, address = random.nextInt(256);
            String rule = "10.0.0." + address + "/" + prefix;
            var included = IpRoutes.select(List.of("10.0.0.0/24"), List.of(rule), true);
            var excluded = IpRoutes.select(List.of("10.0.0.0/24"), List.of(rule), false);
            for (int j = 0; j < 256; ++j) {
                String ip = "10.0.0." + j;
                check(contains(included, ip) != contains(excluded, ip));
                check(contains(included, ip) == contains(List.of(rule), ip));
            }
        }
        System.out.println("CIDR checks passed: IPv4/IPv6 boundaries, invalid literals, scope intersection, 20480 complement samples");
    }
}
