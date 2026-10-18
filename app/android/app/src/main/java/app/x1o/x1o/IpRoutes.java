package app.x1o.x1o;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/** Literal-only CIDR algebra. Never resolves a hostname or expands profile scope. */
public final class IpRoutes {
    private static final int LIMIT = 4096;
    private record Block(BigInteger start, int prefix, int bits) {
        BigInteger end() { return start.add(BigInteger.ONE.shiftLeft(bits - prefix)).subtract(BigInteger.ONE); }
        boolean overlaps(Block b) { return bits == b.bits && start.compareTo(b.end()) <= 0 && b.start.compareTo(end()) <= 0; }
        boolean contains(Block b) { return bits == b.bits && start.compareTo(b.start) <= 0 && end().compareTo(b.end()) >= 0; }
        @Override public String toString() {
            byte[] raw = start.toByteArray(), bytes = new byte[bits / 8];
            int size = Math.min(raw.length, bytes.length);
            System.arraycopy(raw, raw.length - size, bytes, bytes.length - size, size);
            try { return InetAddress.getByAddress(bytes).getHostAddress() + "/" + prefix; }
            catch (Exception e) { throw new IllegalArgumentException("Invalid address", e); }
        }
    }
    private static Block parse(String input) {
        try {
            String[] parts = input.trim().split("/", -1);
            if (parts.length > 2) throw new IllegalArgumentException();
            String address = parts[0];
            byte[] bytes;
            if (address.contains(":")) {
                if (!address.matches("[0-9a-fA-F:]+")) throw new IllegalArgumentException();
                bytes = InetAddress.getByName(address).getAddress(); // colon + hex only: no DNS
                if (bytes.length != 16) throw new IllegalArgumentException();
            } else {
                String[] octets = address.split("\\.", -1);
                if (octets.length != 4) throw new IllegalArgumentException();
                bytes = new byte[4];
                for (int i = 0; i < 4; ++i) {
                    if (!octets[i].matches("0|[1-9][0-9]{0,2}")) throw new IllegalArgumentException();
                    int value = Integer.parseInt(octets[i]);
                    if (value > 255) throw new IllegalArgumentException();
                    bytes[i] = (byte)value;
                }
            }
            int bits = bytes.length * 8;
            if (parts.length == 2 && !parts[1].matches("0|[1-9][0-9]{0,2}")) throw new IllegalArgumentException();
            int prefix = parts.length == 2 ? Integer.parseInt(parts[1]) : bits;
            if (prefix > bits) throw new IllegalArgumentException();
            BigInteger value = new BigInteger(1, bytes);
            return new Block(value.shiftRight(bits - prefix).shiftLeft(bits - prefix), prefix, bits);
        } catch (Exception e) { throw new IllegalArgumentException("Use literal IPv4/IPv6 addresses or CIDR subnets", e); }
    }
    public static List<String> normalize(List<String> rules) {
        if (rules.size() > 128) throw new IllegalArgumentException("Too many subnets");
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String rule : rules) result.add(parse(rule).toString());
        return new ArrayList<>(result);
    }
    private static void subtract(Block base, Block cut, List<Block> result) {
        if (result.size() >= LIMIT) throw new IllegalArgumentException("Too many resulting routes");
        if (!base.overlaps(cut)) { result.add(base); return; }
        if (cut.contains(base)) return;
        int next = base.prefix + 1;
        subtract(new Block(base.start, next, base.bits), cut, result);
        subtract(new Block(base.start.add(BigInteger.ONE.shiftLeft(base.bits - next)), next, base.bits), cut, result);
    }
    public static List<String> select(List<String> profile, List<String> rules, boolean include) {
        List<Block> bases = new ArrayList<>(), filters = new ArrayList<>();
        for (String value : profile) bases.add(parse(value));
        for (String value : normalize(rules)) filters.add(parse(value));
        List<Block> result = new ArrayList<>();
        if (include) {
            for (Block base : bases) for (Block filter : filters) if (base.overlaps(filter))
                result.add(base.prefix >= filter.prefix ? base : filter);
        } else {
            result.addAll(bases);
            for (Block filter : filters) {
                List<Block> next = new ArrayList<>();
                for (Block base : result) subtract(base, filter, next);
                result = next;
            }
        }
        LinkedHashSet<String> output = new LinkedHashSet<>();
        for (Block block : result) output.add(block.toString());
        if (output.size() > LIMIT) throw new IllegalArgumentException("Too many resulting routes");
        return new ArrayList<>(output);
    }
    private IpRoutes() { }
}
