package app.xio.xio;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * One canonicalizer for the split-routing values the app already persists.
 *
 * <p>The durable policy plan embeds a typed routing snapshot, and that snapshot
 * must be byte-stable: {@code SplitRouting} uses the same constants and the same
 * literal-only {@link IpRoutes} algebra here, so the plan copied by Dart and the
 * snapshot recomputed by native admission cannot disagree about "the same"
 * routing policy. Nothing here resolves a hostname, expands a profile scope or
 * tolerates a protocol alias.
 */
public final class RoutingCanon {
    public static final List<String> MODES = List.of("all", "include", "exclude", "ipInclude", "ipExclude");
    public static final List<String> APP_MODES = List.of("include", "exclude");
    public static final int MAX_PACKAGES = 1024;
    public static final int MAX_DOMAINS = 128;
    public static final int MAX_NETWORKS = 128;

    private static final String PACKAGE = "[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*";
    private static final String DOMAIN = "(\\*\\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+([a-z]{2,63}|xn--[a-z0-9-]{2,59})";

    public static boolean validPackage(String name) { return name.matches(PACKAGE); }

    /** Lowercase canonical domain, or {@code null} when the value is not a domain rule. */
    public static String normalizeDomain(String raw) {
        String text = raw.trim().toLowerCase(Locale.ROOT);
        if (text.isEmpty() || text.length() > 253) return null;
        return text.matches(DOMAIN) ? text : null;
    }

    /** Exact canonical form of one routing policy. */
    public static final class Snapshot {
        public final String mode;
        public final List<String> packages;
        public final List<String> networks;
        public final List<String> domains;

        private Snapshot(String mode, List<String> packages, List<String> networks, List<String> domains) {
            this.mode = mode;
            this.packages = List.copyOf(packages);
            this.networks = List.copyOf(networks);
            this.domains = List.copyOf(domains);
        }

        public boolean isIpMode() { return mode.startsWith("ip"); }

        /** Literal networks only: resolved domain addresses are a separate DNS overlay. */
        public List<String> routes() { return networks; }

        @Override public boolean equals(Object other) {
            if (!(other instanceof Snapshot snapshot)) return false;
            return mode.equals(snapshot.mode) && packages.equals(snapshot.packages)
                && networks.equals(snapshot.networks) && domains.equals(snapshot.domains);
        }

        @Override public int hashCode() { return java.util.Objects.hash(mode, packages, networks, domains); }

        public String canonicalJson() {
            java.util.Map<String, Object> value = new java.util.LinkedHashMap<>();
            value.put("mode", mode);
            value.put("packages", packages);
            value.put("networks", networks);
            value.put("domains", domains);
            return StrictJson.canonical(value);
        }
    }

    /**
     * Canonicalizes a routing policy exactly as the editor/plan writer must have
     * stored it. App modes carry applications only, IP modes carry addresses and
     * domains only, and an empty selection is invalid for "include"/"ip*".
     */
    public static Snapshot canonical(String mode, List<String> packages, List<String> networks, List<String> domains) {
        if (!MODES.contains(mode)) throw new StrictJson.Invalid("routing.mode: unsupported");
        if (packages.size() > MAX_PACKAGES) throw new StrictJson.Invalid("routing.packages: too many");
        List<String> cleanPackages = new ArrayList<>();
        for (String name : packages) {
            if (!validPackage(name)) throw new StrictJson.Invalid("routing.packages: invalid package " + name);
            cleanPackages.add(name);
        }
        cleanPackages = new ArrayList<>(new LinkedHashSet<>(cleanPackages));
        java.util.Collections.sort(cleanPackages);
        if ("include".equals(mode) && cleanPackages.isEmpty())
            throw new StrictJson.Invalid("routing.packages: include needs at least one app");
        if (domains.size() > MAX_DOMAINS) throw new StrictJson.Invalid("routing.domains: too many");
        List<String> cleanDomains = new ArrayList<>();
        for (String domain : domains) {
            String normalized = normalizeDomain(domain);
            if (normalized == null) throw new StrictJson.Invalid("routing.domains: invalid domain " + domain);
            cleanDomains.add(normalized);
        }
        cleanDomains = new ArrayList<>(new LinkedHashSet<>(cleanDomains));
        java.util.Collections.sort(cleanDomains);
        List<String> cleanNetworks;
        try {
            if (networks.size() > MAX_NETWORKS) throw new IllegalArgumentException("Too many subnets");
            cleanNetworks = IpRoutes.normalize(networks);
        } catch (IllegalArgumentException failure) {
            throw new StrictJson.Invalid("routing.networks: " + failure.getMessage());
        }
        // WIRE-V2: networks and domains are deduped and sorted ascending by byte
        // value. They are ASCII, so this order matches Dart/Go canonicalization.
        cleanNetworks = new ArrayList<>(new LinkedHashSet<>(cleanNetworks));
        java.util.Collections.sort(cleanNetworks);
        boolean ip = mode.startsWith("ip");
        List<String> packagesOut = MODES.contains(mode) && APP_MODES.contains(mode) ? cleanPackages : List.of();
        List<String> networksOut = ip ? cleanNetworks : List.of();
        List<String> domainsOut = ip ? cleanDomains : List.of();
        if (ip && networksOut.isEmpty() && domainsOut.isEmpty())
            throw new StrictJson.Invalid("routing: ip mode needs an address or domain");
        return new Snapshot(mode, packagesOut, networksOut, domainsOut);
    }

    /**
     * Parses the persisted {@code split-routing.json} document into its canonical
     * snapshot. The resolved-address overlay, revision and lease are deliberately
     * excluded: they are runtime DNS provenance, not policy.
     */
    public static Snapshot fromPersistedJson(String text) {
        Object parsed = StrictJson.parse(text);
        java.util.Map<String, Object> json = StrictJson.asObject(parsed, "routing");
        long schema = StrictJson.integer(json.get("schema"), "routing.schema");
        if (schema != 1) throw new StrictJson.Invalid("routing.schema: unsupported");
        List<Object> packages = StrictJson.array(json.get("packages"), "routing.packages");
        List<Object> networks = json.containsKey("networks") ? StrictJson.array(json.get("networks"), "routing.networks") : List.of();
        List<Object> domains = json.containsKey("domains") ? StrictJson.array(json.get("domains"), "routing.domains") : List.of();
        List<String> packageValues = new ArrayList<>();
        for (Object value : packages) packageValues.add(StrictJson.string(value, "routing.packages"));
        List<String> networkValues = new ArrayList<>();
        for (Object value : networks) networkValues.add(StrictJson.string(value, "routing.networks"));
        List<String> domainValues = new ArrayList<>();
        for (Object value : domains) domainValues.add(StrictJson.string(value, "routing.domains"));
        return canonical(StrictJson.string(json.get("mode"), "routing.mode"), packageValues, networkValues, domainValues);
    }

    /** The absent routing document is the app's own default: everything through the VPN. */
    public static Snapshot absent() { return new Snapshot("all", List.of(), List.of(), List.of()); }

    public static Set<String> modes() { return new LinkedHashSet<>(MODES); }

    private RoutingCanon() { }
}
