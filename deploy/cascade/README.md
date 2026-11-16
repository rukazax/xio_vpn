# XIO standalone cascade backend

## Scope and integration boundary

This payload configures **standalone kernel WireGuard containers**, not the native
XIO RIVET/AWG stack. Existing native profiles, devices and keys are **not** peers
on container `wg1`. Do not install a second tunnel expecting a native profile to
change routes. Native ingress attachment/reconciliation requires separate design
and app/VPS acceptance; this payload does not implement it.

No admin.py/web/gateway server is bundled. Legacy `--web-port` is accepted as
metadata only; no TCP web port is published. The legacy native helper scripts in
this directory are included for provenance/completeness, but are NOT executed by
the container installer and are not an automatic integration path.

## Address families and routing

- `cascade-install.sh --role exit|both --exit-family ipv4|ipv6` selects the required
  exit source/transport address family. Default `ipv6` preserves compatibility.
- Bridge accepts only a strict bare literal `--exit-host`: IPv4 `host:port`, IPv6
  `[host]:port`. URLs, zones, CIDRs, brackets, malformed addresses, loopback,
  unspecified, multicast, link-local and mapped IPv6 are rejected before effects.
- `--routing split` is the legacy bridge default. Only IPv4 destinations in
  `xio_whitelist4` use exit; other IPv4 traffic uses direct bridge NAT44.
- `--routing all` sends **all forwarded wg1 IPv4 traffic** through exit. It does
  not change the host's default route or the tunnel's transport route. A forward
  drop prevents direct fallback/leak from wg1. IPv6 clients always use exit in
  both modes. IPv6 tunnel/client AllowedIPs and reverse routes are registered.
- Exit uses real **NAT44** when an IPv4 egress route/source exists. IPv6 transport
  to a dual-stack exit can also NAT44. Route detection is **not Internet proof**.
  Native IPv6 egress uses NAT66; no NAT46, NAT64 or CLAT is invented.
- **IPv6-only exit cannot provide IPv4 Internet.** Renderer warns, reports
  `ipv4_egress: false`, and explicitly drops IPv4 arriving from wg0. Do not select
  it for all-IPv4 operation. Exit/both `--routing all` fails before writes if no
  IPv4 egress route exists. A separately installed bridge cannot infer remote
  capability from its transport address; the operator/frontend must gate that
  choice on exit capability and actual egress tests. All-IPv4 requires an exit
  with proven IPv4 egress.
- Container network is created with `--ipv6` and private ULA subnet
  `fd42:ca5c:ade::/64`. Existing IPv4-only cascade networks fail, not silently
  reused. Docker/Podman and host must provide working IPv6 routing/NAT and DNS.
  ULA allocation alone is NOT evidence of public IPv6 connectivity.

Tunnel addresses: `10.201.0.1/24`, `fd42:200::1/64` (exit), `.2`/`::2`
(bridge). Device network: `10.202.0.0/24`, `fd42:201::/64`; gateway `.1`/`::1`.
MTU is conservatively 1280. Client addresses are registered explicitly.

## Requirements / unsupported hosts

Linux root; Python 3 stdlib; Bash; existing functional Docker/Podman; **kernel
WireGuard**. No packages are installed on the host. Dockerfile installs container
userspace dependencies when the operator builds it. Its Debian tag and apt
packages are not a reproducible/pinned image supply chain; the payload hash pins
scripts, not future OS package bytes. No image was published by this work.

TUN-only VPS without kernel WireGuard is **unsupported**: wireguard-tools does not
supply wireguard-go. The entrypoint fails clearly; no host module/package change
or unpinned fallback binary download is attempted. Containers use isolated
network namespaces and NET_ADMIN, never privileged or host networking.

## Trusted complete-payload bootstrap

`tools/cascade_payload.py` produces deterministic `app/assets/xio-cascade.tar.gz`
and `app/assets/xio-cascade-release.json` from exact LF deploy bytes. The archive
contains every deploy dependency plus an embedded per-file SHA256 manifest; the
release JSON records archive SHA, size, per-file SHA, and source-tree digest.
There is no self-referential commit hash. The frontend must pin an immutable
bundle URL plus the resulting archive SHA; this repository does not publish it.

The bootstrap **itself must be trusted/pinned** (for example bundled in the app).
Do not fetch mutable-main shell code and call that authenticated bootstrapping.

```bash
# Run a separately trusted bootstrap, not curl | bash:
sudo bash terminal-install.sh \
  --bundle-url https://trusted.example/immutable/xio-cascade.tar.gz \
  --sha256 <release-archive-sha256> --data-dir /var/lib/xio-cascade \
  --unattended -- --role bridge --exit-host 203.0.113.7 \
  --exit-pubkey <REAL-exit-public-key> --routing all
```

HTTPS-only including redirects, explicit nonzero hash, bounded archive,
private owned temp directory, strict regular-file member allowlist, all dependency
hashes verified before **any payload execution**. No unpinned bypass. Arguments
are arrays: paths with spaces are preserved. Cleanup only removes its own original
temp inode, never a symlink/replacement. Caller-owned temporary files are untouched.

State defaults to **`/var/lib/xio-cascade`**, never the disposable payload folder.
Bootstrap requires explicit `--data-dir`. Helpers are copied to its persistent
`payload` subdirectory before bootstrap cleanup. Installer options use separated
`--option value` syntax. Unsafe path newlines/colon/comma are rejected. Automatic
host whitelist timers are deliberately not installed by this bounded interface;
run the included whitelist updater manually for split mode, with explicit state
and config paths. Legacy updater's own optional host timer mode is outside this
installer/test scope.

## Two-way peering (manual across two physical servers)

1. On exit, install `--role exit --exit-family ipv4 --data-dir /var/lib/xio-cascade`.
   Record its **public** key/fingerprint from state/output. Exit has no bridge peer
   yet and is NOT ready for end-to-end traffic.
2. On bridge, install `--role bridge --exit-host <exit-literal>` with the REAL exit
   public key, optional `--exit-fingerprint sha256:<hex>`, and `--routing all`.
   Record the bridge's public key. Never substitute the app/native profile key.
3. On exit, register that bridge key and reload the container, preserving its port,
   family, PSK and data path:
   ```bash
   sudo bash /var/lib/xio-cascade/payload/cascade-exit-setup.sh \
     --data-dir /var/lib/xio-cascade/exit --exit-family ipv4 --port 9443 \
     --add-peer <REAL-bridge-public-key>
   sudo docker restart xio-cascade-exit
   ```
   Default reverse AllowedIPs include bridge tunnel IPv4/IPv6 **and both device
   subnets**. Public keys with `/` are stored under hash filenames, never paths.
4. Register a standalone device key on bridge, then reload bridge:
   ```bash
   sudo bash /var/lib/xio-cascade/payload/cascade-bridge-setup.sh \
     --data-dir /var/lib/xio-cascade/bridge --exit-host <exit-literal> \
     --exit-pubkey <REAL-exit-public-key> --routing all \
     --add-client <REAL-device-public-key> --client-ip 10.202.0.10 \
     --client-ip6 fd42:201::10
   sudo docker restart xio-cascade-bridge
   ```
   Configure that separate WireGuard client with its private key, assigned IPv4/
   IPv6, bridge public key, bridge IPv4 endpoint:51820, and desired AllowedIPs.
   Existing native XIO profiles do NOT perform this step automatically.

The same `--token-file` on both sides derives/stores the same PSK without logging
its contents. Omitted token reuses persisted PSK. `--role both` registers generated
keys in both configs for a laboratory single-host setup; it is NOT remote SSH
orchestration and its public endpoint still needs a working reachability path.
`--peer-pubkey` allows explicit bridge registration during exit installation.
Subsequent installer runs need `--recreate` to replace existing containers.

## Validation and limits of evidence

```bash
python3 tools/cascade_payload.py --check
python3 tools/test_cascade_payload.py
# Optional actual kernel proof, ONLY in fresh private mount+network namespaces:
unshare --mount --net --fork python3 tools/cascade_netns_proof.py
# Infrastructure diagnostic, never native-app acceptance:
sudo bash /var/lib/xio-cascade/payload/cascade-healthcheck.sh \
  --data-dir /var/lib/xio-cascade --role both
```

Config/bootstrap tests use isolated temporary files and mocked ip/wg/runtime/curl.
They do not establish real egress. Kernel/netns proof, if run, uses isolated
synthetic peers/addresses; it is not Internet/VPS/app proof. Healthcheck validates
family-correct container transport/peering and exit HTTP egress independently; it
does not equate a running container or a route with native client acceptance.

No production server, host route/firewall/service, GitHub release, publication or
main branch merge is performed by these tests. Real Docker build, dual-stack
container egress, native ingress attachment, two real VPS peers, external exit IP,
DNS, UDP/firewall behavior, restart/reconnect, MTU, Android/iOS/desktop full-tunnel
and leak checks remain separate acceptance work.
