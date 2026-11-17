# Cascade backend / complete trusted payload — 2026-11-05

## Scope / ownership

- Worktree: `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\agent-cascade-20261105`
- Branch: `agent/cascade-backend-20261105`
- Base: `d48c921bf85b4145d86be96467a6112ab4ce4c6d`
- Changes confined to cascade deploy sources, new deterministic packaging/test
  tools, two reserved generated app assets, and this scoped report/evidence.
- Parent app Dart, app tests, l10n, pubspec, parent worktree and other workers
  were not edited. No publishing, releases, main merge, system/package installs,
  production VPS operations or credential access occurred.

## Implementation

- [Renderer](../../deploy/cascade/cascade-config.py): Python stdlib strict IP
  literal/key/network validation before writes/runtime effects; atomic owned temp
  writes; canonical host endpoint rendering; hashed peer filenames (base64 `/`
  cannot become a path); optional fingerprint and symmetric PSK derivation.
- [Installer](../../deploy/cascade/cascade-install.sh): explicit exit family,
  default IPv6 compatibility, inferred bridge host family, split default/all mode,
  persistent state, IPv6-enabled isolated container network, two-way registration
  for laboratory both mode, explicit manual registration for separate servers.
- Real NAT44 for an exit with an IPv4 source/egress route, including a dual-stack
  exit reached over IPv6 transport. NAT66 and device/tunnel IPv6 reverse AllowedIPs
  preserved. No fake NAT46. IPv6-only exit explicitly reports unsupported IPv4,
  drops IPv4 ingress and rejects exit/both all-IPv4 requests before writes.
- All mode marks all wg1 IPv4, keeps transport on the underlay, and drops wg1
  direct fallback. Split retains whitelist-selective forwarding/direct NAT44.
- [Bootstrap](../../deploy/cascade/terminal-install.sh): explicit HTTPS URL and
  nonzero archive SHA, HTTPS-only redirects, bounded compressed/decompressed data,
  strict regular-file dependency allowlist, per-file SHA manifest verification
  before any payload execution, argv arrays, explicit persistent data-dir, inode/
  owner-checked private temporary cleanup. No mutable-main default/unpinned bypass.
- [Packaging tool](../../tools/cascade_payload.py): deterministic gzip/tar metadata,
  exact LF deploy bytes, internal per-file manifest and external release JSON.
- [Healthcheck](../../deploy/cascade/cascade-healthcheck.sh): family-correct
  transport route/egress probes, actual peer/handshake checks, infrastructure-only
  result scope. No shell-interpolated external address/URL commands.
- Removed fictitious web service/published web port claims. Legacy --web-port is
  metadata only. Kernel WireGuard requirement and missing TUN-only userspace
  fallback are explicit; no unpinned wireguard-go binary was added.
- [Operator instructions / integration boundary](../../deploy/cascade/README.md).

## Deterministic payload handoff

- [Archive](../../app/assets/xio-cascade.tar.gz), **26,686 bytes**.
- SHA256: `6ca4b316517e25ddbcb105173c96bcaa712a99ee4fcc054824a3200504f52171`
- [Release manifest](../../app/assets/xio-cascade-release.json): 18 dependency
  hashes, archive SHA/size, source-tree SHA (no self-referential commit hash).
- Source-tree SHA256:
  `6fd0df4dee6e97d10d394123baa241af7c541775828454cb13599bead3b6b39d`
- Trusted bootstrap SHA256:
  `e9db1d8ef13ffa781bce69fec2d8c1d95e7aa12a11c0f21c9e906563c5f43331`
- Windows and Debian `--check` agree byte-for-byte:
  [Windows evidence](payload-check-windows.log),
  [Debian evidence](payload-check-debian.log).

Frontend integration is parent-owned: add the reserved assets to pubspec, pin an
immutable URL and archive SHA, and trust/pin the bootstrap itself before executing
it. Do not fetch mutable-main bootstrap code and treat a later archive check as
protecting that earlier execution. Prefer app-bundled bootstrap or equivalent
trusted inline verifier. Pass actual exit pubkey, --routing all for intended full
IPv4 forwarding, and explicit persistent --data-dir. Transport family is NOT exit
egress capability; validate capability/egress separately. Fingerprints use
canonicalized host literal, unchanged `xio-cascade-exit-v1|host|port|pubkey` domain.

## Tests and exit codes

Debian artifacts are isolated under `/srv/archives/cascade-backend-20261105`, not
its nearly-full root filesystem. Parent Flutter snapshot was not accessed.

### Mock/config/bootstrap suite — PASS, exit 0

[Test source](../../tools/test_cascade_payload.py),
[complete log](mock-tests.log): **16 tests passed**, 11.448 seconds. Commands:

```bash
cd /srv/archives/cascade-backend-20261105
unshare --mount --net --fork env TMPDIR=/srv/archives/cascade-backend-20261105 \
  python3 tools/test_cascade_payload.py
python3 tools/cascade_payload.py --check
```

Coverage: both literal families/endpoints, malformed/zone/URL/CIDR/injected host
rejection before effects; NAT44/dual-stack versus explicit IPv6-only unsupported
IPv4; all/split rendering; IPv6 reverse registration; two-way both-mode keys;
PSK/data paths with spaces; safe base64 peer filenames; all current Bash scripts
with `bash -n`; invalid options/ports/root-resolving data-dir; fingerprint mismatch;
missing/wrong/tampered/duplicate/symlink/oversize archive dependencies fail before
execution; unpinned/HTTP/forwarded state override rejected; HTTPS redirect flags;
persistent helpers survive cleanup; caller-owned temp files and replaced-temp
symlink target remain untouched; healthcheck family and evidence scope.

Network/runtime/key/download tools are **mocks** in this suite. It proves config
and bootstrap behavior, NOT external egress or Docker build success.

### Actual kernel/network namespace packet proof — PASS, exit 0

[Proof source](../../tools/cascade_netns_proof.py),
[full ping log](kernel-proof.log), [structured results](kernel-proof.json):

```bash
unshare --mount --net --fork python3 tools/cascade_netns_proof.py
```

The proof refuses host namespaces/unexpected interfaces, makes mount propagation
private and mounts private tmpfs on /run before any named netns mountpoint exists.
It creates only client/bridge/exit/synthetic-world namespaces and veth links inside
that private scope. Generated configs are applied with actual kernel WireGuard
and the actual generated nft/routing scripts, no docker/runtime/network mocks.

For **each** IPv4 and IPv6 bridge→exit underlay:

- Real kernel WireGuard two-way handshake.
- Client→bridge wg1→bridge wg0→exit wg0→world **IPv4 NAT44: 3/3 pings**.
- Same chain **IPv6 NAT66: 3/3 pings**.
- World has no client subnet return route; return success requires exit NAT.
- Deleting bridge wg0 blocks client IPv4 despite an available direct underlay
  fallback route: all-mode direct leakage test passes.
- Ephemeral keys/configs removed with the owned temporary proof directory.

[Host-network invariance](host-network-invariance.log): IPv4/IPv6 routes, stateless
nft ruleset and named netns catalog digest are identical before/after:
`c5fb2537d6410992b993245295b29be64e6fa67fe6ecd9224e5a268238b27e7e`.
Both proof and invariance commands exited **0**. No host services were invoked.

The first kernel attempt exposed a malformed IPv6 route-probe destination;
corrected to `2606:4700:4700::1111`, strengthened mock literal validation, and
reran both complete proofs successfully. Final evidence is from the corrected
source, not the failed attempt.

## Gaps / explicitly NOT accepted

1. **Native XIO RIVET/AWG profiles are NOT attached to container wg1.** This is a
   separately provisioned standalone WireGuard ingress, not invisible native
   profile integration. No app/VPS end-to-end acceptance is claimed.
2. Across physical servers, operator/frontend still must move exit pubkey to
   bridge, move bridge pubkey back to exit, reload exit, register device pubkeys
   on bridge, and provision a separate compatible client. Both mode only handles
   same-host lab registration; no remote SSH peering orchestration is included.
3. **No real Internet, production VPS, actual Docker image build/container NAT,
   native app, Android/iOS/desktop full-tunnel, leak/DNS/MTU/reconnect test.** The
   packet proof is genuine networking, but only synthetic private namespaces.
4. IPv6-only egress cannot deliver IPv4 without separately proven translation/
   IPv4 exit. IPv6 ULA Docker allocation alone does not prove external IPv6.
5. Kernel WireGuard is required; TUN-only/no-kernel-WG VPS lacks wireguard-go
   fallback and is unsupported, rather than silently promised compatible.
6. Archive pins deploy scripts; Docker Debian tag/apt packages are not immutable
   image supply-chain pins. No automatic host package install is performed.
7. Legacy arbitrary CIDR overrides/automatic host whitelist timers are outside
   the narrowed installer interface. Fixed documented networks and explicit
   manual split whitelist updates are supported. Included legacy native helpers
   are not automatically executed and not validated as native ingress integration.
8. No payload URL/release was published; parent must decide immutable hosting and
   frontend trust bootstrap. No GitHub publishing/release mutation/main merge.

## Native ingress extension points (future work, NOT implemented)

Parent's independent trace identifies real host L3 ingress: RIVET `xiorivet`
(`10.79.0.0/24`, `fd79:1::/64`) and AWG `xioawg0` (`10.78.0.0/24`,
`fd78:1::/64`). Preserve those existing anti-DPI profiles; do not replace them
with raw container wg1 or mark all root-UID traffic.

A future explicit host-native mode needs separately reviewed options/contracts:

- Opt-in `--network-mode host-native` (NOT currently accepted) and an unambiguous
  dedicated uplink interface/name, rather than silently using container wg0.
- Repeatable ingress-interface/source-prefix mapping (e.g. xiorivet plus its
  IPv4/IPv6 subnets, xioawg0 plus its subnets); nft marks only forwarded packets
  from those classified native ingresses. Management/local SSH and tunnel UDP
  remain on the original underlay route; no broad OUTPUT/root-UID marks.
- Exit peer reverse AllowedIPs and routes expanded to actual preserved native
  client prefixes **and** the cascade hop addresses. Current default reverse
  AllowedIPs cover only the standalone 10.201/10.202/fd42 fixture networks.
- Explicit handling of pre-existing native NAT: if the native base rules SNAT
  clients before cascade egress, exit sees the tunnel hop, not the original
  prefix. Rule priority/NAT exemptions and both peer AllowedIPs and exit NAT
  must match the observed post-NAT source. Do not guess or layer incompatible
  SNAT rules; obtain parent worker's exact existing rule/service evidence first.
- Persistent owned route/firewall lifecycle, conflicts/rollback and tunnel-down
  fail-closed behavior scoped to native forwarded traffic, with no management
  outage. Native prefix/mark/table collisions require explicit validation.
- Real native client device→RIVET/AWG→foreign exit acceptance, IPv4/IPv6 source
  capture, external egress IP, DNS/leak, disconnect/reconnect and rollback proof.

These are design extension points, not flags or behavior delivered by this
bounded standalone installer. No already-tested runtime source was expanded.

Local commit SHA is supplied in the agent handoff, not embedded here (avoids
self-referential provenance). All tests above precede that local commit.
