# Native host cascade connector — scoped implementation and packet proof

## Scope / branch

- Branch: `agent/native-connector-20261105`.
- Base: `c8c36265740ccc173b83b912cb95cec7a3e43347` (finished standalone milestone, preserved).
- New implementation: [native connector](<server/managed/cascade_native.py>).
- Tests: [pure/mocked suite](<server/managed/test_cascade_native.py>) and [private packet proof](<tools/prove_cascade_native.py>).
- No edits to managed admin/dualstack/RIVET setup, Flutter/Dart, existing transports, server packager or signed assets. Their integration is a separate worker's responsibility.
- No publication, production VPS changes, package installs, downloaded implementations, host service changes or host networking mutations were performed.

## Authoritative API for hook/integration worker

Installed module location is `/usr/local/lib/xio-managed/cascade_native.py`; opt-in root is `/etc/xio-managed/cascade-native`.

```python
validate_config(request)                       # pure; secrets stripped from result
plan(config)                                  # pure firewall/policy specifications
configure(request, root=DEFAULT_ROOT)          # explicit owner opt-in; root mutation
inspect(root=DEFAULT_ROOT)                     # bounded local, no Internet probes
remove(root=DEFAULT_ROOT, confirm_direct=True) # explicit restoration of native direct policy
verify(root=DEFAULT_ROOT, targets=None)        # EXPLICIT active source-bound inner-family probes

desired_native_families(native_map=None, *, root=DEFAULT_ROOT)
reconcile_native(native_map=None, reason='native-network-reapply', *, root=DEFAULT_ROOT)
native_capabilities(native_map=None, *, root=DEFAULT_ROOT)
```

Canonical native map (the defaults):

```json
{
  "awg": {"interface":"xioawg0","ipv4":"10.78.0.0/24","ipv6":"fd78:1::/64"},
  "rivet": {"interface":"xiorivet","ipv4":"10.79.0.0/24","ipv6":"fd79:1::/64"}
}
```

- No enabled owned receipt: reconcile does nothing; desired/capabilities return `None`; no directories or network effects are created by observation.
- **Exit peer role has no native bridge routing scope:** desired/capabilities return `None`, preserving that full XIO node's own legacy/direct native metadata. Explicit exit configure/inspect/reconcile still manages the exit peer service.
- Bridge desired returns protocol → `ipv4`/`ipv6` booleans. This is configuration intent, NOT readiness. D owns assigning the independent native ingress addresses and shared forwarding prerequisites; A never changes native ingress devices or global forwarding sysctls.
- Supplying a changed native map is rejected, not silently adopted.
- State is owner-private `state.json`: owner `xio-cascade-native-v1`, schema, enabled, connectorId, revision, normalized public config, configHash, phase, process identity, probe evidence. Private/PSK values are separate mode-0600 files; neither raw UAPI nor `wg dump` is returned or logged. Atomic state writes fsync file and directory before effects proceed. Mutations serialize on a private flock.
- One reserved native connector per host. Live config/private-key/PSK changes require explicit removal/reconfigure; no silent peer takeover.

CLI actions: `validate`, `plan`, `configure`, `reconcile`, `inspect`, `verify`, `remove`; mutating action requests come through JSON **stdin**, never private-key argv. `--root` overrides the root for private test instances only. `remove` needs `{"confirmDirect":true}`; omission refuses before effects.

### Configuration sketch (not runnable key material)

Both full-XIO-node wizard sides must explicitly choose matching `sourceMode:"hop-snat"` and the same requested inner families. Hop addresses must be dedicated and distinct from existing local addresses/routes/management subnets. Egress capabilities must never be inferred from peer endpoint family.

```json
{
  "enabled":true, "ownerOptIn":true,
  "role":"bridge", "backend":"userspace", "interface":"xiocascade0",
  "sourceMode":"hop-snat", "innerFamilies":["ipv4","ipv6"],
  "localAddresses":{"ipv4":"10.203.0.2","ipv6":"fd42:203::2"},
  "peerAddresses":{"ipv4":"10.203.0.1","ipv6":"fd42:203::1"},
  "privateKey":"<owner-supplied-32-byte-base64-key>",
  "peer":{"publicKey":"<exit-public-key>","host":"<literal-exit-IP>","port":9443}
}
```

Exit role reverses the hop addresses, pins the bridge public key, chooses a dedicated interface (default same name on a different host), sets `listenPort:9443` and explicit `exitInterfaces:{"ipv4":"...","ipv6":"..."}`. Its optional peer endpoint may be omitted and learned from the authenticated bridge handshake. The selected exit family's actual egress route/device and non-link-local source are checked before application; later bridge proof, not this declaration, determines usable readiness.

Only all-mode is implemented. Optional PSK is supported. Endpoint must be an unambiguous bare IP literal; hostnames, URL/CIDR/zone/bracket/newline forms are rejected before mutation. Peer keys, names, ports, family/address overlap, explicit owner consent and unknown top-level config fields are validated before mutation.

## Backend / native data path

### Backend selection

Default is the **existing signed-server AWG userspace runtime**, SHA-256:

`fc1a1f9fae43cd8b8a4ac969b49bf80db9ed8d536d935166286cad53fcf34c9a`

Only the root-owned, non-world-writable, non-symlink executable at `/usr/local/lib/xio-managed/amneziawg-go` or `/usr/local/bin/xio-amneziawg-go` is accepted. Both installed Debian copies matched this exact digest. A dedicated `xioc*` TUN is started with `-f`, using its own `/run/amneziawg/<interface>.sock` and stdlib UAPI. Real signed-binary userspace packets proved the standard WireGuard-compatible default profile; no unpinned AWG/WG replacement is fetched. Native AWG/RIVET client anti-DPI transports remain unchanged: only their already-decrypted L3 interfaces feed this separate uplink.

Explicit `backend:"kernel"` uses a legitimate `ip link ... type wireguard` plus existing `wg` tool. There is **no automatic userspace→kernel fallback**. TUN-only supported operation was actually proved with the pinned userspace backend; kernel capability is not assumed.

Runtime PID/starttime/executable and a per-connector link alias prevent adopting or stopping foreign processes/interfaces. An unchanged peer is not replaced on every native rule reconcile, preserving its handshake and short-lived proof. No unrelated process or generic `wg0` is touched.

### Routing and fail-closed policy

- Dedicated route table `20792`, priorities `12042..12046`, exact mark `0x58494f00/0xffffffff`, owned route protocol `242`.
- Native forwarded traffic is scoped by **ingress interface + source subnet**. A selected-family lookup is immediately followed by terminal `prohibit` for that exact ingress/source. An unselected known native family gets terminal `prohibit` without an uplink lookup.
- The table has an unreachable default independent of the device. Interface deletion or even removal of every owned table route cannot fall through to main: the subsequent iif/source terminal rule still rejects it.
- A separate exact-mark lookup is used only by explicit source-bound diagnostic sockets. No OUTPUT marking, root-UID classification, blanket host default route, or main default replacement occurs. Ordinary management/SSH/control sockets are unmarked and iif-less, and stay direct.
- Dedicated mangle PREROUTING classification and mangle FORWARD kill-switch execute before existing native filter accepts. Owned filter FORWARD jumps are reinserted first to override existing native DROP order. Existing admin/RIVET rules are not flushed.
- **Unrequested IPv6 is blocked too** when all-mode requests only IPv4, and vice versa. No silent dual-family downgrade/direct leak.
- Only the dedicated uplink's IPv4 rp_filter is set loose. No global or ingress rp_filter changes are made.

### Source/NAT/reverse path

- Explicit `hop-snat`: precisely classified native packets leaving only the dedicated uplink are SNATed to that family's local dedicated hop. The exit peer AllowedIPs, reverse routes and NAT cover only the bridge hop addresses. Reverse conntrack restores the original native client. This coexists with an exit that already owns the same native 10.78/10.79/fd78/fd79 prefixes.
- Explicit `preserve`: the first owned NAT chain precisely exempts classified native source + dedicated uplink traffic from broad native base MASQUERADE. Exit peer AllowedIPs/routes/NAT include both native prefixes **and** hop addresses, accounting for the native base-NAT-to-hop interaction. Existing reverse-prefix collisions are rejected; nothing silently hijacks an exit's local native clients.
- No silent source-mode changes. Default preserve is conservative; the intended two-full-XIO-node wizard must explicitly choose hop-snat.
- Only reserved chains are flushed. Foreign rules in a reserved chain, foreign route-table entries, occupied policy priorities, foreign link/socket/process or conflicting hop/management routes are rejected instead of deleted/adopted.
- Application records intent first, installs routing/firewall fences before starting the tunnel and retains them on later apply failures. Explicit remove stops only the owned runtime/device and removes exact owned rules/chains/routes; restoration of direct native behavior requires owner confirmation. This is not an automatic 'rollback to direct' on tunnel failure.

## Truthful public readiness

`native_capabilities()` is bounded local observation (two-second local command budget); it performs no Internet probe and never makes a persisted `phase:"applied"` alone positive.

Public optional metadata:

```json
{
  "schema":1,"enabled":true,"connectorId":"...","revision":1,
  "observedAt":"2026-11-05T00:00:00Z","expiresAt":"2026-11-05T00:00:00Z",
  "awg":{"ipv4":false,"ipv6":false,"reason4":"...","reason6":"..."},
  "rivet":{"ipv4":false,"ipv6":false,"reason4":"...","reason6":"..."}
}
```

Positive requires current owned link/alias/native address, current peer AllowedIPs and a fresh handshake, expected owned forward/kill/NAT ordering, exact family routes/policy/fallback fence, forwarding prerequisites, and a config-bound successful per-native source-bound active probe younger than 60 seconds. The source must still exist. No proof, expired proof, mismatched hash, unavailable current inspection, missing route/link/guard or non-applied phase is false. `expiresAt` is the earliest remaining positive proof's expiry; absent positives it is now. Endpoint transport family is not an egress capability.

`verify` explicitly uses `ping` with the native family's assigned source and socket mark, defaults to public `1.1.1.1` / `2606:4700:4700::1111`, and records its narrow scope. This tests the inner family's exit return/NAT path, not actual device anti-DPI acceptance. A normal native forwarded packet proof is separate below. Read-only issuance hooks must not synchronously probe the Internet.

## Final evidence

- [Command exit statuses](<work/native-connector-20261105/command-status.log>): unit=0, packet proof=0, host invariant=0.
- [Unit log](<work/native-connector-20261105/native-unit.log>): **17/17 PASS**, 1.250 seconds.
- Exact tested source SHA-256: connector `bbe31d886b86cfc976ba6e5bc732371e2430e92002ce937a3c9d439169c7b91a`; unit suite `d8e7b49c14d28309b3e3f2d8a709b479ad22120b3b3688fc47c55dbb23e1346a`; packet proof `30d1c19d8d8e52cd1a85f2ed2043e32ca08a45dc42173ce128bbd8e520150ef3`.
- [Actual packet log](<work/native-connector-20261105/native-proof.log>) and [machine-readable matrix](<work/native-connector-20261105/native-packet-proof.json>).
- [Host network invariant](<work/native-connector-20261105/host-network-invariance.log>): before and after digest `c5fb2537d6410992b993245295b29be64e6fa67fe6ecd9224e5a268238b27e7e`.

Six cases:

| Uplink backend | Endpoint transport | Source mode | Requested inner families | Native AWG/RIVET result |
|---|---|---|---|---|
| Pinned userspace AWG | IPv4 | hop-snat | IPv4 + IPv6 | each 2/2 |
| Pinned userspace AWG | IPv6 | hop-snat | IPv4 + IPv6 | each 2/2 |
| Pinned userspace AWG | IPv4 | preserve | IPv4 + IPv6 | each 2/2 |
| Explicit kernel WG | IPv4 | hop-snat | IPv4 + IPv6 | each 2/2 |
| Pinned userspace AWG | IPv4 | hop-snat | IPv4 only | IPv4 each 2/2; IPv6 blocked |
| Pinned userspace AWG | IPv6 | hop-snat | IPv6 only | IPv6 each 2/2; IPv4 blocked |

Every case also checks IPv4+IPv6 management sockets/routes stay direct, fresh capability values match requested families, exit role publishes no native bridge override, removing the entire owned table **and mangle guards** still cannot fall through to direct under an early native base ACCEPT, reconcile recovers, tunnel deletion prevents both native families leaking, and explicit remove leaves foreign/base rules intact. Hop-SNAT cases deliberately provision overlapping local native prefixes on the exit.

### Isolation / reproduction

Only saved Debian access was used. All transferred code, fixture/state/temp artifacts and evidence are beneath `/srv/archives/native-connector-20261105`. Before creating test namespaces the proof refuses host network/mount namespace IDs and requires an empty outer network namespace. It makes mounts private and places a private tmpfs on `/run` before creating named namespaces/UAPI sockets. All links/rules/sysctls/processes belong to this fresh private scope; cleanup targets only PIDs enumerated from its own named namespaces.

```sh
# From the archived source root; NOT on the host net/mount namespace.
unshare --mount --net --fork env TMPDIR=/srv/archives/native-connector-20261105 \
  python3 server/managed/test_cascade_native.py
unshare --mount --net --fork python3 tools/prove_cascade_native.py
```

Host IPv4+IPv6 routes, stateless nft rules and named-netns lists were hashed before/after the final packet run. No host network/service action, Docker mutation, production VPS change or external package fetch is part of these tests.

## What is NOT proved / integration gates

1. **No real device anti-DPI acceptance or public VPS/Internet deployment acceptance.** Native ingress is simulated with L3 veths named xioawg0/xiorivet; the signed uplink engine and kernel/NAT/routing are real. Public-looking ICMP targets are synthetic addresses inside the isolated world namespace. No claim is made about real Internet egress, UDP DPI behavior, HTTP/TCP acceptance, load or MTU performance.
2. This branch does not wire D's admin/start/reapply hooks, provision independent fd78/fd79 ingress addresses, rebuild the signed server package, install the module on a production node, or alter app profile policy. Those must be integrated and independently tested.
3. **Cold-boot ordering is still an integration gate.** Persisted intent alone does not survive a kernel reboot as live rules. An early owned guard/reconcile unit (Before native listeners) or equivalent native-start ordering is required to avoid a direct-first boot window. Post-apply hooks alone do not prove reboot-safe fail-closed behavior. The live tunnel-loss/table-loss safety proof above must not be generalized to cold boot.
4. No periodic active verifier/watchdog unit is installed by this module. The owner/managed scheduler must explicitly refresh probes; after 60 seconds without a new successful probe public booleans are false. Kernel/TUN loss remains blocked, not automatically rerouted direct. A later reconcile can recover the runtime, but no standalone unattended supervision claim is made.
5. Only all-mode, one peer and one connector instance per host are supported. Source mode and key changes require explicit remove/reconfigure. Existing conntrack sessions established before opt-in may need reconnect; no broad conntrack flush is performed.
6. Not every power-loss/partial-platform-command failure has a real packet fault-injection proof. Atomic durable owner intent and conservative failure state are implemented; full cross-family distributed transaction/reboot/recovery acceptance remains separate.
