# Native cascade lifecycle — bounded boot ordering and periodic verification

## Separate follow-up / owned scope

This follow-up builds on committed native connector `e41699d86b22e6cc3f2bf64b14cca4d41f245956`; its [core report and exact six-case evidence](<work/native-connector-20261105/REPORT.md>) are preserved unchanged.

New [lifecycle helper](<server/managed/cascade_native_lifecycle.py>), [lifecycle tests](<server/managed/test_cascade_native_lifecycle.py>), [early-ingress packet proof](<tools/prove_native_boot_guard.py>), and narrow calls/auto-actions in the existing [connector](<server/managed/cascade_native.py>) are the entire implementation scope. No admin/dualstack/RIVET generator, Flutter/Dart, unrelated transport service, packager or signed artifact is edited here.

The parent/packager must install BOTH sibling runtime modules in the existing signed payload at `/usr/local/lib/xio-managed`. A missing lifecycle helper is not silently tolerated by production configure, boot guard, reconcile or positive readiness.

## Managed production lifecycle

The supported production root remains `/etc/xio-managed/cascade-native` and systemd directory `/etc/systemd/system`. An alternate connector root can bypass host lifecycle only inside **both a private network and private mount namespace**; it is an isolated test instance, not a supported alternate production deployment. Outside those namespaces alternate roots are rejected. Tests inject private unit directories and a mocked systemctl backend; no real host systemd manager is changed.

Production configure performs:

1. Validate the request and persist durable owner-private connector intent.
2. Install/journal owned boot artifacts before accepting the network apply.
3. Apply routing/firewall fences and the dedicated native uplink.
4. Activate only the owned verifier timer after the apply succeeds.

An initial configure that cannot install the mandatory lifecycle returns failure and is not an accepted active cascade. No 'best effort lifecycle' success is reported. Existing legacy no-opt-in operation remains unchanged: no owned lifecycle artifacts/dependencies are created, reconcile is a no-op, capabilities are `None`, and timer auto-action does no probing.

### Owned artifacts, bridge role

The helper renders only:

- `xio-cascade-native-guard.service`.
- `xio-cascade-native-verify.service` and `xio-cascade-native-verify.timer`.
- Reserved `20-xio-cascade-native-guard.conf` drop-ins under each exact native unit:
  - `xio-managed-awg.service`.
  - `xio-rivet-gateway.service`.
  - `xio-rivet-entry.service`.
- Exact relative enable symlinks in `multi-user.target.wants` and `timers.target.wants` for those owned units.

Each native drop-in has mandatory `Requires=xio-cascade-native-guard.service` **and** `After=xio-cascade-native-guard.service`. The guard also declares `Before` those three services. Consequently the guard must successfully finish before native ExecStartPre/ExecStart/listeners; guard failure, absent/disabled owned receipt, missing helper or missing connector program must fail the dependency, not skip successfully. There is deliberately **no ConditionPathExists/ExecCondition** that could turn a missing mandatory guard into a successful skip.

The guard's oneshot `guard-auto` reads the existing owned receipt, verifies the installed lifecycle, and applies fences/uplink before native ingress interfaces exist. It does not wait for native addresses or Internet proof, because those belong later in startup. Actual Linux packet proof confirms iif/source rules bound before xioawg0/xiorivet existence become effective when those interfaces appear. Existing native start/reapply hooks may then reassert owned priorities after their base firewall rules, without weakening the terminal policy fences.

The guard is `RemainAfterExit=yes`; the owned runtime can remain in its cgroup on boot. Native units keep the normal managed service generators and transport executables; only dependency drop-ins are added. No xio-stack, cloak, OpenVPN, Docker or generic wg0 unit is altered.

### Exit role is not a local native bridge override

Exit-only peer role installs only its owned guard/peer boot unit and enable link. It does **not** install dependencies on its own local native AWG/RIVET listeners or a native-family probe timer. Its desired/capabilities wrappers remain `None`, preserving that full XIO node's existing local direct native profile metadata. The separate remote bridge remains fail-closed if its exit peer is unavailable.

## Explicit periodic source-bound verification

The verifier uses dedicated stdin-independent `verify-auto`, with `StandardInput=null`; it never invokes the JSON-stdin `verify` action with empty input. Both `guard-auto` and `verify-auto` are bounded dedicated CLI actions, not shell pipelines containing secrets.

- Timer: `OnActiveSec=15s`, `OnUnitActiveSec=30s`, `AccuracySec=1s`, no randomized delay.
- Verifier: Requires/After the guard, oneshot timeout 25 seconds.
- `verify-auto` first reconciles owned network state (idempotent peer preservation), then uses the already implemented explicit native-source + exact socket-mark probes to the configured public-family defaults.
- Timer refresh interval plus worst declared verifier runtime is below the 60-second proof lifetime. Failures do not fabricate a new positive; expired proof becomes false and tunnel/route loss remains blocked.
- No Internet probing is added to `inspect`, desired, public capabilities or normal profile-read metadata. They remain bounded local observation.
- No owner opt-in / removed opt-in / exit-only role: `verify-auto` returns a non-probing negative result.

## Ownership, failure and removal

A mode-0600 `lifecycle.json` in the owner-private connector root records owner `xio-cascade-native-lifecycle-v1`, connectorId/revision/role, exact unit directory, expected file SHA-256 values, enable-link targets, effect journal and install/active/remove phases. Files, receipt and directories are fsynced before accepting application.

- First installation refuses preexisting reserved files or enable links instead of adopting them.
- Reapply accepts only exact receipt-bound content and symlink targets. Changed reserved files, receipt mismatch, foreign enable links and symlinked/unsafe drop-in parents are rejected.
- Install failure rolls back only artifacts newly created by that attempt **and still matching** its expected owner content. A concurrent foreign edit is preserved, not overwritten/deleted.
- Unrelated drop-ins in native service directories remain untouched. This helper does not rewrite the base native units or flush directories.
- Positive production readiness also checks the installed lifecycle receipt/files/links; missing or modified mandatory owned artifacts cannot retain a fresh positive merely because old probe JSON exists.
- Remove still requires explicit `confirmDirect:true`. Lifecycle removal validates ownership before any stop/delete, stops only the owned timer/verifier, removes only owned dependency drop-ins and enable links, reloads definitions, then stops/removes only the owned guard unit. Removing dependencies before stopping the guard avoids needlessly stopping native transports through a still-live Requires relationship.
- If a foreign lifecycle edit is detected, core remove refuses before deleting live network fences. There is no forced overwrite of foreign content and no silent direct fallback.
- Core then stops its owned runtime/interface and removes exact owned network effects. Durable removed receipts are retained; empty parent directories are not broadly removed. Explicit reconfiguration can create a new owner generation after successful removal.

## Evidence and precise acceptance boundary

Final results are in [exit statuses](<work/native-lifecycle-20261105/final-status.log>), [core regression unit log](<work/native-lifecycle-20261105/core-unit.log>), [lifecycle unit/offline graph log](<work/native-lifecycle-20261105/lifecycle-unit.log>), [early packet log](<work/native-lifecycle-20261105/boot-proof.log>), [early packet JSON](<work/native-lifecycle-20261105/boot-packet-proof.json>), [six-case packet regression](<work/native-lifecycle-20261105/packet-regression.log>) and [host invariant](<work/native-lifecycle-20261105/final-host-invariance.log>).

Final exact-source results: **17/17 core tests PASS** (3.568s), **23/23 lifecycle/offline-systemd tests PASS** (13.994s), both actual early-guard backend cases PASS, all six encrypted-native packet regression cases PASS. All five command exit statuses are zero. Host digest is identical before/after: `c5fb2537d6410992b993245295b29be64e6fa67fe6ecd9224e5a268238b27e7e`.

Exact tested source SHA-256 (local and archived remote copies matched):

| Source | SHA-256 |
|---|---|
| [Connector](<server/managed/cascade_native.py>) | `99fbe2272eddb2f301a4dd2a5536993a805c32e42c70ea1ff1c27775c47586c2` |
| [Lifecycle helper](<server/managed/cascade_native_lifecycle.py>) | `ab43499fb0f5e4b2ed211dbccb7bcf42d94b1646317c47bf90346939ca8ca257` |
| [Lifecycle tests](<server/managed/test_cascade_native_lifecycle.py>) | `0b9315a77b627fec67d96d18d1644e7e800ba649e1a4db53c7116bda7f857741` |
| [Early packet proof](<tools/prove_native_boot_guard.py>) | `56f0aa17510d45fb23ae3b0902a368b5c15242e88d1e84eb3883814015f23f02` |

The lifecycle tests cover exact three-unit dependency graph, no successful conditional skip, missing program/helper/receipt and failed guard preventing mocked listener starts, configure ordering, no-opt-in legacy behavior, exit no-native-scope behavior, timer stdin/arguments/interval, ownership conflicts, foreign concurrent edits, install rollback, remove preserving unrelated drop-ins, foreign edits blocking core network removal, required enable-link loss/recovery, and host custom-root bypass rejection. `systemd-analyze verify` validates all generated services/timer plus private native fixtures **offline**, without contacting the live manager.

### Actual early-guard packets

Both the pinned signed AWG **userspace** backend and explicit legitimate **kernel** backend passed a fresh isolated startup sequence:

1. Durable owner receipt exists, but there are no native interfaces, no previous runtime and no previous kernel policy.
2. Run exact `guard-auto` with empty stdin before xioawg0/xiorivet exist; it succeeds only after installing fences/uplink.
3. Create both native L3 interfaces later and insert early direct-native base ACCEPT/MASQUERADE rules with a genuinely usable IPv4+IPv6 direct network. Native AWG/RIVET 4/6 cannot leak directly while the peer is unavailable.
4. Delete the tunnel, flush its table and remove mangle guard rules. The terminal iif/source fences still block both families on the late-created interfaces.
5. Management IPv4+IPv6 sockets remain direct.
6. Explicit owner removal restores direct native IPv4+IPv6 pings as a positive network control, proving the earlier drops were not a disconnected test network.

The full original six-case encrypted uplink/native-family/NAT matrix was rerun against this follow-up source, preserving selected-family 2/2 returns, unrequested-family blocks, management direct, route/tunnel-loss fail-closed and foreign-rule-preserving remove.

All code, temporary private roots, unit fixtures and evidence are below `/srv/archives/native-lifecycle-20261105`. The proof refuses host network/mount namespace IDs and requires an empty outer network namespace; mounts are made private and `/run` gets a private tmpfs before named namespaces/UAPI sockets are created. Unit filesystem effects are private and systemctl is mocked. Host IPv4/IPv6 routes, stateless nft rules and named-netns lists are hashed before/after.

## Remaining gates / what is NOT claimed

- **No real host/VPS reboot was performed**, and no live host systemd manager, native service, route or firewall was mutated. Evidence establishes generated systemd dependency validity + mocked failure timeline + actual early/late-interface kernel packet behavior, not acceptance of a production node reboot.
- No real anti-DPI device/client or public-Internet/VPS egress acceptance, TCP/UDP workload, MTU/load benchmark or package upgrade/reboot soak is claimed. Public-looking ICMP addresses in packet proofs are inside the private synthetic world.
- Parent must integrate D's existing native lifecycle/address hooks and package BOTH signed runtime modules, then independently test the final installed units/services and requested inner-family profile contracts. No release/deployment is authorized by these reports alone.
- Assumes unrelated privileged administrators do not deliberately remove policy fences or override mandatory native dependency semantics through separate conflicting unit configuration. Foreign content is preserved/refused, never force-edited.
- Source/key/family changes still require explicit remove/reconfigure. One peer/connector and all-mode only. Cross-family/distributed power-loss acceptance beyond the journaled filesystem/network fault cases remains separate.
