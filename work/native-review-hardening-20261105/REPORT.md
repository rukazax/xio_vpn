# Core review hardening — RPDB ownership, private key reads, truthful failure states

Separate bounded follow-up after map-pin commit `3bad25eb5a66698b42079ba3476dbb71ef0cd750`. Only [core module](<server/managed/cascade_native.py>), [new reviewer regression tests](<server/managed/test_cascade_native_review.py>), and narrow fixture/expectation updates in the existing [core tests](<server/managed/test_cascade_native.py>) / [lifecycle tests](<server/managed/test_cascade_native_lifecycle.py>) change. No RPC/D/package/native generator or lifecycle implementation edits.

## Exact policy ownership / no management capture

`policy_matches` now verifies effective mark **and full 0xffffffff mask**, including omitted full-mask, explicit decimal/hex and consistent embedded-mask encodings. Zero/partial/contradictory masks are never adopted or green.

All native lookup/prohibit rules require exact source+iif and unrestricted destination; diagnostic mark-only rule cannot gain source/iif/destination narrowing. Unknown selectors/modifiers (UID, output interface, packet protocol, ports, suppression, inversion/goto, unknown flags) are refused. Prohibit action and lookup/table semantics are checked. Harmless kernel protocol metadata and the actual Debian late-bound `iif_detached:null` representation, plus known detached-iif flags, are retained.

**Important ordering fix:** both families' reserved priorities and every reference to owned table 20792 are validated before adding ANY route/rule. Previously a foreign mask-zero rule could capture all management immediately when the controller added its rejecting default, even if a later rule check refused it. Foreign/modified/duplicate rules or foreign references at other priorities now fail before that first write. Remove performs the same read-only validation before stopping lifecycle/runtime or deleting any fence. Live readiness uses the same exact selector/ownership check.

A new actual private-kernel regression seeds `fwmark 0x58494f00/0x0` at the reserved priority, reads real iproute2 JSON and confirms rejection with **no rejecting route added**. It refuses host namespaces and nonempty outer private networks. Mocked IPv4/IPv6 conflicts include narrowed destinations on both lookup and terminal prohibit rules and prove zero kernel/lifecycle mutation. A fully positive live-observation fixture becomes public-capability false when only the mask changes to zero.

## Bounded no-follow private/PSK reads

All private/PSK consumption in configure comparison and peer application uses one reader: O_NOFOLLOW + O_NONBLOCK descriptor, fstat regular file, current-euid ownership, no group/other mode bits, at most128 bytes, ASCII/base64 key validation. Optional PSK treats a genuinely missing file as absent, but not a dangling symlink or unsafe inode. FIFO/directory/device-style nonregular files cannot cause a blocking read. Generic failures include no key content or sensitive path.

Regressions cover valid600 key, missing optional file, symlinks/dangling links,0644, oversized file rejected before read, nonregular FIFO/directory, foreign owner rejected before read, invalid private/PSK failing before backend/kernel/lifecycle calls and secret-free errors. One old handshake-preservation fixture previously created a0644 file; it now correctly uses the controller's atomic0600 writer. No runtime validation is weakened for tests.

## Truthful preparation / guard state

- Failure before `_apply`: `phase:"preparation_failed"`, `guardState:"unknown"`; explicitly says no network apply was attempted and does not claim retained fences.
- `_apply` records `applying` / unknown before effects; only successful policy+firewall installation records `guarded` / `last_installed`.
- Failure after that stage: `fail_closed` with last-installed guard provenance, no automatic direct rollback, and a request to inspect current guards.
- Partial/unknown apply failure: `apply_failed` / unknown, never an unproved retained-fence claim.
- Existing owned effects are not deleted on failures; all probe proofs clear and no failure phase can publish positive readiness. Enabled remains owner intent, NOT successful activation.

Configure, native reconcile and boot guard use this distinction consistently. Lifecycle-install failure tests assert `_apply` was never called and the phase is preparation_failed. A backend failure after actual mocked guard-stage completion asserts guards remain installed, the recorded provenance is last_installed and no cleanup/direct restoration is invoked.

## Exact-source evidence

Core SHA-256: `e16b9f63262caa9bb01a7a1e7602afa2010092baaad4d33e1bf2f3690c7c52b4`.
Reviewer tests SHA-256: `8a7db033f79c707cbec02eee0b7ea6d9868eb29055c4fafc0b25d83e16b36638`.
Local and remote archived source hashes matched.

- [Core log](<work/native-review-hardening-20261105/core-unit.log>): **19/19 PASS**.
- [Lifecycle/offline-systemd log](<work/native-review-hardening-20261105/lifecycle-unit.log>): **23/23 PASS**.
- [New reviewer log](<work/native-review-hardening-20261105/review-unit.log>): **11/11 PASS**, 1.870s (includes real private-kernel zero-mask reproduction).
- [Early-guard packets](<work/native-review-hardening-20261105/boot-proof.log>): both pinned userspace + explicit kernel PASS with native devices created after guards.
- [Encrypted native packet regression](<work/native-review-hardening-20261105/packet-regression.log>): all six cases PASS.
- [Packet command statuses](<work/native-review-hardening-20261105/packet-status.log>): all three zero. Unit command also exited0 with all three suite exits0.
- [Host network invariant](<work/native-review-hardening-20261105/host-invariance.log>): identical before/after digest `c5fb2537d6410992b993245295b29be64e6fa67fe6ecd9224e5a268238b27e7e`.

Everything ran under fresh private mount+network namespaces, private `/run`, mocked systemctl/offline unit verification. Files and fixtures remain below `/srv/archives/native-review-hardening-20261105`. No real host network/systemd mutation, deployment or external package install.

## Not claimed

No actual VPS reboot, real anti-DPI device or public Internet acceptance. Existing [lifecycle integration/acceptance gates](<work/native-lifecycle-20261105/REPORT.md>) remain; parent must rebuild/integrate and independently validate the final combined branch. The core source here is not the final signed package. Concurrent deliberately conflicting privileged/root configuration is outside the bounded ownership model; foreign effects are refused, not force-deleted.
