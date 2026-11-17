# Authoritative native-map validation safety fix

Separate minimal follow-up after `e44379535219a93e2e83ea6d3309b9f1cf49110e` responding to independent review: [connector validation](<server/managed/cascade_native.py>) previously accepted custom native ingress maps and could apply their policy before a later default-map mismatch was reported.

## Change

- Configuration must resolve to the exact normalized authoritative AWG/RIVET interfaces and both-family subnets. This applies to bridge/exit, both/single inner-family selections, production/default and private/test roots. No testing exception permits alternate maps.
- Map shape is strict: exactly awg/rivet; each entry exactly interface/ipv4/ipv6; correct types and CIDR string families. Explicit null is malformed, not an implicit default.
- Omitted canonical default, explicit canonical map and equivalent normalized canonical CIDR notation have identical public config and pure network plan.
- Rejection occurs inside pure validation, before owner writes, locks, lifecycle, preflight, policy/firewall or runtime calls. No routing or RPC/D/package implementation is changed.

## Tests / isolation

[Core tests](<server/managed/test_cascade_native.py>) add 25 negative map variants across 2 roles × 3 family selections × 3 roots: 450 configure +450 plan rejection checks, with every effect entry point patched to fail if reached. Cases include eth0/broad source, eth0 with otherwise disjoint routable prefix, loopback, other private prefixes, changed IPv6 even when not requested, wrong families/types and extra/missing entries/fields. Fresh private root directories remain absent. Pure default/explicit/normalized plan equality is checked separately.

No intentional custom fixture map needed accommodation: actual private packet fixtures already use canonical xioawg0/xiorivet and native subnets.

Exact connector source SHA-256 tested: `523fad66d3ba730884fa0a7e84a0937b74c3e031b9828fc87ca0c075522b1f4f`.

- [Core unit log](<work/native-map-guard-20261105/core-unit.log>): **19/19 PASS**, 3.758s.
- [Lifecycle/offline-systemd log](<work/native-map-guard-20261105/lifecycle-unit.log>): **23/23 PASS**.
- [Actual early-guard packet log](<work/native-map-guard-20261105/boot-proof.log>): pinned userspace + explicit kernel PASS with native interfaces created only after guard application.
- [Full encrypted packet regression](<work/native-map-guard-20261105/packet-regression.log>): all six canonical cases PASS.
- [Final command statuses](<work/native-map-guard-20261105/final-status.log>): all five zero.
- [Host invariant](<work/native-map-guard-20261105/host-invariance.log>): unchanged before/after (`c5fb2537d6410992b993245295b29be64e6fa67fe6ecd9224e5a268238b27e7e`).

Everything ran under fresh private mount+network namespaces; artifacts only under `/srv/archives/native-map-guard-20261105`, private `/run`, mocked systemctl/offline verification. No actual host systemd/network mutations or deployment.

## Remaining review / acceptance gates

This commit fixes only native-map validation. The parent's separately reported RPDB selector/mask matching, bounded private key-file reads and truthful preparation-failure state are next authorized bounded core follow-ups, not claimed fixed by this commit. Existing [lifecycle report](<work/native-lifecycle-20261105/REPORT.md>) production integration/real reboot/device/public Internet acceptance gates remain unchanged. Previously persisted noncanonical receipts are not silently adopted/migrated; parent confirms this implementation has not been deployed.
