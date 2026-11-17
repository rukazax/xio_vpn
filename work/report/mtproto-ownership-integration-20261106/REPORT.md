# MTProto ownership lifecycle — integration receipt

Independently accepted source: `5801b32da95a8e86b9949dec03dca430374b92e4`, parent `ea891990997038d50c863fb07cdc27967943fcdd`. Integrated without conflicts as `bf94472466dcd3cc4e71ccd3719b4a45eca44e8a`, first parent `6da8451249c80e75fbed1255df4932f699585aa1`.

The merge changes exactly the installer, README and focused ownership test. The complete MTProto directory matches the accepted source commit. App, protocol, server, tools, tooling and vendor trees remain identical to the first parent. Existing C6 combined host-test acceptance is therefore preserved by source identity, not claimed as a fresh execution after this shell-only merge.

## Independent evidence

- [Original 49 cases](<full49.log>): 49 passed, zero skipped, 547.608 seconds, exit 0.
- [Six additional adversarial cases](<adversarial6.log>): six passed, zero skipped, 60.259 seconds, exit 0.
- Bash syntax and source-only whitespace checks passed.
- [Runner](<run_independent_suite.py>) verifies original hashes and adapts only two fixture-root string literals in memory for the separately authorized reviewer directory. This is declared test-fixture adaptation, not a production change.
- [Independent adversarial probe](<independent_adversarial.py>) exercises current quiescence, vendor alias and absent-unit/replacement boundaries. Additional fixture inputs remain in the outer reviewer workspace; this evidence directory is not a standalone replay kit.

Exact committed/tested SHA256:

| Component | SHA256 |
|---|---|
| Installer | `fda86965e827652e0df86e76a4f1562f4a602a578c598c0c3b6443e1d1836ff3` |
| Tests | `eeb44ebb4b1ea22815b790bc4426fc44d33cee6f5c7049d5b0f17f742bb5674b` |
| README | `580a050b7481887bacabc0d38b995defb4a088810ee77bd8f131bed4389ea2ff` |

Original test hash above is unchanged; reviewer-bound in-memory test hash is `dd174ce3c4640b6fdc7452a0c9ac85e3dad692b345e8f46b81aaf7d69c6c0728`. Full log hash is `fc3cb4ba67baa234f805895500f5a1fdf9ddce44e0346cae8cf93aea6de37bbb`; adversarial log hash is `e24274a355211b00bbd47804ff6fc4afc8792fe3a5d1148833fe2caeb7f21961`.

## Rejected candidate history

The [old stop-retry counterexample](<historical-stop-retry.log>) is retained unchanged. Its successful probe exit established a defect, NOT successful installer acceptance: after cached stop completion and simulated reactivation, the old installer removed payload while the service remained active. The corrected source revalidates live quiescence on every invocation. A second pre-effect gap omitted vendor aliases; the corrected scan covers declared vendor roots conservatively. Both P2 findings were independently closed before integration.

## Limits

All account/group/NSS/service/package/download/DNS/HTTP boundaries were mocked. Real POSIX metadata, inode/ctime, file operations and flock were exercised only in explicitly owned fixture trees. No real account, service, installer, VPN, phone or VPS action occurred. No live systemd/NSS compatibility, network reachability, power-loss/global atomicity, or hostile/noncooperating-root immunity is claimed. Legacy unreceipted resources and ambiguous interrupted states remain fail-closed/manual-recovery cases.

This is bounded source/fixture acceptance, not a live deployment or release. Other app/WebUI/provisioning/artifact work remains pending. Five raw evidence files were copied byte-identically without log normalization.
