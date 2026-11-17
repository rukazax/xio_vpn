# Android / Ubuntu / Windows integration checkpoint — 2026-11-05

## Source, not a release

Initial parent code integration `b0934c70181f1e757429553f994b7db3982cf781` merges independently accepted native candidate `280625da9377d076879c06523988482ed2dd1750` into packaging/CI integration `c94d9ce07a4c50bb61631a308b9cb001fb31807a`. Both merge parents are retained. No push, tag, release, actual CI run, authoritative asset regeneration or new application package in this checkpoint. Published feature baseline remains `a751864a38fe755018b716f6b42e6964fcac890b`, not main. Apple remains deferred.

## Checks and boundaries

- Parent rerun on the **merged** source: **92 run, 87 pass / 5 explicit skip / 0 fail** (Linux dpkg fixture plus four PyYAML-dependent workflow checks unavailable on this Windows Python). [Log](packaging-tests.log), [source receipt](source-receipt.json), [runner](run-scoped.py). Package provenance/resource/staging checks, dynamic Client versions, CI parser/security cases and mocked Android acceptance harness. The receipt contains exact result counts and independently compares all eight accepted native source/test SHA256 values against this parent tree. No packaged PE execution or Android/device action.
- Native candidate: ordinary WSL and Debian **207 tests, 206 pass / 1 skip / 0 fail**. Independent reviewer repeated the exact immutable candidate, same result, plus **98 standalone Dart parser checks**. The one skip requires a fresh private network AND mount namespace; host mutation was not substituted. Native finalizer also ran **44 scoped Flutter tests**, formatter and analyzer clean. [Candidate report](../../NATIVE-BOUNDARY-FINALIZE-20261105.md), [eight source hashes](../../../evidence/source-hashes.json). These are bounded tests, NOT a full integrated application/release suite.
- Plan/key journal foundation: **100 scoped tests** and analyzer clean on its earlier exact source set, [report](../native-plan-journal-20261105/REPORT.md). Includes persist-before-admission, unknown-outcome retention, stale revision refusal and deterministic Python-normalizer hashes. The journal only serializes one process; coordinator/UI and cross-process locking are not implied.
- Android encrypted-vault sync admission: exact source standalone cached Kotlin2.4.0 / Android36 public SDK compile passed. File sync precedes checked rename and child-to-parent directory fsync. [Evidence](../android-vault-sync-20261105/REPORT.md). No physical-device filesystem, Keystore or power-loss proof; no whole APK compilation in this check.

## Integrated changes

Await archive verification before update side effects; encrypted native plan/key journal; trusted standalone payload source; strict native ingress map, full-mask/selector RPDB ownership and both-family pre-mutation checks; bounded no-follow private key reads; early boot guard and periodic verifier; owner-only RPC; RA ordering; honest inspectable recovery phases with historical guard provenance; bounded <=60s consumer TTL; package resource/stream bounds; transactional staged artifact copies; PE allocation bounds; Client version derivation; collect-only identity-pinned Android harness; owner/manual CI lanes for current platforms. The CI workflow is source only, not a successful run or desktop signing attestation.

## Complete installer source integration

Source merge **`48c0382ec67580f40bc18089c7c95f1be84c4fb2`** additionally integrates shipping `28192d9aa6ba1b4ee80f8ae1de947bc4991fc111` AND independently accepted parent-ownership follow-up `37b576e81224c0faf769e2eee14dd569e7072303`. All three native runtime modules are mandatory through packaging/bootstrap/updater. Full unprojected producer-layout archive compatibility is covered. This is source wiring, not regeneration/publication of a pinned production archive.

Original 28192 rollback could unlink/restore a same-name foreign file through a replaced directory or symlink. The follow-up records no-follow parent identities, validates all rollback parents before any rollback file operation and rechecks per target. Known replacement now enters **retained-backup owner recovery**, NOT a promise that STATE/runtime rolled back. Independent reviewer repeated all37 and its own four original/new-directory/preexisting-directory × foreign-directory/symlink cases, with zero foreign file actions and preserved original bytes/modes. This is not a general proof against arbitrary privileged per-syscall races or replaced backup storage.

Parent repeated the **combined I+M tree** in ordinary WSL Ubuntu, all effects mocked except owned fixture files:

- [Native suite](integrated-48c0382-native.log): **207 run, 206 pass / 1 legitimate private-kernel skip / 0 fail**,35.362s.
- [Shipping suite](integrated-48c0382-shipping.log): **37 pass**,50.844s; includes full fixture installer and four replacement-parent cases. These suites overlap; do not add their counts as unique tests.
- `sh -n` and `bash -n` both exit0; [six source hashes](integrated-48c0382-hashes.txt) match accepted native3 and updater30eb.../shipping57e1... source.
- [Package/CI/harness rerun](packaging-48c0382.log) **87 pass / 5 explicit skips / 0 fail** on48c; [receipt](source-receipt-48c0382.json) confirms exact tested HEAD and all eight native source/test byte hashes.
- [File-backed driver](run-integrated-48c0382.sh). Initial inline PowerShell→WSL bash quoting lost shell-variable expansion and failed `cd /server/managed` BEFORE any tests. It exited1, not a test failure; file-backed `wsl --exec bash` then ran the above tests. No host networking/services activated.

Inert catalog/cascade copies do not imply external SNI/catalog activation. Authoritative archives/mirrors/native assets remain stale until a separate pinned-input regeneration.

## Still open / do not ship

1. Connection policy/global round: final limited Go milestone **`435de091a82d02ad16fe74e3512f6bec8286bab8` independently accepted**. Fixes establishment-vs-session lifetime, truthful terminal IO, actual H3 carrier cancellation during withheld CONNECT, and stale retired-lease watcher ownership. Unchanged independent H3 cancel/setup/lifetime/deadline probes pass, S1 authenticated packet exchange survives setup cancellation; old four regressions plus stale-watcher repeat10 pass;15 mobile recovery +3 carrier cases pass. No physical/native/package/full successful H3 or full-suite attestation. Go mobile/internal-rivet bytes are unchanged in the later frozen app-source `61b69433686c5868146bdc78ae00c7fc87b72026`.
2. Frozen Dart/Android/desktop candidate61b6943 (evidence HEAD37d7286) is **not integrated/independently accepted yet**. Worker reports28 scoped Dart, analyzer0, javac0,13 pure desktop tests and crosscompile; independent app/Android/controller/desktop review is underway. Source and evidence survived worker failure; untracked construction scripts/archives preserved, no reset/stash. New JNI/AAR/helper assets still mandatory. Visible Auto/selectedOnly UI and persistent user choice are separate parent work, not implemented by this runtime scope.
3. Old VPS installer/UI has not been replaced by the durable native coordinator. Owner user issuance still needs prepared encrypted material and unknown-outcome reconciliation, not fresh UID/key retry or blind revocation. Cached profile migration and authenticated native client acceptance remain open.
4. Regenerate coherent server archives/bootstrap mirrors/native bindings/helpers/metadata and fresh Android Full+Client, Ubuntu and Windows artifacts; choose a new immutable release version rather than overwrite v0.24.2. Actual signed APK/POCO, memory, airplane mode, manual transport, fallback wall-clock, VPS reboot/Internet/native client and platform acceptance remain separate. Windows unsigned execution is restricted by SAC/WDAC; no bypass.

Existing isolated native packet/early-guard proofs were run on earlier exact backend source and do not magically become fresh proof of this later integrated tree. No real VPS/systemd/host network changes or app installation were made by this checkpoint.
