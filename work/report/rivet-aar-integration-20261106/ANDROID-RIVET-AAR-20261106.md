# XIO Android rivet.aar — fresh all-ABI payload, MAIN 595def6a — 2026-11-06

## Verdict and strict scope

**PASS: a FRESH `rivet.aar` was produced offline from the exact MAIN snapshot with the project's own recipe, covering all three ABIs the release ships, and it satisfies the real Kotlin/Java application compilers in both Full (`app.xio.xio`) and Client (`app.xio.client`) modes.** The committed `cfc336c936c06f0d08b73fca77768f31a23afcb7f915354e5d78e61995e27de7` AAR fails the same compiles on the three known methods, so it is confirmed as the blocker, not a Kotlin defect.

**This is compiler-level proof of the native payload. It is NOT APK/AAB, signing, install, device, route/VPN, or runtime acceptance.** Dart compilation and asset merging were excluded; `app/pubspec.lock`, Dart sources and assets were untouched. Only the three ABIs actually built are claimed. Nothing was committed, pushed, or replaced in `work/repo-merge`; the bundled AAR there is unchanged.

## Fresh artifact

| Item | Value |
|---|---|
| Path (host) | `/srv/archives/agent-rivet-aar-20261106/artifacts/rivet-fresh-595def6a-allabi.aar` |
| Path (this workspace) | [rivet-fresh-595def6a-allabi.aar](<agent-rivet-aar-20261106/artifacts/rivet-fresh-595def6a-allabi.aar>) |
| SHA-256 | `7e11803667f85980f2d35b35c7474b19987936101f3b9564472017cc5858370c` |
| Size | 36,548,360 bytes |
| `classes.jar` | `8f1849333170c09c3e874c740bfc932a89adb177f454d131cf7caa86d5741400` (12,290 B) |
| ABIs | `arm64-v8a`, `armeabi-v7a`, `x86_64` |
| `minSdkVersion` | 26 |

| ABI | `libgojni.so` SHA-256 | Size | ELF |
|---|---|---|---|
| arm64-v8a | `990c84db1bb4142dcf68e1f112317d00b794719713f26680293eb1997b217ecd` | 32,582,984 | ELF64 DYN, AArch64 |
| armeabi-v7a | `18ac04444292b0e4a37b7d0a1b05105a5de13905cd5f2652df2e706e5c592ff1` | 31,331,504 | ELF32 DYN, ARM EABI5 |
| x86_64 | `ddb62423c7d4049ba860315f0b69f108b601897a4b6a82297687b58e08955cd6` | 34,766,472 | ELF64 DYN, x86-64 |

All three are `built by NDK r30 (16248370)`, `for Android 26`, stripped ([ELF headers](<agent-rivet-aar-20261106/evidence/artifacts/elf/summary.txt>)). AAR entries: `AndroidManifest.xml`, `proguard.txt`, `classes.jar`, three `jni/<abi>/libgojni.so`, `R.txt`, `res/`.

`javap app.xio.mobile.Mobile` on the fresh `classes.jar` contains — verbatim from [fresh-javap.txt](<agent-rivet-aar-20261106/evidence/artifacts/surface/fresh/fresh-javap.txt>):

```text
public static native void cancelConnect();
public static native void stopWithTimeout(long) throws java.lang.Exception;
public static native java.lang.String connectPolicyTimeout(java.lang.String, app.xio.mobile.Protector, long, java.lang.String) throws java.lang.Exception;
public static native java.lang.String connectionPolicyMode(java.lang.String) throws java.lang.Exception;
```

## Recipe (found, not invented) and ABIs

The project's canonical AAR producer is `tools/build-rivet.py` (lines 20–23): a private Go copy prepared by `tools/prepare-mobile-go.py` (Go 1.27.3 with the CLOCK_BOOTTIME assembly patch for arm/arm64/amd64) and:

```sh
cd protocol/rivet
gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi 26 -trimpath \
  '-ldflags=-s -w' -javapkg app.xio -o app/android/app/libs/rivet.aar ./mobile
```

The recipe's ABIs are therefore exactly **arm64-v8a, armeabi-v7a, x86_64** — corroborated independently by `tools/build-amneziawg.py:48-50` and `tools/build-openvpn.py:20` (same three ABIs) and `tools/check-native-payload.py` (`jni/<abi>/libgojni.so`). No export surface was added or changed. The earlier EA891/C946 preflight built **arm64 only**; this round follows the release recipe and builds all three.

Executed command line: [native-command.txt](<agent-rivet-aar-20261106/evidence/logs/native-command.txt>), exit **0** ([native-bind-exit.txt](<agent-rivet-aar-20261106/evidence/logs/native-bind-exit.txt>)). Offline environment: `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2`, `GOFLAGS='-mod=readonly -p=1'`, owned `GOCACHE`/`GOMODCACHE`/`GOPATH`/`HOME`/`TMPDIR`/`XDG_*`; module supply was the host's cached download archives only (copied, never network).

## Exact source snapshot and input hashes

| Item | Value |
|---|---|
| MAIN commit | `595def6ab24590002458c0a5fa4f8020d5c8a86f` |
| Snapshot command | `git archive --format=tar 595def6a app client CONTRIBUTING.md docs legal patches protocol tooling tools vendor vendor-metadata` run in `work/repo-merge` |
| Archive SHA-256 | `27148ceb51225e5f60894952e469a116ede930e41a310ee342c8192edd95b904` |
| Archive size | 220,733,440 bytes (kept read-only) |
| Extracted files | 2,598 |

The archive hash was identical before and after transfer. `protocol`, `vendor`, `tools`, `tooling` tree ids equal the historical EA891/C946 ones (`31f1a7d4…`, `c32b7204…`, `24386867…`, `c8ca36cf…`); the only MAIN delta vs C946 is server-side (`server/managed/admin.py`, `server/webui/*`).

The exact `gomobile` input set — **1,842 files** under `protocol/`, `vendor/`, `tools/`, `tooling/` — hashes to aggregate `d0dcd5926a9a09ef0c4e7b5311aedaef7209e532679fc15dc2ff2646b414c20a` and is **byte-identical to the historical EA891 inputs** (independent comparison, exit 0). `go.mod` `37db580b…`, `go.sum` `15234f1d…`, `app/pubspec.lock` `f1dd7110…` (unchanged). The 1,842-file recheck was repeated **after** both compiles and still matches ([final-integrity.json](<agent-rivet-aar-20261106/evidence/logs/final-integrity.json>)).

## Toolchain

Go 1.27.3 (`linux/amd64`), private patched copy verified by its `.xio-patched` marker; `gomobile` `d94feb54…` and `gobind` `95d48502…`, both from `golang.org/x/mobile v0.0.0-20261011034528-197770444867` (the module pin); NDK 30.0.16248370 (r30); Android SDK 36; JDK 21.0.13; Gradle 9.3.1; AGP 9.1.0; Kotlin Android plugin 2.4.0; Flutter 3.47.7 (`abaf9c5237…`), Dart 3.13.5. Receipts: [native](<agent-rivet-aar-20261106/evidence/logs/toolchain-native.txt>), [bind provenance](<agent-rivet-aar-20261106/evidence/logs/toolchain-bind-provenance.txt>), [compile](<agent-rivet-aar-20261106/evidence/logs/toolchain-compile.txt>).

## Compiler proof (new AAR substituted in my own tree)

```sh
gradle --offline --no-daemon --no-build-cache --max-workers=1 \
  '-Dorg.gradle.jvmargs=-Xmx1536m -XX:MaxMetaspaceSize=512m' \
  '-Pkotlin.daemon.jvmargs=-Xmx1024m' \
  :app:compileDebugKotlin :app:compileDebugJavaWithJavac \
  -Ptarget-platform=android-arm64 \
  -x :app:compileFlutterBuildDebug -x :app:mergeDebugAssets
# Client adds: -Pdart-defines=WElPX0NMSUVOVF9PTkxZPXRydWU= -Ptarget=lib/client_main.dart
```

Runs were strictly serial inside my worker (`--no-daemon`, one Gradle process at a time) with `--no-build-cache`. Execution — not directory cleanup — is the evidence: in the two fresh-AAR logs, both `:app:compileDebugKotlin` and `:app:compileDebugJavaWithJavac` appear **without** `UP-TO-DATE`/`FROM-CACHE`. The two stale-AAR negative controls stop at `:app:compileDebugKotlin FAILED`; application Javac does not run in those controls. The AAR SHA-256 was recorded per run. (Housekeeping detail, stated to avoid over-claiming: the per-run `rm -rf` targeted `src/app/android/app/build`, while the effective output root is `src/app/build`; no result depends on that cleanup, because the changed AAR input and `--no-build-cache` forced real recompilation, as the task lines and per-run AAR receipts show.)

| | Full | Client |
|---|---|---|
| Exit | **0** | **0** |
| Duration | 71 s | 60 s |
| `:app:compileDebugKotlin` | executed (not UP-TO-DATE) | executed (not UP-TO-DATE) |
| `:app:compileDebugJavaWithJavac` | executed | executed |
| Generated `APPLICATION_ID` | `app.xio.xio` | `app.xio.client` |
| Generated `CLIENT_ONLY` | `false` | `true` |
| Application `.class` outputs | 98 | 98 |
| Compiler diagnostics (`^e: `/`error:`) | 0 | 0 |

Both modes compiled against the AAR whose SHA-256 was recorded at run time as `7e118036…` ([full](<agent-rivet-aar-20261106/evidence/logs/fresh-full-aar.txt>), [client](<agent-rivet-aar-20261106/evidence/logs/fresh-client-aar.txt>)). Generated BuildConfig hashes match the previous historical runs (`21e4a9c6…` Full, `8cefcb10…` Client), and `MainActivity.class` hashes match the accepted C7 bytecode (`4ac50cba…` / `0570cde7…`). Logs: [full gradle](<agent-rivet-aar-20261106/evidence/logs/fresh-full-gradle.txt>), [client gradle](<agent-rivet-aar-20261106/evidence/logs/fresh-client-gradle.txt>), audits [full](<agent-rivet-aar-20261106/evidence/logs/fresh-full-audit.txt>) / [client](<agent-rivet-aar-20261106/evidence/logs/fresh-client-audit.txt>).

## Negative control (old `cfc336c9…` AAR, same command, same tree)

| | Full | Client |
|---|---|---|
| Exit | **1** | **1** |
| Duration | 656 s | 585 s |
| Result | `:app:compileDebugKotlin` FAILED | `:app:compileDebugKotlin` FAILED |

Identical real compiler errors in both modes ([full](<agent-rivet-aar-20261106/evidence/logs/stale-full-errors.txt>), [client](<agent-rivet-aar-20261106/evidence/logs/stale-client-errors.txt>)):

```text
MainActivity.kt:60:50  Unresolved reference 'cancelConnect'.
MainActivity.kt:198:22 Unresolved reference 'stopWithTimeout'.
RivetBackend.kt:16:61  Unresolved reference 'stopWithTimeout'.
RivetBackend.kt:30:33  Unresolved reference 'connectPolicyTimeout'.
RivetBackend.kt:49:30  Unresolved reference 'cancelConnect'.
RivetBackend.kt:31:17  Unresolved reference 'optBoolean'.
RivetBackend.kt:31:48  Unresolved reference 'optString'.
```

`javap` on the stale `classes.jar` (`c2493dbd…`) contains none of the three methods. The `optBoolean`/`optString` lines are the known cascading inference errors and disappear with the fresh binding without any source edit.

## Reproducibility — what is and is not established

- **Proven fact:** the fresh `classes.jar` is **byte-identical** (`8f184933…`) to the historical EA891 arm64 binding's `classes.jar`, i.e. the generated Java API surface reproduces exactly.
- **Not established:** byte-identity of the native libraries to the historical build. The fresh arm64 `.so` is `990c84db…`, the historical one `777c70cf…`. A **confirmed contributor** is that Go records replace-directive absolute paths in build info and those embed the build root: the fresh libs contain `/srv/archives/agent-rivet-aar-20261106/src/…`, the historical ones `/srv/archives/agent-android-compile-preflight-20261106/src/…`. Complete binary equivalence/reproducibility of the `.so` was **not** established, and this non-identity is specific to this pair of builds — it is not a general claim about AAR reproducibility. Every other build input was verified byte-identical.

## Integrity of the owned tree

[final-integrity.json](<agent-rivet-aar-20261106/evidence/logs/final-integrity.json>): the source archive is unchanged; among the 2,598 archived files exactly **one** differs — `app/android/app/libs/rivet.aar` `cfc336c9…` → `7e118036…`; nothing was removed; 439 added files are generated build outputs, `app/.flutter-plugins-dependencies`, `local.properties` (both non-committed scaffolding) and Gradle intermediates. The artifact in `fresh-binding/` is unchanged after the compiles and equals the file placed in the tree. No product Kotlin/Java/Go/build script was edited.

## Limits

- No APK/AAB, no signing, no install, no device, no runtime, no route/VPN/system-service behaviour.
- Dart compilation and asset merging excluded (`-x :app:compileFlutterBuildDebug -x :app:mergeDebugAssets`); Dart/assets/pubspec untouched.
- Only arm64-v8a, armeabi-v7a and x86_64 were built and claimed; no other ABI is claimed.
- OpenVPN/AmneziaWG JNI rebuilds, separate Client manifest/assets staging and macOS/iOS are out of scope.
- The repository's committed AAR was not replaced; integration is a separate decision.

## Evidence map

Canonical host tree `/srv/archives/agent-rivet-aar-20261106/` (833 GiB mount; root FS untouched). Local copies in this workspace: [artifact](<agent-rivet-aar-20261106/artifacts/rivet-fresh-595def6a-allabi.aar>), [evidence bundle](<agent-rivet-aar-20261106/evidence-bundle.tar.gz>) (`e70c1c77…`), extracted [evidence](<agent-rivet-aar-20261106/evidence>), [provenance.json](<agent-rivet-aar-20261106/evidence/artifacts/provenance.json>), [SHA256SUMS](<agent-rivet-aar-20261106/evidence/artifacts/SHA256SUMS>).
