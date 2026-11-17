# Independent review — fresh RIVET all-ABI AAR — 2026-11-06

## Verdict

**SCOPED ACCEPT** of [the candidate AAR](<agent-rivet-aar-20261106/artifacts/rivet-fresh-595def6a-allabi.aar>) with SHA-256 **`7e11803667f85980f2d35b35c7474b19987936101f3b9564472017cc5858370c`**, **36,548,360 bytes**, as the replacement candidate for the stale bundled binding at exact source **`595def6ab24590002458c0a5fa4f8020d5c8a86f`**.

Independent source/payload checks and **new actual Full + Client Kotlin/Javac executions in the reviewer's own tree PASS**. No blocking finding remains in this scope. This review **does not perform the replacement or merge**.

**NOT APK/AAB, release, signing, install, device, VPN, native-runtime or screenshot-behavior acceptance.** Compiler replay selects arm64 and excludes Dart/assets; static payload inspection covers all three ABIs. No gomobile rebuild or duplicate stale negative compilation was performed. **Future manual-mode Kotlin composition must receive a separate real compiler run against its exact composed source.** This receipt must not be applied automatically to that future branch.

## Independent source/provenance verification

1. Re-created a new archive directly from Git, not from the author's tree:

   ```sh
   git archive --format=tar 595def6ab24590002458c0a5fa4f8020d5c8a86f \
     app client CONTRIBUTING.md docs legal patches protocol tooling tools vendor vendor-metadata
   ```

   [Own immutable archive](<review-rivet-aar-20261106/source-595.tar>) SHA-256 **`27148ceb51225e5f60894952e469a116ede930e41a310ee342c8192edd95b904`** — byte-identical to the author's pinned archive. Both hashes were independently checked on Debian.
2. Compared **all 1,842 actual files** under the author's protocol/vendor/tools/tooling against the own Git archive SHA manifest. Every file matched; this input mapping also matches the historical EA891 manifest. Checked actual files, not only the author's summary. C946→595 diff over app/protocol/vendor/tools/tooling is empty.
3. Read the canonical source recipe and author's [executed native command](<agent-rivet-aar-20261106/evidence/logs/native-command.txt>), [binary/toolchain provenance](<agent-rivet-aar-20261106/evidence/logs/toolchain-bind-provenance.txt>) and raw compiler evidence. The recipe targets arm64/arm/amd64 at API26 with private Go1.27.3 CLOCK_BOOTTIME preparation. The standalone `gomobile version` probe in the author log cannot identify a version outside a Go module; actual binary `go version -m` records the pinned x/mobile version. This is not treated as a successful version probe.
4. Independently read embedded Go build information from **all three candidate SOs**: Go1.27.3, generated gobind module and author-root local replacements are present. [arm64 build info](<review-rivet-aar-20261106/logs/arm64-v8a-go-buildinfo.txt>), [ARM build info](<review-rivet-aar-20261106/logs/armeabi-v7a-go-buildinfo.txt>), [x86-64 build info](<review-rivet-aar-20261106/logs/x86_64-go-buildinfo.txt>).
5. Verified the author's private Go patch marker and all three patched runtime assembly file hashes against the previously independently checked private Go copy. Seven sampled toolchain hashes also match the historical baseline. [Patch receipt](<review-rivet-aar-20261106/logs/private-go-patch-check.json>), [toolchain hash receipt](<review-rivet-aar-20261106/logs/toolchain-hash-check.json>).

The [independent payload/input receipt](<review-rivet-aar-20261106/logs/independent-input-payload-check.json>) records these checks. Native build execution itself remains the author's evidenced build; the verifier did **not** rebuild it or claim independent native reproducibility.

## Independent payload/API/ABI verification

- Exact candidate SHA/size verified on Windows, after transfer into the own Debian root, and against the author's artifact.
- ZIP CRC: PASS; eight unique entries, exactly the expected three JNI libraries; no duplicate entries or extra ABI.
- Manifest declares minimum Android API26.
- Real extracted classes JAR: **`8f1849333170c09c3e874c740bfc932a89adb177f454d131cf7caa86d5741400`**, identical to the earlier accepted Java binding.
- Own [javap output](<review-rivet-aar-20261106/logs/javap-Mobile.txt>) includes `cancelConnect()`, `stopWithTimeout(long)`, `connectPolicyTimeout(String,Protector,long,String)` and `connectionPolicyMode(String)`.
- All four matching `Java_app_xio_mobile_Mobile_*` JNI exports are defined GLOBAL functions, **not undefined symbols**, in **each** SO: [arm64](<review-rivet-aar-20261106/logs/arm64-v8a-jni-api-exports.json>), [ARM](<review-rivet-aar-20261106/logs/armeabi-v7a-jni-api-exports.json>), [x86-64](<review-rivet-aar-20261106/logs/x86_64-jni-api-exports.json>).

| ABI | SO SHA-256 | Bytes | Independently read ELF |
|---|---|---:|---|
| arm64-v8a | `990c84db1bb4142dcf68e1f112317d00b794719713f26680293eb1997b217ecd` | 32,582,984 | ELF64 DYN, machine183, LOAD alignment0x4000 |
| armeabi-v7a | `18ac04444292b0e4a37b7d0a1b05105a5de13905cd5f2652df2e706e5c592ff1` | 31,331,504 | ELF32 DYN, machine40, LOAD alignment0x1000 |
| x86_64 | `ddb62423c7d4049ba860315f0b69f108b601897a4b6a82297687b58e08955cd6` | 34,766,472 | ELF64 DYN, machine62, LOAD alignment0x4000 |

[arm64 readelf](<review-rivet-aar-20261106/logs/arm64-v8a-readelf.txt>), [ARM readelf](<review-rivet-aar-20261106/logs/armeabi-v7a-readelf.txt>), [x86-64 readelf](<review-rivet-aar-20261106/logs/x86_64-readelf.txt>) also show Android26/r30/16248370 notes. These are static ELF facts, not an installation/package-alignment or runtime-loader test.

**Non-reproducibility limitation:** native bytes differ from the historical arm64-only build. Embedded absolute replacement paths are observed, but this review does **not** establish that paths are the only difference or prove native semantic/binary equivalence. Exact reproduction is established only for the Java classes JAR. No stronger causal claim is needed for this compiler-level acceptance.

## New independent real compiler replay

Fresh source/output root: `/srv/archives/agent-review-rivet-aar-20261106`. No author build outputs were reused. Both modes ran serially with the exact candidate installed **only in the reviewer's extracted source**.

```sh
gradle --offline --no-daemon --no-build-cache --max-workers=1 \
  '-Dorg.gradle.jvmargs=-Xmx1536m -XX:MaxMetaspaceSize=512m' \
  '-Pkotlin.daemon.jvmargs=-Xmx1024m' \
  :app:compileDebugKotlin :app:compileDebugJavaWithJavac \
  -Ptarget-platform=android-arm64 \
  -x :app:compileFlutterBuildDebug -x :app:mergeDebugAssets
# Client adds:
# -Pdart-defines=WElPX0NMSUVOVF9PTkxZPXRydWU= -Ptarget=lib/client_main.dart
```

| Replay fact | Full | Client |
|---|---|---|
| Exit | **0** | **0** |
| Duration | 6m30s | 10m6s |
| App Kotlin compiler | Executed; PASS | Executed; PASS |
| App Javac compiler | Executed; PASS | Executed; PASS |
| Tasks executed / up-to-date | 31 / 1 | 6 / 26 |
| Application class files | 98 | 98 |
| Generated application ID | `app.xio.xio` | `app.xio.client` |
| Generated `CLIENT_ONLY` | false | true |
| Output identity audit exit | 0 | 0 |

Application Kotlin and Javac task lines have **neither UP-TO-DATE nor FROM-CACHE** in either run. This checks all **19 Kotlin + 47 Java application main-source files** with real dependencies, including Engine and native wrappers. No stub or substituted dependency version was used. Long elapsed times were retained, not hidden or shortened by reruns.

- [Full command](<review-rivet-aar-20261106/logs/full-command.txt>), [Full raw log](<review-rivet-aar-20261106/logs/full-gradle.txt#L107-L120>), [exit](<review-rivet-aar-20261106/logs/full-exit.txt>).
- [Client command](<review-rivet-aar-20261106/logs/client-command.txt>), [Client raw log](<review-rivet-aar-20261106/logs/client-gradle.txt#L77-L87>), [exit](<review-rivet-aar-20261106/logs/client-exit.txt>).
- Per-run candidate SHA is **7e118036… before and after both runs**: [Full before](<review-rivet-aar-20261106/logs/full-aar-before.txt>), [Full after](<review-rivet-aar-20261106/logs/full-aar-after.txt>), [Client before](<review-rivet-aar-20261106/logs/client-aar-before.txt>), [Client after](<review-rivet-aar-20261106/logs/client-aar-after.txt>).

Saved immediately per mode:

| Output | Full SHA-256 | Client SHA-256 |
|---|---|---|
| BuildConfig | `21e4a9c6ee212b98f4d30b47322a5ac907f8cf40e6305dff353fc89767bb2008` | `8cefcb10b89a8acdb4ab71807fbaf7123c5cecf3bb274166447e5da7197be210` |
| MainActivity.class | `4ac50cba4dc3ba0e8716b7c500b5ee7965b7075097e43dfa2c6f11299dce7d00` | `0570cde798e699f5db8346d57e11163433c440b4becfef3293d6fb9434db5a0e` |

[Full BuildConfig](<review-rivet-aar-20261106/logs/full-BuildConfig.java>), [Client BuildConfig](<review-rivet-aar-20261106/logs/client-BuildConfig.java>), [Full class manifest](<review-rivet-aar-20261106/logs/full-compiled-classes.json>), [Client class manifest](<review-rivet-aar-20261106/logs/client-compiled-classes.json>). These output identities reproduce the accepted C7 results.

## Negative evidence and documentation finding

Re-inspected the stale AAR hash `cfc336c936c06f0d08b73fca77768f31a23afcb7f915354e5d78e61995e27de7` and independently extracted its [old API](<review-rivet-aar-20261106/logs/stale-Mobile-api.txt>): the three required methods are absent. Read author's [Full negative log](<agent-rivet-aar-20261106/evidence/logs/stale-full-gradle.txt#L119-L128>) and [Client negative log](<agent-rivet-aar-20261106/evidence/logs/stale-client-gradle.txt#L77-L95>): actual Kotlin failure on those methods plus cascading JSONObject diagnostics. **Did not rerun these expensive negative compiles.**

Identified a nonblocking documentation error: the author's original line82 incorrectly described both app compilers executing in all four logs. Negative controls stop at Kotlin FAILED; application Javac does not execute. Parent corrected the [author report](<ANDROID-RIVET-AAR-20261106.md#L82>); reviewer re-read the corrected wording. Raw logs unchanged. **Not a product defect.**

## Integrity, resource boundaries and completion

[Pre manifest](<review-rivet-aar-20261106/source-pre.json>) / [post manifest](<review-rivet-aar-20261106/source-post.json>) cover **2,598 archived files**. [Final integrity receipt](<review-rivet-aar-20261106/logs/hash-verification.json>) reports only the allowed owned-tree AAR delta `cfc336… → 7e118036…`; all source Kotlin/Java/Go/build scripts and immutable archive remain unchanged. Generated scaffolding/build outputs are additional owned files. No reviewer write to main or author trees, no merge/replacement.

Drivers: [setup/payload verifier](<review-rivet-aar-20261106/setup.py>), [compiler](<review-rivet-aar-20261106/compile.sh>), [class/source audit](<review-rivet-aar-20261106/audit.py>), [extra provenance/JNI/old API verifier](<review-rivet-aar-20261106/extra-provenance.py>). Extra verifier exit **0**; [receipt](<review-rivet-aar-20261106/extra-provenance-exit.txt>).

HOME/TMP/XDG/Gradle/Go paths configured under owned archive storage; controlled reuse of the reviewer's own historical Gradle dependency cache only. Fresh copied Gradle tooling and integration_test plugin prevent shared SDK build writes. API36/JDK21.0.13/Gradle9.3.1/Kotlin2.4/AGP9.1, existing Flutter3.47.7/Dart3.13.5 resources. `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2`; no downloads/install, SDK/global Git/security changes, device/VPN/service/credential actions. No manual provider/model switch was performed; runtime identifies gpt-6-astra.

At start no other Gradle/Kotlin/gomobile process was present and 5.5GiB RAM was available; later check showed 4.8GiB available. Runs stayed single-worker/serial; no duplication or forced restart. Both background jobs were collected. **Final integration remains the parent's separate action; future composed manual-mode sources require a new compiler receipt.**
