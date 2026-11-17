# C5 follow-up: reject missing/nonpositive native handshake

Parent-reviewed defect in original `802143503070fdd10524d4448656e38c75acad0c`: freshness comparison alone could accept zero/negative sentinels when injected wall-clock start was0/1000/2000ms near Unix epoch. Parent fixture found9 false acceptances out of12, with HTTP0. This was a deterministic boundary test, **not a host/device clock change or physical VPN claim**. Original candidate remains unaccepted pending this new follow-up's independent replay; no amendment/rebase/cherry-pick.

## Narrow change

Only production delta is [helper:35](<app/android/app/src/main/java/app/xio/xio/BackgroundVerificationOptions.java#L35>): require `observed > 0 && observed >= started - 2000` before accepting the opt-out native handshake. Same attempt/freshness/wait/cancellation checks remain. True still delegates to the unchanged combined probe; no URL, clock-design, controller, lifecycle, flags, core/DNS/routing/fallback or Engine change.

[Regression test:30–46](<app/android/app/src/test/java/app/xio/xio/BackgroundVerificationOptionsTest.java#L30-L46>) adds the12 missing/error cases (`started`0/1000/2000 × observed0/-1/-2/-3), each required to expire the original1000ms monotonic budget without HTTP. Three positive near-epoch cases must still accept a positive fresh handshake. Existing normal-positive/delayed, deadline/cancellation, typed-option, true-probe/error and fallback tests remain.

## Executed offline results

- Before helper change: new regression exit1 ([RED](<work/report/background-probe-fix-20261106/sentinel-followup/baseline-regression.log>)); unchanged parent fixture exit1,9/12 false acceptance ([RED parent replay](<work/report/background-probe-fix-20261106/sentinel-followup/baseline-parent-replay.log>)). Both compiled against actual old helper, compiler exit0.
- After change: **44 helper checks PASS**, JVM exit0 ([GREEN](<work/report/background-probe-fix-20261106/sentinel-followup/fixed-regression.log>)).
- Author replay of byte-identical [parent fixture copy](<work/report/background-probe-fix-20261106/sentinel-followup/ReviewMissingHandshake.java>): all12 `accepted=false`, HTTP0, exit0 ([GREEN parent replay](<work/report/background-probe-fix-20261106/sentinel-followup/fixed-parent-replay.log>)). Copy SHA256 verified against parent's owned original before replay; no parent artifact modified. This author replay is **not independent acceptance**.
- Original budget test exit0 ([log](<work/report/background-probe-fix-20261106/sentinel-followup/original-budget.log>)); actual tile/restore controller source wiring3/3 exit0 ([log](<work/report/background-probe-fix-20261106/sentinel-followup/wiring.log>)).
- Actual unchanged controller + unchanged combined probe + changed Java helper cached Kotlin2.2.21/API36/JVM17 compile exit0 ([log](<work/report/background-probe-fix-20261106/sentinel-followup/api36-compile.log>)); same compile-only collaborator signatures, no APK/runtime/device claim.
- Scoped Java source/test whitespace check exit0. Exact current/unchanged source and fixture hashes: [manifest](<work/report/background-probe-fix-20261106/sentinel-followup/source-sha256.txt>). The previous manifest/test counts are historical802 results, not the new helper's identity.

Commands: existing JDK21 `javac --release 17` compiles production budget/helper, updated test, original budget test and unmodified parent fixture into OWN baseline/fixed directories; `java -cp` runs the three corresponding mains. Same cached API36 replay script and Python wiring check as the original report. No downloads, HTTP/DNS probes, real waiting, clock changes, phone/VPN/OS-policy changes or Windows SAC bypass. Dart source/tests were not changed or rerun in this Java-only follow-up; their previous12+1 results remain evidence only for unchanged802 Dart bytes.

**Merge/review gate unchanged:** parent must independently replay this new helper hash and accept final N ownership/cancellation follow-up before merging the combined C5 branch. This follow-up does not accept N or itself.
