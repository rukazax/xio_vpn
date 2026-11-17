#!/bin/bash
# Offline Kotlin+Javac compile of Full (app.xio.xio) and Client (app.xio.client) with
# the FRESH AAR, plus the same compiles against the committed stale AAR (negative control).
# Usage: compile.sh [run ...]   (default: all four in the fixed order below)
set -u
B=/srv/archives/agent-rivet-aar-20261106
export HOME="$B/home" TMPDIR="$B/tmp" TMP="$B/tmp" TEMP="$B/tmp"
export XDG_CACHE_HOME="$B/xdg/cache" XDG_CONFIG_HOME="$B/xdg/config" XDG_DATA_HOME="$B/xdg/data"
export GRADLE_USER_HOME="$B/gradle" PUB_CACHE="$B/pub-cache"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
export PATH="$JAVA_HOME/bin:/opt/go1.27.3/bin:/usr/local/bin:/usr/bin:/bin"
export JAVA_TOOL_OPTIONS="-Duser.home=$HOME -Djava.io.tmpdir=$TMPDIR"
G=(/root/.gradle/wrapper/dists/gradle-9.3.1-all/*/gradle-9.3.1/bin/gradle)
mkdir -p "$B/logs" "$B/artifacts/surface"

{
  echo '== java =='; java -version 2>&1
  echo '== gradle =='; "${G[0]}" --version 2>&1 | head -12
  echo '== sdk/ndk =='; grep -E 'Pkg.Revision|AndroidVersion' /opt/android-sdk/ndk/30.0.16248370/source.properties /opt/android-sdk/platforms/android-36/source.properties 2>/dev/null
  echo '== flutter =='; /opt/flutter/bin/cache/dart-sdk/bin/dart --version 2>&1
  echo '== flutter revision =='; git -C /opt/flutter rev-parse HEAD
  echo '== go =='; /opt/go1.27.3/bin/go version
} > "$B/logs/toolchain-compile.txt" 2>&1

cd "$B/src/app/android" || exit 1

run() {
  local name="$1"; local aar="$2"; local mode="$3"; shift 3
  cp -f "$aar" app/libs/rivet.aar
  rm -rf app/build
  local cmd=("${G[0]}" --offline --no-daemon --no-build-cache --max-workers=1
    '-Dorg.gradle.jvmargs=-Xmx1536m -XX:MaxMetaspaceSize=512m'
    '-Pkotlin.daemon.jvmargs=-Xmx1024m'
    :app:compileDebugKotlin :app:compileDebugJavaWithJavac
    -Ptarget-platform=android-arm64
    -x :app:compileFlutterBuildDebug -x :app:mergeDebugAssets "$@")
  printf '%q ' "${cmd[@]}" > "$B/logs/$name-command.txt"; echo >> "$B/logs/$name-command.txt"
  printf 'AAR %s sha256 %s\n' "$aar" "$(sha256sum "$aar" | cut -d' ' -f1)" > "$B/logs/$name-aar.txt"
  local start; start=$(date +%s)
  "${cmd[@]}" > "$B/logs/$name-gradle.txt" 2>&1
  local rc=$?
  echo "$rc" > "$B/logs/$name-exit.txt"
  echo "$(( $(date +%s) - start ))s" > "$B/logs/$name-duration.txt"
  grep -E '(^e: |error:|Unresolved reference|FAILURE: Build failed)' "$B/logs/$name-gradle.txt" > "$B/logs/$name-errors.txt" 2>/dev/null
  if [ "$rc" = 0 ]; then
    python3 "$B/scripts/audit_run.py" "$name" "$mode" > "$B/logs/$name-audit.txt" 2>&1
    echo "$?" > "$B/logs/$name-audit-exit.txt"
  fi
  echo "$name exit=$rc duration=$(cat "$B/logs/$name-duration.txt")"
}

runs=("$@")
[ ${#runs[@]} -eq 0 ] && runs=(stale-full stale-client fresh-full fresh-client)
for name in "${runs[@]}"; do
  case "$name" in
    stale-full)   run stale-full   "$B/artifacts/stale-rivet-cfc336c9.aar" full ;;
    stale-client) run stale-client "$B/artifacts/stale-rivet-cfc336c9.aar" client -Pdart-defines=WElPX0NMSUVOVF9PTkxZPXRydWU= -Ptarget=lib/client_main.dart ;;
    fresh-full)   run fresh-full   "$B/fresh-binding/rivet.aar" full ;;
    fresh-client) run fresh-client "$B/fresh-binding/rivet.aar" client -Pdart-defines=WElPX0NMSUVOVF9PTkxZPXRydWU= -Ptarget=lib/client_main.dart ;;
    *) echo "unknown run $name" >&2; exit 2 ;;
  esac
done

# Leave the tree in the FRESH state and record it.
cp -f "$B/fresh-binding/rivet.aar" app/libs/rivet.aar
echo done
