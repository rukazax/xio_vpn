#!/bin/bash
set -u
B=/srv/archives/agent-review-rivet-aar-20261106
export HOME="$B/home" TMPDIR="$B/tmp" TMP="$B/tmp" TEMP="$B/tmp" XDG_CACHE_HOME="$B/xdg/cache" XDG_CONFIG_HOME="$B/xdg/config" XDG_DATA_HOME="$B/xdg/data" GRADLE_USER_HOME="$B/gradle" PUB_CACHE="$B/pub-cache"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2 GOCACHE="$B/go-cache" GOMODCACHE="$B/go-mod" GOPATH="$B/go-path"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
export PATH="$JAVA_HOME/bin:/opt/go1.27.3/bin:$PATH"
export JAVA_TOOL_OPTIONS="-Duser.home=$HOME -Djava.io.tmpdir=$TMPDIR"
G=(/root/.gradle/wrapper/dists/gradle-9.3.1-all/*/gradle-9.3.1/bin/gradle)
{ java -version; /opt/flutter/bin/cache/dart-sdk/bin/dart --version; go version; git -C /opt/flutter rev-parse HEAD; } > "$B/logs/toolchain.txt" 2>&1
cd "$B/src/app/android"
for mode in full client; do
 args=()
 if [ "$mode" = client ]; then args+=('-Pdart-defines=WElPX0NMSUVOVF9PTkxZPXRydWU=' '-Ptarget=lib/client_main.dart'); fi
 cmd=("${G[0]}" --offline --no-daemon --no-build-cache --max-workers=1 '-Dorg.gradle.jvmargs=-Xmx1536m -XX:MaxMetaspaceSize=512m' '-Pkotlin.daemon.jvmargs=-Xmx1024m' :app:compileDebugKotlin :app:compileDebugJavaWithJavac -Ptarget-platform=android-arm64 -x :app:compileFlutterBuildDebug -x :app:mergeDebugAssets "${args[@]}")
 printf '%q ' "${cmd[@]}" > "$B/logs/$mode-command.txt"
 sha256sum "$B/src/app/android/app/libs/rivet.aar" > "$B/logs/$mode-aar-before.txt"
 "${cmd[@]}" > "$B/logs/$mode-gradle.txt" 2>&1
 rc=$?; echo "$rc" > "$B/logs/$mode-exit.txt"
 sha256sum "$B/src/app/android/app/libs/rivet.aar" > "$B/logs/$mode-aar-after.txt"
 if [ "$rc" = 0 ]; then python3 "$B/audit.py" "$mode" > "$B/logs/$mode-output-audit.txt" 2>&1; echo "$?" > "$B/logs/$mode-audit-exit.txt"; fi
done
python3 "$B/audit.py" finalize > "$B/logs/finalize.txt" 2>&1
