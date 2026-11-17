#!/bin/bash
# Fresh rivet.aar from the exact MAIN snapshot, using the project's own recipe.
set -u
B=/srv/archives/agent-rivet-aar-20261106
export HOME="$B/home" TMPDIR="$B/tmp" TMP="$B/tmp" TEMP="$B/tmp"
export XDG_CACHE_HOME="$B/xdg/cache" XDG_CONFIG_HOME="$B/xdg/config" XDG_DATA_HOME="$B/xdg/data"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2
export GOCACHE="$B/go-cache" GOMODCACHE="$B/go-mod" GOPATH="$B/go-path" GOFLAGS='-mod=readonly -p=1' GOTELEMETRY=off
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk ANDROID_NDK_HOME=/opt/android-sdk/ndk/30.0.16248370
export JAVA_TOOL_OPTIONS="-Duser.home=$HOME -Djava.io.tmpdir=$TMPDIR"
mkdir -p "$GOMODCACHE/cache" "$B/fresh-binding" "$B/logs" "$B/artifacts"

# Offline Go module supply: cached download archives only (no network).
if [ ! -d "$GOMODCACHE/cache/download" ]; then
  cp -a /root/go/pkg/mod/cache/download "$GOMODCACHE/cache/"
fi

# Private Go with the project's Android CLOCK_BOOTTIME assembly semantics.
python3 "$B/src/tools/prepare-mobile-go.py" /opt/go1.27.3 "$B/go-private" > "$B/logs/go-private.txt" 2>&1
rc=$?; echo "$rc" > "$B/logs/go-private-exit.txt"
[ "$rc" = 0 ] || exit "$rc"
export GOROOT="$B/go-private"
export PATH="$B/go-private/bin:/root/go/bin:$JAVA_HOME/bin:/usr/local/bin:/usr/bin:/bin"

{
  echo "== go =="; "$GOROOT/bin/go" version
  echo "== gomobile =="; command -v gomobile; gomobile version 2>&1
  echo "== gobind =="; command -v gobind; ls -l "$(command -v gobind)"
  echo "== ndk =="; cat "$ANDROID_NDK_HOME/source.properties"
  echo "== java =="; java -version 2>&1
  echo "== go env =="; "$GOROOT/bin/go" env GOOS GOARCH GOROOT GOPATH GOMODCACHE GOCACHE CGO_ENABLED GOPROXY GOFLAGS
} > "$B/logs/toolchain-native.txt" 2>&1

cd "$B/src/protocol/rivet" || exit 1
CMD=(gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi 26 -trimpath '-ldflags=-s -w' -javapkg app.xio -o "$B/fresh-binding/rivet.aar" ./mobile)
printf '%q ' "${CMD[@]}" > "$B/logs/native-command.txt"
echo >> "$B/logs/native-command.txt"
"${CMD[@]}" > "$B/logs/native-bind.txt" 2>&1
rc=$?
echo "$rc" > "$B/logs/native-bind-exit.txt"
exit "$rc"
