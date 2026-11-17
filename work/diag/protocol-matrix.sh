#!/bin/bash
# Drives the test build through adb. Results are the app's own `TEST {...}`
# lines, mirrored to logcat by the native Diag logger.
set -u
PKG=${PKG:-app.xio.xio}
WAIT=${WAIT:-45}

send() {
  # URL-safe base64: `adb shell` re-parses arguments and strips JSON quotes.
  local payload
  payload=$(printf %s "$1" | base64 -w0 | tr '+/' '-_')
  adb shell am start -n "$PKG/.MainActivity" --es xioTest64 "$payload" >/dev/null 2>&1 || return 1
}

# run <json> [timeout_seconds] -> prints the last TEST payload
run() {
  local json=$1 timeout=${2:-$WAIT}
  adb logcat -c >/dev/null 2>&1
  send "$json" || { echo '{"ok":false,"error":"am start failed"}'; return 1; }
  local started=$SECONDS
  while (( SECONDS - started < timeout )); do
    local line
    line=$(adb logcat -d -s XIO:I 2>/dev/null | grep -o 'TEST {.*}' | tail -1)
    if [[ -n $line ]]; then echo "${line#TEST }"; return 0; fi
    sleep 1
  done
  echo '{"ok":false,"error":"timeout waiting for app"}'
  return 1
}

case ${1:-} in
  profiles) run '{"action":"profiles"}' 20 ;;
  status)   run '{"action":"status"}' 20 ;;
  connect)  run "{\"action\":\"connect\",\"protocol\":\"$2\"}" "${3:-$WAIT}" ;;
  switch)   run "{\"action\":\"switch\",\"protocol\":\"$2\"}" "${3:-$WAIT}" ;;
  disconnect) run '{"action":"disconnect"}' 30 ;;
  http)     run "{\"action\":\"http\",\"url\":\"${2:-https://api.ipify.org?format=json}\"}" 25 ;;
  awg)      run '{"action":"awg"}' 20 ;;
  wait)     run "{\"action\":\"wait\",\"ms\":${2:-2000}}" 20 ;;
  raw)      run "$2" "${3:-$WAIT}" ;;
  *) echo "usage: $0 profiles|status|connect PROTO|switch PROTO|disconnect|http [URL]|awg|wait MS|raw JSON" >&2; exit 2 ;;
esac
