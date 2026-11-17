#!/bin/sh
set -u
root=/srv/archives/agent-server-contract-fixes-20261105
cd "$root/src" || exit 1
export TMPDIR="$root/tmp" XDG_CACHE_HOME="$root/cache" PYTHONDONTWRITEBYTECODE=1
python3 -B -m unittest discover -s server/managed -v > "$root/managed-after.txt" 2>&1
rc=$?
printf '\nEXIT=%s\n' "$rc" >> "$root/managed-after.txt"
printf 'managed exit=%s\n' "$rc"
exit "$rc"
