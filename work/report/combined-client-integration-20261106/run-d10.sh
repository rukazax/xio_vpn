#!/bin/bash
set -eu
b=/srv/archives/agent-combined-client-review-20261106
f="$b/d10"
mkdir -p "$f"/{source,home,tmp,cache,data,config}
tar -xf "$b/d10-source.tar" -C "$f/source"
export HOME="$f/home" TMPDIR="$f/tmp" XDG_CACHE_HOME="$f/cache" XDG_DATA_HOME="$f/data" XDG_CONFIG_HOME="$f/config" PUB_CACHE="$b/pub-cache" TTL_ROOT="$f" CI=true FLUTTER_SUPPRESS_ANALYTICS=true DART_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
sha256sum "$b/d10-source.tar" > "$f/archive-before.sha256"
cd "$f/source"
find app/lib app/test app/assets app/android tools work/report -type f -print0 | sort -z | xargs -0 sha256sum > "$f/source-before.sha256"
python3 - <<'PY' > "$f/repair-identity.log"
from pathlib import Path
import hashlib,json
b=Path('/srv/archives/agent-combined-client-review-20261106')
a=b/'followup/source';z=b/'d10/source'
old={line.split('  ',1)[1]:line.split('  ',1)[0] for line in (b/'followup/source-before.sha256').read_text().splitlines()}
new={line.split('  ',1)[1]:line.split('  ',1)[0] for line in (b/'d10/source-before.sha256').read_text().splitlines()}
assert old.keys()==new.keys()
changed=[p for p in old if old[p]!=new[p]]
assert len(changed)==13,changed
wanted={'Превышено время подключения (30 с)','Отключение VPN не завершено'}
def unique(pairs):
 d={}
 for k,v in pairs:
  assert k not in d,k
  d[k]=v
 return d
for p in changed:
 assert p.startswith('app/assets/l10n/')
 x=json.loads((a/p).read_text(),object_pairs_hook=unique)
 y=json.loads((z/p).read_text(),object_pairs_hook=unique)
 assert y.keys()-x.keys()==wanted
 assert x.keys()-y.keys()==set()
 assert all(y[k]==v for k,v in x.items())
 assert all(y[k].strip() for k in wanted)
 print('EXPECTED_ONLY_CHANGE',p)
print('PASS13 catalogue changes/exact26 cells; unique keys/all prior values unchanged; other761 archived files identical')
s=(z/'app/test/l10n_test.dart').read_text();helpers=s[s.index('class _Literal {'):]
(b/'d10/missing-keys.dart').write_text((b/'missing-keys-main.dart').read_text()+helpers)
print('unchanged diagnostic helper suffix SHA256',hashlib.sha256(helpers.encode()).hexdigest())
PY
run() { name=$1; shift; printf '%s ' "$@" >> "$f/commands.log"; printf '\n' >> "$f/commands.log"; set +e; "$@" > "$f/$name.log" 2>&1; rc=$?; set -e; echo "$name=$rc" | tee -a "$f/results.log"; }
cd app
run pub /opt/flutter/bin/flutter --no-version-check pub get --offline
mapfile -t files < "$b/test-selection.txt"
printf '%s\n' "${files[@]}" > "$f/test-selection.txt"
run flutter /opt/flutter/bin/flutter --no-version-check test --no-pub --concurrency=2 --reporter expanded --timeout 60s "${files[@]}"
run analyzer /opt/flutter/bin/flutter --no-version-check analyze --no-pub lib/core.dart lib/routing_domains.dart lib/managed_models.dart lib/managed_service.dart lib/subclients.dart lib/app_settings.dart lib/credentials.dart lib/desktop_engine.dart
run missing-keys /opt/flutter/bin/cache/dart-sdk/bin/dart "$f/missing-keys.dart"
cd "$f/source"
run source-after sha256sum -c "$f/source-before.sha256"
cd /root/.pub-cache
run cache-after sha256sum -c "$b/cache-before.sha256"
sha256sum "$b/d10-source.tar" > "$f/archive-after.sha256"
