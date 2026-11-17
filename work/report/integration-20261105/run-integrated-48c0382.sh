#!/bin/bash
set -eu
w=/srv/archives/xio-parent-integrated-48c0382-20261105b
[ ! -e "$w" ] || { echo 'owned test directory already exists'; exit 2; }
mkdir -p "$w/tmp"
export TMPDIR="$w/tmp" PYTHONDONTWRITEBYTECODE=1
root=/mnt/c/Users/er-ka/Documents/deepseek-harness/xio_vpn/work/repo-merge
out=/mnt/c/Users/er-ka/Documents/deepseek-harness/kot/_runtime/cascade-20261105
cd "$root/server/managed"
set +e
python3 -B -m unittest discover -v -p 'test_*.py' > "$w/native-tests.log" 2>&1
native=$?
cd "$root"
PYTHONPATH=tools:server/managed python3 -B -m unittest -v tools/test_native_shipping.py tools/test_package_server.py server/managed/test_update.py server/managed/test_update_ipv6.py server/managed/test_network_delta.py > "$w/shipping-tests.log" 2>&1
shipping=$?
sh -n server/managed/bootstrap.sh
shcode=$?
bash -n server/managed/bootstrap.sh
bashcode=$?
sha256sum server/managed/cascade_native.py server/managed/cascade_native_rpc.py server/managed/dualstack.py server/managed/update.py tools/package-server.py tools/test_native_shipping.py > "$w/source-hashes.txt"
cp "$w/native-tests.log" "$out/integrated-48c0382-native.log"
cp "$w/shipping-tests.log" "$out/integrated-48c0382-shipping.log"
cp "$w/source-hashes.txt" "$out/integrated-48c0382-hashes.txt"
printf 'native=%s shipping=%s sh=%s bash=%s\n' "$native" "$shipping" "$shcode" "$bashcode"
[ "$native" -eq 0 ] && [ "$shipping" -eq 0 ] && [ "$shcode" -eq 0 ] && [ "$bashcode" -eq 0 ]
