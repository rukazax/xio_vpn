set -eu
umask 077
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo 'root required' >&2; exit 1; }
. /etc/os-release
major=${VERSION_ID%%.*}
case "$ID:$major" in
 debian:12|debian:13) manager=apt ;;
 ubuntu:22|ubuntu:24|ubuntu:26)
  case "$VERSION_ID" in 22.04|24.04|26.04) manager=apt ;; *) echo 'Unsupported Ubuntu release' >&2; exit 1 ;; esac ;;
 centos:9|centos:10|rocky:9|rocky:10|almalinux:9|almalinux:10|rhel:9|rhel:10) manager=rpm ;;
 *) echo 'Unsupported OS: Debian 12/13, Ubuntu 22.04/24.04/26.04, CentOS Stream/Rocky/Alma/RHEL 9/10 required' >&2; exit 1 ;;
esac
if [ "$manager" = apt ]; then command -v apt-get >/dev/null; else command -v dnf >/dev/null; fi
[ "$(uname -m)" = x86_64 ] || { echo 'x86_64 server required' >&2; exit 1; }
[ -d /run/systemd/system ] || { echo 'systemd required' >&2; exit 1; }
[ -c /dev/net/tun ] || { echo '/dev/net/tun required' >&2; exit 1; }
command -v tar >/dev/null
lib=/usr/local/lib/xio-managed
if [ -d "$lib" ]; then
 [ "$(cat "$lib/.owner")" = xio-managed-v1 ] || exit 1
else
 [ ! -e /etc/xio-managed ] || { echo 'Unknown server data; installation refused' >&2; exit 1; }
 mkdir "$lib"
 printf 'xio-managed-v1\n' > "$lib/.owner"
fi
if [ ! -f "$lib/packages-before" ] && [ ! -f /etc/xio-managed/deployment.json ]; then
 if [ "$manager" = apt ]; then
  dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' | awk '$2=="installed"{print $1}' > "$lib/packages-before"
 else
  rpm -qa --qf '%{NAME}\n' > "$lib/packages-before"
 fi
fi
if ! command -v python3 >/dev/null || ! command -v ip >/dev/null || ! command -v ss >/dev/null; then
 if [ "$manager" = apt ]; then
  DEBIAN_FRONTEND=noninteractive apt-get update >> "$lib/bootstrap.log" 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 iproute2 ca-certificates >> "$lib/bootstrap.log" 2>&1
 else
  dnf -y install python3 iproute ca-certificates >> "$lib/bootstrap.log" 2>&1
 fi
fi
# Replace the executable atomically: an existing AWG process may still use it.
tmp=$(mktemp -d "$lib/.upload.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tar -xzf - -C "$tmp"
chmod 700 "$tmp/amneziawg-go"
mv "$tmp/admin.py" "$lib/admin.py"
mv "$tmp/client_api.py" "$lib/client_api.py"
mv "$tmp/dualstack.py" "$lib/dualstack.py"
mv "$tmp/amneziawg-go" "$lib/amneziawg-go"
chmod 755 "$tmp/rivet"
mv "$tmp/rivet" "$lib/rivet"
mv "$tmp/rivet-setup.py" "$lib/rivet-setup.py"
command -v restorecon >/dev/null && restorecon -R "$lib" || true

mv "$tmp/xraygateway" "$lib/xraygateway"
chmod 755 "$lib/xraygateway"
mv "$tmp/stack.py" "$lib/stack.py"

mv "$tmp/network_stack.py" "$lib/network_stack.py"

mv "$tmp/cloak" "$lib/cloak"
chmod 755 "$lib/cloak"

mv "$tmp/mesh_stack.py" "$lib/mesh_stack.py"
mv "$tmp/mesh-pins.json" "$lib/mesh-pins.json"

mkdir -p "$lib/xio_vici"
mv "$tmp/xio_vici/"* "$lib/xio_vici/"

# Readiness responder: answers on the tunnel gateways so clients can tell
# "the tunnel carries packets" from "some website happens to be reachable".
mv "$tmp/readiness.py" "$lib/readiness.py"
chmod 644 "$lib/readiness.py"
mv "$tmp/xio-ready.service" /etc/systemd/system/xio-ready.service
chmod 644 /etc/systemd/system/xio-ready.service
systemctl daemon-reload
systemctl enable --now xio-ready.service >> "$lib/bootstrap.log" 2>&1 || true