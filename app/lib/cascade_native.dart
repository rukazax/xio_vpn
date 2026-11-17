import 'dart:convert';

import 'cascade_model.dart';
import 'core.dart';

/// Two-stage native cascade installer.
///
/// This is the path that was verified on live servers, expressed as exactly two
/// stages so the app can show what it is about to do and prove each step:
///
/// 1. **exit** (foreign VPS): `tun0` 10.250.0.2/30 + fd78:2::2/64, forwarding,
///    NAT44/NAT66, `PermitTunnel yes`.
/// 2. **bridge** (RU VPS): `tun0` 10.250.0.1/30 + fd78:2::1/64, policy routing
///    for client traffic, SNAT, MSS clamp, and the `ssh -N -w 0:0` unit.
///
/// Both stages are idempotent and report evidence lines only after the state was
/// read back from the host. A stage that cannot prove its state throws
/// [CascadeStageFailure] instead of claiming success.
const String cascadeExitUpScript = r'''#!/bin/bash
# XIO cascade exit (foreign VPS): terminate SSH TUN and NAT client traffic to the Internet.
set -euo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
WAN=$(ip -4 route show default | awk '{print $5; exit}')
[ -n "$WAN" ] || { echo "no IPv4 default route" >&2; exit 1; }
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
ip tuntap add dev "$TUN" mode tun 2>/dev/null || true
ip link set "$TUN" mtu 1400 up
ip addr replace 10.250.0.2/30 dev "$TUN"
ip -6 addr replace fd78:2::2/64 dev "$TUN"
ip route replace 10.78.0.0/24 dev "$TUN"
iptables -C FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$TUN" -j ACCEPT
iptables -C FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.250.0.0/30 -o "$WAN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 10.250.0.0/30 -o "$WAN" -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.78.0.0/24 -o "$WAN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 10.78.0.0/24 -o "$WAN" -j MASQUERADE
ip6tables -C FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || ip6tables -I FORWARD 1 -i "$TUN" -j ACCEPT
ip6tables -C FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  ip6tables -I FORWARD 1 -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -t nat -C POSTROUTING -s fd78:2::/64 -o "$WAN" -j MASQUERADE 2>/dev/null || \
  ip6tables -t nat -I POSTROUTING 1 -s fd78:2::/64 -o "$WAN" -j MASQUERADE
echo "exit cascade up: $TUN -> $WAN"
''';

const String cascadeExitDownScript = r'''#!/bin/bash
set -uo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
WAN=$(ip -4 route show default | awk '{print $5; exit}')
for net in 10.250.0.0/30 10.78.0.0/24; do
  for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -s "$net" -o "$WAN" -j MASQUERADE 2>/dev/null || break; done
done
for i in $(seq 1 4); do ip6tables -t nat -D POSTROUTING -s fd78:2::/64 -o "$WAN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -D FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -D FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -D FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -D FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
ip route del 10.78.0.0/24 dev "$TUN" 2>/dev/null || true
ip link del "$TUN" 2>/dev/null || true
echo "exit cascade down"
''';

const String cascadeBridgeUpScript = r'''#!/bin/bash
# XIO cascade bridge (RU VPS): client traffic from xioawg0 -> SSH TUN -> exit VPS.
# Idempotent. No secrets in this file; the SSH key lives in /root/.ssh/xio_cascade.
set -euo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
EXIT_HOST=${XIO_CASCADE_EXIT_HOST:?XIO_CASCADE_EXIT_HOST is required}
WAN=$(ip -4 route show default | awk '{print $5; exit}')
[ -n "$WAN" ] || { echo "no IPv4 default route" >&2; exit 1; }
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
ip tuntap add dev "$TUN" mode tun 2>/dev/null || true
ip link set "$TUN" mtu 1400 up
ip addr replace 10.250.0.1/30 dev "$TUN"
ip -6 addr replace fd78:2::1/64 dev "$TUN"
ip rule add iif xioawg0 lookup 51888 priority 1000 2>/dev/null || true
ip -6 rule add iif xioawg0 lookup 51888 priority 1000 2>/dev/null || true
# Client traffic forwarded from xioawg0 is covered by the iif rule above. Traffic
# that a local transport (Xray, RIVET gateway) generates itself has no input
# interface, so it is matched by SO_MARK instead: such a socket must set
# XIO_CASCADE_MARK (default 0x518) and then leaves through the same table.
ip rule add fwmark ${XIO_CASCADE_MARK:-0x518} lookup 51888 priority 1000 2>/dev/null || true
ip route replace default dev "$TUN" table 51888
ip -6 route replace default dev "$TUN" table 51888
iptables -t nat -C POSTROUTING -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE
# Locally generated, marked traffic (Xray/RIVET egress) keeps the bridge address
# as its source, so it needs its own SNAT rule on the cascade tunnel.
iptables -t nat -C POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -o "$TUN" -j MASQUERADE
iptables -C FORWARD -i xioawg0 -o "$TUN" -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -i xioawg0 -o "$TUN" -j ACCEPT
iptables -C FORWARD -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -I FORWARD 1 -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t nat -C POSTROUTING -s fd78:1::/64 -o "$TUN" -j MASQUERADE 2>/dev/null || \
  ip6tables -t nat -I POSTROUTING 1 -s fd78:1::/64 -o "$TUN" -j MASQUERADE
ip6tables -C FORWARD -i xioawg0 -o "$TUN" -j ACCEPT 2>/dev/null || \
  ip6tables -I FORWARD 1 -i xioawg0 -o "$TUN" -j ACCEPT
ip6tables -C FORWARD -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  ip6tables -I FORWARD 1 -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  ip6tables -t mangle -I FORWARD 1 -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
echo "bridge cascade up: $TUN -> $EXIT_HOST via $WAN"
''';

const String cascadeBridgeDownScript = r'''#!/bin/bash
set -uo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
ip rule del iif xioawg0 lookup 51888 priority 1000 2>/dev/null || true
ip -6 rule del iif xioawg0 lookup 51888 priority 1000 2>/dev/null || true
ip rule del fwmark ${XIO_CASCADE_MARK:-0x518} lookup 51888 priority 1000 2>/dev/null || true
ip route flush table 51888 2>/dev/null || true
ip -6 route flush table 51888 2>/dev/null || true
for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -D FORWARD -i xioawg0 -o "$TUN" -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -D FORWARD -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -t mangle -D FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -t nat -D POSTROUTING -s fd78:1::/64 -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -D FORWARD -i xioawg0 -o "$TUN" -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -D FORWARD -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -t mangle -D FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || break; done
ip link del "$TUN" 2>/dev/null || true
echo "bridge cascade down"
''';

const String cascadeExitUnit = '''[Unit]
Description=XIO cascade exit (SSH TUN endpoint and NAT for cascade clients)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/xio-cascade-exit-up.sh
ExecStop=/usr/local/sbin/xio-cascade-exit-down.sh

[Install]
WantedBy=multi-user.target
''';

/// The bridge unit reads the exit address from the environment file, so the
/// address never becomes part of the command line or of this constant.
const String cascadeBridgeUnit = '''[Unit]
Description=XIO cascade bridge (client -> RU -> foreign exit over SSH TUN)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
EnvironmentFile=-/etc/xio-cascade/bridge.env
ExecStartPre=/usr/local/sbin/xio-cascade-bridge-up.sh
ExecStart=/usr/bin/ssh -N -w 0:0 -i /root/.ssh/xio_cascade -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes root@\${XIO_CASCADE_EXIT_HOST}
ExecStopPost=/usr/local/sbin/xio-cascade-bridge-down.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
''';

/// `PermitTunnel yes` belongs in a drop-in: appending to `sshd_config` would be
/// the *first* value only when no earlier directive exists, and a reload of a
/// broken file would lock the operator out. The file is validated with `sshd -t`
/// before the reload.
const String cascadePermitTunnelScript = r'''set -eu
mkdir -p /etc/ssh/sshd_config.d
printf 'PermitTunnel yes\n' > /etc/ssh/sshd_config.d/99-xio-cascade.conf
chmod 644 /etc/ssh/sshd_config.d/99-xio-cascade.conf
grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config || \
  sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
echo "permit-tunnel yes"
''';

/// Success markers. A stage returns these only after it read the state back.
const String exitReadyMarker = 'XIO_CASCADE_EXIT_READY';
const String bridgeReadyMarker = 'XIO_CASCADE_BRIDGE_READY';

class CascadeStageFailure implements Exception {
  CascadeStageFailure(this.stage, this.message, {this.evidence = const []});
  final String stage;
  final String message;
  final List<String> evidence;
  @override
  String toString() => '$stage: $message';
}

/// Stages of the two-step install, in the order the wizard runs them.
enum CascadeInstallStage { exit, bridge }

String cascadeStageTitle(CascadeInstallStage stage) =>
    stage == CascadeInstallStage.exit ? 'exit' : 'bridge';

/// One connection to one host, used by both stages.
///
/// Kept apart from the wizard UI so the commands can be exercised by tests
/// against a fake [VpsService].
class CascadeInstaller {
  CascadeInstaller(this.ssh, {this.runTimeout = const Duration(minutes: 6)});

  final VpsService ssh;
  final Duration runTimeout;

  Future<String> _run(String command) async {
    try {
      final bytes = await ssh.executeInput(
        command,
        const <int>[],
        timeout: runTimeout,
      );
      return utf8.decode(bytes, allowMalformed: true).trim();
    } on SshCommandFailure catch (failure) {
      final tail = utf8.decode(failure.stdoutBytes, allowMalformed: true).trim();
      throw StateError(tail.isEmpty ? 'remote command failed' : tail);
    }
  }

  static String _q(String value) => "'${value.replaceAll("'", "'\\''")}'";

  Future<void> _put(String path, String content, String mode) async {
    // `mkdir -p` only: the parent may be /etc/systemd/system, whose mode must
    // never be changed as a side effect of uploading our own file.
    final quoted = _q(path);
    await _run('set -eu\nmkdir -p "\$(dirname $quoted)"');
    await ssh.upload(path, utf8.encode(content));
    await _run('set -eu\nchmod $mode $quoted\nchown root:root $quoted');
  }

  /// Stage 1: the exit terminates the tunnel and NATs client traffic.
  Future<List<String>> installExit() async {
    final evidence = <String>[];
    try {
      await _put('/usr/local/sbin/xio-cascade-exit-up.sh', cascadeExitUpScript, '700');
      await _put('/usr/local/sbin/xio-cascade-exit-down.sh', cascadeExitDownScript, '700');
      await _put(
        '/etc/systemd/system/xio-cascade-exit.service',
        cascadeExitUnit,
        '644',
      );
      await _run(cascadePermitTunnelScript);
      evidence.add('PermitTunnel yes (drop-in, sshd -t)');
      final out = await _run(r'''set -eu
systemctl daemon-reload
systemctl enable --now xio-cascade-exit.service >/dev/null 2>&1
systemctl is-active --quiet xio-cascade-exit.service
ip -4 addr show tun0 | grep -Fq '10.250.0.2/30'
ip -6 addr show tun0 | grep -Fq 'fd78:2::2/64'
printf '%s addr=%s forward=%s v6=%s\n' XIO_CASCADE_EXIT_READY \
  "$(ip -4 -o addr show tun0 | awk '{print $4}')" \
  "$(sysctl -n net.ipv4.ip_forward)" \
  "$(sysctl -n net.ipv6.conf.all.forwarding)"
''');
      if (!out.contains(exitReadyMarker)) {
        throw StateError('exit did not confirm readiness');
      }
      final line = out
          .split('\n')
          .firstWhere((l) => l.contains(exitReadyMarker), orElse: () => out);
      final fields = line.split(' ');
      evidence.add('tun0 ${fields.firstWhere((f) => f.startsWith('addr='), orElse: () => 'addr=?')}');
      evidence.add('IPv4 forwarding ${fields.firstWhere((f) => f.startsWith('forward='), orElse: () => 'forward=?')}');
      evidence.add('IPv6 forwarding ${fields.firstWhere((f) => f.startsWith('v6='), orElse: () => 'v6=?')}');
      final nat = await _run(
        'iptables -t nat -S POSTROUTING | grep -Fc -- \'10.78.0.0/24\' || true',
      );
      evidence.add('NAT rules for clients: ${nat.isEmpty ? '?' : nat}');
      return evidence;
    } on StateError catch (error) {
      throw CascadeStageFailure('exit', error.message, evidence: evidence);
    }
  }

  /// Stage 2: the bridge gets a key, the exit authorizes it, and the SSH TUN
  /// unit is started and verified from the bridge side.
  Future<List<String>> installBridge(String exitHost) async {
    final exit = validateCascadeExit(exitHost);
    if (exit == null) {
      throw CascadeStageFailure('bridge', 'exit address must be IPv4 or IPv6');
    }
    final evidence = <String>[];
    try {
      var pubkey = '';
      try {
        pubkey = await _run(r'''set -eu
umask 077
mkdir -p /root/.ssh
if [ ! -s /root/.ssh/xio_cascade ]; then
  ssh-keygen -q -t ed25519 -N '' -C xio-cascade -f /root/.ssh/xio_cascade
fi
cat /root/.ssh/xio_cascade.pub
''');
      } on StateError catch (error) {
        throw CascadeStageFailure('bridge', 'key creation failed: ${error.message}', evidence: evidence);
      }
      if (pubkey.isEmpty || !pubkey.startsWith('ssh-ed25519 ')) {
        throw CascadeStageFailure('bridge', 'cascade key was not created', evidence: evidence);
      }
      evidence.add('key /root/.ssh/xio_cascade ready');
      await _put('/etc/xio-cascade/bridge.env', 'XIO_CASCADE_EXIT_HOST=$exit\n', '600');
      evidence.add('/etc/xio-cascade/bridge.env -> $exit');
      await _put('/usr/local/sbin/xio-cascade-bridge-up.sh', cascadeBridgeUpScript, '700');
      await _put('/usr/local/sbin/xio-cascade-bridge-down.sh', cascadeBridgeDownScript, '700');
      await _put('/etc/systemd/system/xio-cascade-bridge.service', cascadeBridgeUnit, '644');
      // A restart, not just `enable --now`: the unit is Restart=always, so it
      // may be mid-restart (an exit reinstall breaks the tunnel) and a bare
      // `is-active` would race it. The wait loop makes the check deterministic.
      final out = await _run(r'''set -eu
. /etc/xio-cascade/bridge.env
systemctl daemon-reload
systemctl enable xio-cascade-bridge.service >/dev/null 2>&1 || true
systemctl restart xio-cascade-bridge.service
up=no
for _ in $(seq 1 30); do
  if systemctl is-active --quiet xio-cascade-bridge.service && \
     ip -4 addr show tun0 2>/dev/null | grep -Fq '10.250.0.1/30'; then up=yes; break; fi
  sleep 1
done
[ "$up" = yes ] || { echo "bridge did not come up" >&2; systemctl status xio-cascade-bridge.service --no-pager -n 5 >&2 || true; exit 1; }
ssh -i /root/.ssh/xio_cascade -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -o ConnectTimeout=8 -o ExitOnForwardFailure=yes root@"$XIO_CASCADE_EXIT_HOST" true
for _ in $(seq 1 10); do ping -c 1 -W 3 10.250.0.2 >/dev/null 2>&1 && break; sleep 1; done
ping -c 2 -W 3 10.250.0.2 >/dev/null
printf '%s tun=%s ssh=ok ping=ok\n' XIO_CASCADE_BRIDGE_READY \
  "$(ip -4 -o addr show tun0 | awk '{print $4}')"
''');
      if (!out.contains(bridgeReadyMarker)) {
        throw CascadeStageFailure('bridge', 'bridge did not confirm readiness', evidence: evidence);
      }
      evidence.add('tun0 10.250.0.1/30 up');
      evidence.add('SSH TUN to $exit: OK');
      evidence.add('ping 10.250.0.2: OK');
      return evidence;
    } on StateError catch (error) {
      throw CascadeStageFailure(
        'bridge',
        error.message,
        evidence: evidence,
      );
    }
  }
}

/// Authorizes the bridge key on the exit. Split out because the key material is
/// passed over stdin, never interpolated into a command.
Future<void> authorizeCascadeKey(VpsService exitSsh, String publicKey) async {
  final line = publicKey.trim();
  if (!line.startsWith('ssh-ed25519 ') || line.length > 400) {
    throw StateError('invalid cascade public key');
  }
  try {
    await exitSsh.executeInput(
      r'''set -eu
umask 077
mkdir -p /root/.ssh
touch /root/.ssh/authorized_keys
key=$(cat)
if ! grep -qxF -- "$key" /root/.ssh/authorized_keys; then
  printf '%s\n' "$key" >> /root/.ssh/authorized_keys
fi
chmod 600 /root/.ssh/authorized_keys
printf 'authorized %s\n' "$(printf '%s' "$key" | cut -d' ' -f1)"
''',
      utf8.encode('$line\n'),
      timeout: const Duration(minutes: 1),
    );
  } on SshCommandFailure catch (failure) {
    final tail = utf8.decode(failure.stdoutBytes, allowMalformed: true).trim();
    throw StateError(tail.isEmpty ? 'failed to authorize the key on exit' : tail);
  }
}

/// Reads the bridge public key: creates it when missing, never returns key
/// material that was not read back from the host.
Future<String> readCascadeKey(VpsService bridgeSsh) async {
  try {
    final bytes = await bridgeSsh.executeInput(
      r'''set -eu
umask 077
mkdir -p /root/.ssh
if [ ! -s /root/.ssh/xio_cascade ]; then
  ssh-keygen -q -t ed25519 -N '' -C xio-cascade -f /root/.ssh/xio_cascade
fi
cat /root/.ssh/xio_cascade.pub
''',
      const <int>[],
      timeout: const Duration(minutes: 1),
    );
    final text = utf8.decode(bytes, allowMalformed: true).trim();
    if (!text.startsWith('ssh-ed25519 ')) {
      throw StateError('cascade public key not found');
    }
    return text;
  } on SshCommandFailure {
    throw StateError('failed to read the cascade public key');
  }
}

/// Asks the exit which IPv4 it actually egresses with. Used as the final proof
/// that the foreign side has working connectivity, not merely a live unit.
Future<String> cascadeEgressIp(VpsService exitSsh) async {
  try {
    final bytes = await exitSsh.executeInput(
      r'''set -u
for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
  ip=$(curl -4 -sS --max-time 8 "$url" 2>/dev/null | tr -d '[:space:]')
  case "$ip" in
    [[:digit:]]*.[[:digit:]]*) printf '%s\n' "$ip"; exit 0;;
  esac
done
exit 1
''',
      const <int>[],
      timeout: const Duration(seconds: 40),
    );
    final text = utf8.decode(bytes, allowMalformed: true).trim();
    return text.isEmpty ? 'unknown' : text;
  } on SshCommandFailure {
    return 'unavailable';
  }
}
