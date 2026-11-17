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
# XIO cascade bridge (RU VPS): client traffic from every xio* tunnel -> SSH TUN -> exit VPS.
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
# Every client-facing transport forwards into the cascade, and the interface name
# differs per transport (xioawg0 for AWG, xiorivet for the RIVET gateway, a
# separate TUN when Xray runs one). Discover them instead of hardcoding a single
# name: a transport installed later must not silently keep exiting from the RU
# address just because this file only knew about AWG.
client_ifs() {
  ip -br link show | awk -v skip="$TUN" '
    { name = $1; sub(/@.*/, "", name) }
    name ~ /^xio/ && name != skip { print name }
  '
}
CLIENT_IFS=$(client_ifs)
[ -n "$CLIENT_IFS" ] || echo "warning: no client tunnel interface found yet" >&2
for IF in $CLIENT_IFS; do
  ip rule add iif "$IF" lookup 51888 priority 1000 2>/dev/null || true
  ip -6 rule add iif "$IF" lookup 51888 priority 1000 2>/dev/null || true
  iptables -C FORWARD -i "$IF" -o "$TUN" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -i "$IF" -o "$TUN" -j ACCEPT
  iptables -C FORWARD -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ip6tables -C FORWARD -i "$IF" -o "$TUN" -j ACCEPT 2>/dev/null || \
    ip6tables -I FORWARD 1 -i "$IF" -o "$TUN" -j ACCEPT
  ip6tables -C FORWARD -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    ip6tables -I FORWARD 1 -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
done
# FORWARD accepts for every client interface are installed by the loop above.
ip rule add fwmark ${XIO_CASCADE_MARK:-0x518} lookup 51888 priority 1000 2>/dev/null || true
# Traffic a local transport generates itself (Xray, the RIVET gateway dialling
# upstream) has no input interface, so the iif rules above cannot match it: such
# a socket must set XIO_CASCADE_MARK (default 0x518) to leave through this table.
ip route replace default dev "$TUN" table 51888
ip -6 route replace default dev "$TUN" table 51888
iptables -t nat -C POSTROUTING -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE
# Locally generated, marked traffic (Xray/RIVET egress) keeps the bridge address
# as its source, so it needs its own SNAT rule on the cascade tunnel.
iptables -t nat -C POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -o "$TUN" -j MASQUERADE
iptables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -I FORWARD 1 -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t nat -C POSTROUTING -s fd78:1::/64 -o "$TUN" -j MASQUERADE 2>/dev/null || \
  ip6tables -t nat -I POSTROUTING 1 -s fd78:1::/64 -o "$TUN" -j MASQUERADE
ip6tables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  ip6tables -t mangle -I FORWARD 1 -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
echo "bridge cascade up: $TUN -> $EXIT_HOST via $WAN"
''';

const String cascadeBridgeDownScript = r'''#!/bin/bash
set -uo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
# Interfaces are discovered rather than assumed: up installs an iif rule per
# xio* tunnel, and at teardown a transport's interface may already be gone while
# its rule (and its FORWARD accepts) are still installed.
ifs=$( { ip rule show; ip -6 rule show; } 2>/dev/null \
  | awk '/lookup 51888/ && /iif/ { for (i = 1; i <= NF; i++) if ($i == "iif") print $(i + 1) }'
  ip -br link show 2>/dev/null | awk -v skip="$TUN" '{ n = $1; sub(/@.*/, "", n) } n ~ /^xio/ && n != skip { print n }'
  echo xioawg0 )
ifs=$(printf '%s\n' $ifs | sort -u)
for IF in $ifs; do
  for i in $(seq 1 4); do ip rule del iif "$IF" lookup 51888 priority 1000 2>/dev/null || break; done
  for i in $(seq 1 4); do ip -6 rule del iif "$IF" lookup 51888 priority 1000 2>/dev/null || break; done
  for i in $(seq 1 4); do iptables -D FORWARD -i "$IF" -o "$TUN" -j ACCEPT 2>/dev/null || break; done
  for i in $(seq 1 4); do iptables -D FORWARD -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
  for i in $(seq 1 4); do ip6tables -D FORWARD -i "$IF" -o "$TUN" -j ACCEPT 2>/dev/null || break; done
  for i in $(seq 1 4); do ip6tables -D FORWARD -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
done
ip rule del fwmark ${XIO_CASCADE_MARK:-0x518} lookup 51888 priority 1000 2>/dev/null || true
ip route flush table 51888 2>/dev/null || true
ip -6 route flush table 51888 2>/dev/null || true
for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -t mangle -D FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -t nat -D POSTROUTING -s fd78:1::/64 -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
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

/// Tools both stages call. A host may have lost one of them: purging a previous
/// XIO install removes the packages that install added, and `iptables` is one of
/// them, so a bridge that worked a minute ago answers "command not found" and
/// the wizard shows a generic failure. Missing tools are installed before any
/// script is written and re-probed before the stage is allowed to continue.
const String cascadeToolsScript = r'''set -u
need=""
command -v ip >/dev/null 2>&1 || need="$need iproute2"
command -v iptables >/dev/null 2>&1 || need="$need iptables"
command -v ip6tables >/dev/null 2>&1 || need="$need iptables"
command -v ssh >/dev/null 2>&1 || need="$need openssh-client"
command -v ping >/dev/null 2>&1 || need="$need iputils-ping"
command -v sysctl >/dev/null 2>&1 || need="$need procps"
if [ -z "$need" ]; then echo "tools=ok"; exit 0; fi
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=60 --no-install-recommends $need >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q iproute iptables iputils openssh-clients procps-ng >/dev/null 2>&1 || true
else
  echo "tools=no-package-manager"
  exit 2
fi
still=""
for tool in ip iptables ip6tables ssh sysctl ping; do
  command -v "$tool" >/dev/null 2>&1 || still="$still $tool"
done
[ -z "$still" ] || { echo "tools=missing:$still"; exit 3; }
echo "tools=installed:$(echo $need | tr ' ' ',')"
''';

/// Success markers. A stage returns these only after it read the state back.
const String exitReadyMarker = 'XIO_CASCADE_EXIT_READY';
const String bridgeReadyMarker = 'XIO_CASCADE_BRIDGE_READY';
const String tunnelReadyMarker = 'XIO_CASCADE_TUNNEL_READY';

/// Unit names, used both to restart a stage and to read its journal back when a
/// step fails.
const String cascadeExitUnitName = 'xio-cascade-exit.service';
const String cascadeBridgeUnitName = 'xio-cascade-bridge.service';

class CascadeStageFailure implements Exception {
  CascadeStageFailure(
    this.stage,
    this.message, {
    this.evidence = const [],
    this.logs = const [],
    this.step = '',
  });

  /// `exit` or `bridge`: the server that was being changed.
  final String stage;

  /// What the host refused to confirm, in its own words.
  final String message;

  /// Evidence the stage had already proven before it failed.
  final List<String> evidence;

  /// Remote output of the failing step and the service journal, collected while
  /// the connection is still open. Empty when the failure happened before any
  /// command reached the host.
  final List<String> logs;

  /// Visible plan step that failed, empty when the failure came earlier, for
  /// example while the SSH connection was being opened.
  final String step;

  @override
  String toString() =>
      step.isEmpty ? '$stage: $message' : '$stage · $step: $message';
}

/// Stages of the install, in the order the wizard applies them: the exit first
/// (it terminates the tunnel), the bridge second (its key must be authorized on
/// the exit before its own unit starts).
enum CascadeInstallStage { exit, bridge }

String cascadeStageTitle(CascadeInstallStage stage) => switch (stage) {
  CascadeInstallStage.exit => 'exit',
  CascadeInstallStage.bridge => 'bridge',
};

/// One step of the plan as the wizard draws it.
class CascadePlanStep {
  const CascadePlanStep(this.stage, this.id, this.label);

  final CascadeInstallStage stage;
  final String id;
  final String label;
}

/// Progress of one step.
enum CascadeStepState { running, done, failed }

/// A step event: `running` when the server starts being changed, then `done`
/// with the line that proves the step, or `failed` with the reason.
class CascadeStepEvent {
  const CascadeStepEvent(this.stage, this.id, this.state, {this.detail});

  final CascadeInstallStage stage;
  final String id;
  final CascadeStepState state;
  final String? detail;
}

typedef CascadeStepCallback = void Function(CascadeStepEvent event);

/// The complete plan for one server, in execution order.
///
/// The wizard draws this list before anything is changed, so the operator sees
/// what will be applied to each server and where a failure stopped instead of a
/// single opaque "installing" spinner. A test keeps the emitted step ids equal to
/// this list, so the picture cannot drift from what actually runs.
List<CascadePlanStep> cascadePlanSteps(
  CascadeInstallStage stage, {
  bool clean = false,
  bool trust = true,
}) => <CascadePlanStep>[
  if (clean) CascadePlanStep(stage, 'clean', 'remove the previous XIO install'),
  CascadePlanStep(stage, 'tools', 'prerequisites'),
  if (stage == CascadeInstallStage.exit) ...<CascadePlanStep>[
    CascadePlanStep(stage, 'scripts', 'tunnel scripts, unit, PermitTunnel'),
    CascadePlanStep(stage, 'unit', 'addresses and forwarding'),
    CascadePlanStep(stage, 'nat', 'NAT for client networks'),
  ] else ...<CascadePlanStep>[
    CascadePlanStep(stage, 'key', 'cascade key'),
    if (trust) CascadePlanStep(stage, 'trust', 'key authorized on exit'),
    CascadePlanStep(stage, 'scripts', 'env, scripts, unit'),
    CascadePlanStep(stage, 'tunnel', 'SSH TUN and addresses'),
    CascadePlanStep(stage, 'reach', 'SSH and ping to exit'),
  ],
];

/// Human title of a step id, used by failure messages.
String cascadeStepLabel(CascadeInstallStage stage, String id) {
  for (final step in <CascadePlanStep>[
    ...cascadePlanSteps(stage),
    ...cascadePlanSteps(stage, clean: true),
  ]) {
    if (step.id == id) return step.label;
  }
  return id;
}

/// What each server proved during one install.
class CascadeInstallResult {
  const CascadeInstallResult({
    required this.exitEvidence,
    required this.bridgeEvidence,
  });

  final List<String> exitEvidence;
  final List<String> bridgeEvidence;
}

/// One connection to one host, used by both stages.
///
/// Kept apart from the wizard UI so the commands can be exercised by tests
/// against a fake [VpsService].
class CascadeInstaller {
  CascadeInstaller(this.ssh, {this.runTimeout = const Duration(minutes: 6)});

  final VpsService ssh;
  final Duration runTimeout;

  /// Last command and its output. Kept so a failed step can show the host's own
  /// words in the wizard instead of a generic sentence.
  String _lastCommand = '';
  String _lastOutput = '';

  Future<String> _run(String command) async {
    _lastCommand = command;
    try {
      final bytes = await ssh.executeInput(
        command,
        const <int>[],
        timeout: runTimeout,
      );
      _lastOutput = utf8.decode(bytes, allowMalformed: true);
      return _lastOutput.trim();
    } on SshCommandFailure catch (failure) {
      _lastOutput = utf8.decode(failure.stdoutBytes, allowMalformed: true);
      final tail = _lastOutput.trim();
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

  /// Last non-empty lines of a failed stage, joined for the error message. The
  /// verification scripts merge stderr into stdout, so this carries the real
  /// reason (`iptables: command not found`, a unit failure) instead of leaving
  /// the operator with "did not confirm readiness".
  static String _tail(String text, {int lines = 6}) {
    final all = [
      for (final line in text.split('\n'))
        if (line.trim().isNotEmpty) line.trim(),
    ];
    if (all.isEmpty) return '';
    return all.length <= lines
        ? all.join(' | ')
        : all.sublist(all.length - lines).join(' | ');
  }

  /// Installs what both stages call when the host has lost it, then re-probes.
  /// Returns an evidence line when something was installed, or null when the
  /// host already had everything.
  Future<String?> _ensureTools() async {
    String out;
    try {
      out = await _run(cascadeToolsScript);
    } on StateError catch (error) {
      throw StateError('prerequisites: ${error.message}');
    }
    if (!out.contains('tools=installed:')) return null;
    final tools = {
      for (final tool
          in out
              .substring(
                out.indexOf('tools=installed:') + 'tools=installed:'.length,
              )
              .trim()
              .split(','))
        if (tool.trim().isNotEmpty) tool.trim(),
    }.toList()..sort();
    return 'installed prerequisites: ${tools.join(', ')}';
  }

  /// Runs one visible step: emits `running`, then `done` with the line that
  /// proves it — or `failed` and throws [CascadeStageFailure] carrying the host
  /// output and, when [unit] is given, the journal of that service.
  Future<void> _step(
    _StageRun run,
    String id,
    Future<String?> Function() body, {
    String unit = '',
  }) async {
    run.onStep?.call(CascadeStepEvent(run.stage, id, CascadeStepState.running));
    try {
      final detail = await body();
      run.onStep?.call(
        CascadeStepEvent(run.stage, id, CascadeStepState.done, detail: detail),
      );
    } catch (error) {
      if (error is CascadeStageFailure) rethrow;
      final message = switch (error) {
        StateError(:final message) => message,
        FormatException(:final message) => message,
        _ => '$error',
      };
      final logs = await _collectLogs(unit);
      run.onStep?.call(
        CascadeStepEvent(
          run.stage,
          id,
          CascadeStepState.failed,
          detail: message,
        ),
      );
      throw CascadeStageFailure(
        cascadeStageTitle(run.stage),
        message,
        evidence: run.evidence,
        logs: logs,
        step: cascadeStepLabel(run.stage, id),
      );
    }
  }

  /// Output of the failing command plus the unit journal, read while the
  /// connection is still open: the wizard shows both, so "what was applied" and
  /// "what exactly refused" are answerable without a second SSH session.
  Future<List<String>> _collectLogs(String unit) async {
    final logs = <String>[];
    final command = _lastCommand.trim();
    if (command.isNotEmpty &&
        !command.contains('\n') &&
        command.length <= 200) {
      logs.add(r'$ $command');
    }
    for (final line in _lastOutput.split('\n')) {
      if (line.trim().isEmpty) continue;
      logs.add(line.trimRight());
    }
    if (unit.isNotEmpty) {
      try {
        final bytes = await ssh.executeInput(
          'journalctl -u $unit -n 40 --no-pager 2>&1 || true',
          const <int>[],
          timeout: const Duration(seconds: 40),
        );
        final text = utf8.decode(bytes, allowMalformed: true).trim();
        if (text.isNotEmpty) {
          logs.add('--- journalctl -u $unit -n 40 ---');
          for (final line in text.split('\n')) {
            logs.add(line.trimRight());
          }
        }
      } catch (_) {
        // A host without journald still reports the step's own output.
      }
    }
    return logs.length <= 160 ? logs : logs.sublist(logs.length - 160);
  }

  /// Stage 1: the exit terminates the tunnel and NATs client traffic.
  ///
  /// [clean] removes a previous XIO install from the same host before anything
  /// is written, so the removal is one visible step instead of a hidden prelude.
  Future<List<String>> installExit({
    Future<void> Function()? clean,
    CascadeStepCallback? onStep,
  }) async {
    final run = _StageRun(CascadeInstallStage.exit, onStep);
    final evidence = run.evidence;
    if (clean != null) {
      await _step(run, 'clean', () async {
        await clean();
        evidence.add('previous XIO install removed');
        return 'previous XIO install removed';
      });
    }
    await _step(run, 'tools', () async {
      final tools = await _ensureTools();
      if (tools != null) evidence.add(tools);
      return tools;
    });
    await _step(run, 'scripts', () async {
      await _put(
        '/usr/local/sbin/xio-cascade-exit-up.sh',
        cascadeExitUpScript,
        '700',
      );
      await _put(
        '/usr/local/sbin/xio-cascade-exit-down.sh',
        cascadeExitDownScript,
        '700',
      );
      await _put(
        '/etc/systemd/system/xio-cascade-exit.service',
        cascadeExitUnit,
        '644',
      );
      await _run(cascadePermitTunnelScript);
      evidence.add('PermitTunnel yes (drop-in, sshd -t)');
      return 'PermitTunnel yes, unit written';
    }, unit: cascadeExitUnitName);
    await _step(run, 'unit', () async {
      final out = await _run(r'''set -eu
exec 2>&1
systemctl daemon-reload
systemctl enable xio-cascade-exit.service >/dev/null 2>&1 || true
systemctl restart xio-cascade-exit.service
systemctl is-active --quiet xio-cascade-exit.service || {
  echo "exit unit is not active"; journalctl -u xio-cascade-exit.service -n 10 --no-pager || true; exit 1; }
ip -4 addr show tun0 | grep -Fq '10.250.0.2/30' || {
  echo "tun0 has no 10.250.0.2/30"; ip -4 -o addr show tun0 || true; exit 1; }
ip -6 addr show tun0 | grep -Fq 'fd78:2::2/64' || {
  echo "tun0 has no fd78:2::2/64"; ip -6 -o addr show tun0 || true; exit 1; }
printf '%s addr=%s forward=%s v6=%s\n' XIO_CASCADE_EXIT_READY \
  "$(ip -4 -o addr show tun0 | awk '{print $4}')" \
  "$(sysctl -n net.ipv4.ip_forward)" \
  "$(sysctl -n net.ipv6.conf.all.forwarding)"
''');
      if (!out.contains(exitReadyMarker)) {
        final tail = _tail(out);
        throw StateError(
          tail.isEmpty
              ? 'exit did not confirm readiness'
              : 'exit did not confirm readiness: $tail',
        );
      }
      final line = out
          .split('\n')
          .firstWhere((l) => l.contains(exitReadyMarker), orElse: () => out);
      final fields = line.split(' ');
      final addr = fields.firstWhere(
        (f) => f.startsWith('addr='),
        orElse: () => 'addr=?',
      );
      final forward = fields.firstWhere(
        (f) => f.startsWith('forward='),
        orElse: () => 'forward=?',
      );
      final v6 = fields.firstWhere(
        (f) => f.startsWith('v6='),
        orElse: () => 'v6=?',
      );
      evidence.add('tun0 $addr');
      evidence.add('$forward (net.ipv4.ip_forward)');
      evidence.add('$v6 (net.ipv6.conf.all.forwarding)');
      return 'tun0 ${addr.substring('addr='.length)} · forwarding '
          '${forward.substring('forward='.length)}/'
          '${v6.substring('v6='.length)}';
    }, unit: cascadeExitUnitName);
    await _step(run, 'nat', () async {
      final nat = await _run(
        'iptables -t nat -S POSTROUTING | grep -Fc -- \'10.78.0.0/24\' || true',
      );
      evidence.add('NAT rules for clients: ${nat.isEmpty ? '?' : nat}');
      return 'NAT rules for clients: ${nat.isEmpty ? '?' : nat}';
    });
    return evidence;
  }

  /// Stage 2: the bridge gets a key, the exit authorizes it, and the SSH TUN
  /// unit is started and verified from the bridge side.
  ///
  /// [authorize] receives the bridge public key and installs it on the exit
  /// through the exit connection; the wizard passes [authorizeCascadeKey]. When
  /// it is absent the step is not part of the plan
  /// (`cascadePlanSteps(..., trust: false)`), which is what the live test does.
  Future<List<String>> installBridge(
    String exitHost, {
    Future<void> Function(String publicKey)? authorize,
    Future<void> Function()? clean,
    CascadeStepCallback? onStep,
  }) async {
    final exit = validateCascadeExit(exitHost);
    if (exit == null) {
      throw CascadeStageFailure('bridge', 'exit address must be IPv4 or IPv6');
    }
    final run = _StageRun(CascadeInstallStage.bridge, onStep);
    final evidence = run.evidence;
    var pubkey = '';
    if (clean != null) {
      await _step(run, 'clean', () async {
        await clean();
        evidence.add('previous XIO install removed');
        return 'previous XIO install removed';
      });
    }
    await _step(run, 'tools', () async {
      final tools = await _ensureTools();
      if (tools != null) evidence.add(tools);
      return tools;
    });
    await _step(run, 'key', () async {
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
        throw StateError('key creation failed: ${error.message}');
      }
      if (pubkey.isEmpty || !pubkey.startsWith('ssh-ed25519 ')) {
        throw StateError('cascade key was not created');
      }
      evidence.add('key /root/.ssh/xio_cascade ready');
      return 'key /root/.ssh/xio_cascade ready';
    });
    if (authorize != null) {
      await _step(run, 'trust', () async {
        await authorize(pubkey);
        evidence.add('public key authorized on $exit');
        return 'public key authorized on $exit';
      });
    }
    await _step(run, 'scripts', () async {
      await _put(
        '/etc/xio-cascade/bridge.env',
        'XIO_CASCADE_EXIT_HOST=$exit\n',
        '600',
      );
      evidence.add('/etc/xio-cascade/bridge.env -> $exit');
      await _put(
        '/usr/local/sbin/xio-cascade-bridge-up.sh',
        cascadeBridgeUpScript,
        '700',
      );
      await _put(
        '/usr/local/sbin/xio-cascade-bridge-down.sh',
        cascadeBridgeDownScript,
        '700',
      );
      await _put(
        '/etc/systemd/system/xio-cascade-bridge.service',
        cascadeBridgeUnit,
        '644',
      );
      return 'env -> $exit, unit written';
    }, unit: cascadeBridgeUnitName);
    // A restart, not just `enable --now`: the unit is Restart=always, so it may
    // be mid-restart (an exit reinstall breaks the tunnel) and a bare `is-active`
    // would race it. The wait loop makes the check deterministic.
    await _step(run, 'tunnel', () async {
      final out = await _run(r'''set -eu
exec 2>&1
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
[ "$up" = yes ] || { echo "bridge did not come up"; journalctl -u xio-cascade-bridge.service -n 10 --no-pager || true; exit 1; }
printf '%s tun=%s\n' XIO_CASCADE_TUNNEL_READY "$(ip -4 -o addr show tun0 | awk '{print $4}')"
''');
      if (!out.contains(tunnelReadyMarker)) {
        final tail = _tail(out);
        throw StateError(
          tail.isEmpty
              ? 'bridge did not confirm the tunnel'
              : 'bridge did not confirm the tunnel: $tail',
        );
      }
      final line = out
          .split('\n')
          .firstWhere((l) => l.contains(tunnelReadyMarker), orElse: () => out);
      final tun = line
          .split(' ')
          .firstWhere((f) => f.startsWith('tun='), orElse: () => 'tun=?');
      evidence.add('tun0 ${tun.substring('tun='.length)} up');
      return 'tun0 ${tun.substring('tun='.length)} up';
    }, unit: cascadeBridgeUnitName);
    await _step(run, 'reach', () async {
      final out = await _run(r'''set -eu
exec 2>&1
. /etc/xio-cascade/bridge.env
ssh -i /root/.ssh/xio_cascade -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -o ConnectTimeout=8 -o ExitOnForwardFailure=yes root@"$XIO_CASCADE_EXIT_HOST" true
for _ in $(seq 1 10); do ping -c 1 -W 3 10.250.0.2 >/dev/null 2>&1 && break; sleep 1; done
ping -c 2 -W 3 10.250.0.2 >/dev/null
printf '%s ssh=ok ping=ok\n' XIO_CASCADE_BRIDGE_READY
''');
      if (!out.contains(bridgeReadyMarker)) {
        final tail = _tail(out);
        throw StateError(
          tail.isEmpty
              ? 'bridge did not reach the exit'
              : 'bridge did not reach the exit: $tail',
        );
      }
      evidence.add('SSH TUN to $exit: OK');
      evidence.add('ping 10.250.0.2: OK');
      return 'SSH TUN to $exit, ping 10.250.0.2';
    }, unit: cascadeBridgeUnitName);
    return evidence;
  }
}

/// Runs the whole install in one action: the exit first, then the bridge, whose
/// key is authorized on the exit before its own unit starts. Both connections
/// are already open and owned by the caller, so a failure leaves them usable for
/// another attempt and the wizard can close them when it goes away.
Future<CascadeInstallResult> installCascade({
  required VpsService exitSsh,
  required VpsService bridgeSsh,
  required String exitHost,
  Future<void> Function(VpsService ssh)? cleanExit,
  Future<void> Function(VpsService ssh)? cleanBridge,
  CascadeStepCallback? onStep,
}) async {
  final exitEvidence = await CascadeInstaller(exitSsh).installExit(
    clean: cleanExit == null ? null : () => cleanExit(exitSsh),
    onStep: onStep,
  );
  final bridgeEvidence = await CascadeInstaller(bridgeSsh).installBridge(
    exitHost,
    authorize: (key) => authorizeCascadeKey(exitSsh, key),
    clean: cleanBridge == null ? null : () => cleanBridge(bridgeSsh),
    onStep: onStep,
  );
  return CascadeInstallResult(
    exitEvidence: exitEvidence,
    bridgeEvidence: bridgeEvidence,
  );
}

/// Per-stage bookkeeping the steps share: the proof lines they collect and the
/// listener that turns them into wizard progress.
class _StageRun {
  _StageRun(this.stage, this.onStep);

  final CascadeInstallStage stage;
  final CascadeStepCallback? onStep;
  final List<String> evidence = <String>[];
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
    throw StateError(
      tail.isEmpty ? 'failed to authorize the key on exit' : tail,
    );
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
