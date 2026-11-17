import 'package:flutter/material.dart';

import 'cascade_native.dart';
import 'core.dart';
import 'l10n.dart';
import 'managed_service.dart';
import 'server_address.dart';

/// Two explicit stages with their own connection and their own proof:
/// exit first (terminates the tunnel and NATs client traffic), bridge second
/// (key trust, SSH TUN, policy routing). Nothing is saved until the bridge stage
/// has proven the tunnel from the bridge side.
///
/// The wizard is deliberately not a single "install everything" button: each
/// stage reports the evidence it read back, and a failed stage never advances.
/// Evidence lines are the host's own read-back facts and stay in the technical
/// English the rest of the output uses; the interface prose is translated.
class CascadeWizardDialog extends StatefulWidget {
  const CascadeWizardDialog({super.key, required this.store, this.bridgeHint});

  final AppStore store;
  final String? bridgeHint;

  static Future<void> open(
    BuildContext context,
    AppStore store, {
    String? bridgeHint,
  }) => showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (_) => CascadeWizardDialog(store: store, bridgeHint: bridgeHint),
  );

  @override
  State<CascadeWizardDialog> createState() => _CascadeWizardDialogState();
}

/// SSH fields for one host. Kept as a plain holder so both stages look the same
/// and neither reuses another host's password by accident.
class _HostFields {
  _HostFields({String host = '', String user = 'root', String port = '22'})
    : host = TextEditingController(text: host),
      port = TextEditingController(text: port),
      username = TextEditingController(text: user);

  final TextEditingController host, port, username;
  final TextEditingController password = TextEditingController(),
      key = TextEditingController(),
      passphrase = TextEditingController();

  void dispose() {
    for (final c in [host, port, username, password, key, passphrase]) {
      c.clear();
      c.dispose();
    }
  }
}

class _CascadeWizardDialogState extends State<CascadeWizardDialog> {
  final _exit = _HostFields(host: '');
  final _bridge = _HostFields(host: '');
  VpsService? _exitSsh, _bridgeSsh;
  bool _busy = false;
  String? _error;
  /// 0 — exit pending, 1 — exit ready (bridge pending), 2 — cascade ready.
  int _stage = 0;
  final List<String> _exitEvidence = [], _bridgeEvidence = [];
  String _egress = '';
  String _exitHost = '', _bridgeHost = '';
  bool _purgeExit = false, _purgeBridge = false;

  @override
  void initState() {
    super.initState();
    _exit.host.text = widget.store.cascadeExit;
    _bridge.host.text = widget.bridgeHint ?? widget.store.cascadeBridge;
  }

  @override
  void dispose() {
    _exitSsh?.close();
    _bridgeSsh?.close();
    _exit.dispose();
    _bridge.dispose();
    super.dispose();
  }

  /// Validation runs before any socket is opened, so an empty field never
  /// reaches a server. Messages stay technical: they name the field, not a
  /// translated sentence that would have to be inflected.
  String? _validate(_HostFields fields, String label) {
    final host = normalizeServerHost(fields.host.text);
    if (host.isEmpty) return '$label: host is required';
    final port = int.tryParse(fields.port.text.trim());
    if (port == null || port < 1 || port > 65535) {
      return '$label: port must be 1-65535';
    }
    if (fields.username.text.trim().isEmpty) return '$label: user is required';
    if (fields.password.text.isEmpty && fields.key.text.trim().isEmpty) {
      return '$label: password or private key is required';
    }
    return null;
  }

  Future<void> _runStage1() async {
    final problem = _validate(_exit, 'Exit');
    if (problem != null) return setState(() => _error = problem);
    final host = normalizeServerHost(_exit.host.text);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final ssh = VpsService();
      await ssh.open(
        SshTarget(
          host,
          int.parse(_exit.port.text.trim()),
          _exit.username.text.trim(),
          '',
        ),
        _exit.password.text,
        _exit.key.text,
        _exit.passphrase.text,
      );
      _exitSsh = ssh;
      if (_purgeExit) {
        await ManagedService(ssh).purge(widget.store);
      }
      final evidence = await CascadeInstaller(ssh).installExit();
      _exit.password.clear();
      _exit.key.clear();
      _exit.passphrase.clear();
      if (!mounted) return;
      setState(() {
        _exitHost = host;
        _exitEvidence
          ..clear()
          ..addAll(evidence);
        _stage = 1;
      });
    } catch (error) {
      await _exitSsh?.close();
      _exitSsh = null;
      if (mounted) setState(() => _error = _message(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _runStage2() async {
    final problem = _validate(_bridge, 'Bridge');
    if (problem != null) return setState(() => _error = problem);
    final exitSsh = _exitSsh;
    if (exitSsh == null) {
      // The button is disabled until stage 1 succeeds; this is a guard, not a
      // user-facing sentence.
      return setState(
        () => _error = 'stage 2 requires the exit connection from stage 1',
      );
    }
    final host = normalizeServerHost(_bridge.host.text);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final ssh = VpsService();
      await ssh.open(
        SshTarget(
          host,
          int.parse(_bridge.port.text.trim()),
          _bridge.username.text.trim(),
          '',
        ),
        _bridge.password.text,
        _bridge.key.text,
        _bridge.passphrase.text,
      );
      _bridgeSsh = ssh;
      if (_purgeBridge) {
        await ManagedService(ssh).purge(widget.store);
      }
      final publicKey = await readCascadeKey(ssh);
      await authorizeCascadeKey(exitSsh, publicKey);
      final evidence = <String>[
        'bridge public key authorized on exit',
        ...await CascadeInstaller(ssh).installBridge(_exitHost),
      ];
      final egress = await cascadeEgressIp(exitSsh);
      final saved = await widget.store.setCascadeServers(
        bridge: host,
        exit: _exitHost,
      );
      _bridge.password.clear();
      _bridge.key.clear();
      _bridge.passphrase.clear();
      if (!mounted) return;
      setState(() {
        _bridgeHost = host;
        _bridgeEvidence
          ..clear()
          ..addAll(evidence);
        _egress = egress;
        _stage = 2;
        if (!saved) {
          _error = tr(context, 'Каскад поднят, но адрес не сохранён');
        }
      });
    } catch (error) {
      if (mounted) setState(() => _error = _message(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String _message(Object error) => switch (error) {
    CascadeStageFailure() => '${error.stage}: ${error.message}',
    StateError(:final message) => message,
    FormatException(:final message) => message,
    _ => tr(
      context,
      'Не удалось выполнить этап. Проверьте SSH-доступ и состояние сервера.',
    ),
  };

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Dialog(
      insetPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 24),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 760, maxHeight: 720),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 18, 12, 8),
              child: Row(
                children: [
                  const Icon(Icons.hub_outlined),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      tr(context, 'Мастер каскада · 2 этапа'),
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  Text(
                    '${_stage.clamp(0, 2)}/2',
                    style: theme.textTheme.labelMedium,
                  ),
                ],
              ),
            ),
            LinearProgressIndicator(value: _stage / 2),
            Flexible(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _stageCard(
                      number: 1,
                      title: tr(context, 'Exit · зарубежный VPS'),
                      done: _stage >= 1,
                      active: _stage == 0,
                      fields: _exit,
                      hint: tr(
                        context,
                        'Этот сервер будет выпускать трафик в интернет.',
                      ),
                      details: [
                        'tun0 10.250.0.2/30 and fd78:2::2/64',
                        'IP forwarding and NAT for cascade clients',
                        'PermitTunnel yes in a drop-in, sshd -t before reload',
                      ],
                      evidence: _exitEvidence,
                      purge: _purgeExit,
                      onPurge: (v) => setState(() => _purgeExit = v),
                      action: FilledButton.icon(
                        onPressed: _busy || _stage > 0 ? null : _runStage1,
                        icon: const Icon(Icons.download_done),
                        label: Text(
                          tr(context, 'Этап 1 · установить exit'),
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    _stageCard(
                      number: 2,
                      title: tr(context, 'Bridge · точка входа'),
                      done: _stage >= 2,
                      active: _stage == 1,
                      fields: _bridge,
                      hint: _stage == 0
                          ? tr(context, 'Сначала этап 1: exit нужен для ключа bridge.')
                          : tr(
                              context,
                              'Клиенты подключаются сюда, трафик уходит на exit.',
                            ),
                      details: [
                        'tun0 10.250.0.1/30 and fd78:2::1/64',
                        'key /root/.ssh/xio_cascade and authorization on exit',
                        'policy iif xio* → table 51888, fwmark 0x518, SNAT, MSS clamp',
                      ],
                      evidence: _bridgeEvidence,
                      purge: _purgeBridge,
                      onPurge: (v) => setState(() => _purgeBridge = v),
                      action: FilledButton.icon(
                        onPressed: _busy || _stage != 1 ? null : _runStage2,
                        icon: const Icon(Icons.bolt),
                        label: Text(tr(context, 'Этап 2 · поднять bridge')),
                      ),
                    ),
                    if (_stage >= 2) ...[
                      const SizedBox(height: 12),
                      Card(
                        color: theme.colorScheme.secondaryContainer,
                        child: Padding(
                          padding: const EdgeInsets.all(14),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  const Icon(Icons.check_circle_outline),
                                  const SizedBox(width: 8),
                                  Expanded(
                                    child: Text(
                                      tr(context, 'Каскад поднят'),
                                      style: const TextStyle(
                                        fontWeight: FontWeight.w600,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 6),
                              SelectableText('$_bridgeHost → $_exitHost'),
                              Text(
                                'IPv4 egress: $_egress',
                              ),
                              const SizedBox(height: 6),
                              Text(
                                tr(
                                  context,
                                  'Проверка с телефона: откройте вкладку «Соединение» и убедитесь, что внешний адрес равен адресу exit.',
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                    if (_error != null) ...[
                      const SizedBox(height: 10),
                      Card(
                        color: theme.colorScheme.errorContainer,
                        child: Padding(
                          padding: const EdgeInsets.all(12),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Icon(Icons.error_outline),
                              const SizedBox(width: 8),
                              Expanded(child: SelectableText(_error!)),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 14),
              child: Row(
                children: [
                  TextButton(
                    onPressed: _busy
                        ? null
                        : () {
                            _exitSsh?.close();
                            _bridgeSsh?.close();
                            Navigator.of(context).pop();
                          },
                    child: Text(
                      _stage >= 2 ? tr(context, 'Закрыть') : tr(context, 'Отмена'),
                    ),
                  ),
                  const Spacer(),
                  if (_busy) ...[
                    const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                    const SizedBox(width: 10),
                    Text(tr(context, 'Выполняется…')),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _stageCard({
    required int number,
    required String title,
    required bool done,
    required bool active,
    required _HostFields fields,
    required String hint,
    required List<String> details,
    required List<String> evidence,
    required bool purge,
    required ValueChanged<bool> onPurge,
    required Widget action,
  }) {
    final theme = Theme.of(context);
    final editable = active && !_busy;
    return Card(
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(
          color: done
              ? theme.colorScheme.primary
              : active
              ? theme.colorScheme.outline
              : theme.colorScheme.outlineVariant,
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  radius: 13,
                  backgroundColor: done
                      ? theme.colorScheme.primary
                      : theme.colorScheme.surfaceContainerHighest,
                  child: done
                      ? Icon(
                          Icons.check,
                          size: 16,
                          color: theme.colorScheme.onPrimary,
                        )
                      : Text('$number', style: theme.textTheme.labelMedium),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    title,
                    style: const TextStyle(fontWeight: FontWeight.w600),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(hint, style: theme.textTheme.bodySmall),
            const SizedBox(height: 10),
            for (final line in details)
              Padding(
                padding: const EdgeInsets.only(bottom: 2),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('· ', style: theme.textTheme.bodySmall),
                    Expanded(
                      child: Text(line, style: theme.textTheme.bodySmall),
                    ),
                  ],
                ),
              ),
            if (active) ...[
              const SizedBox(height: 10),
              Row(
                children: [
                  Expanded(
                    flex: 3,
                    child: TextField(
                      controller: fields.host,
                      enabled: editable && !done,
                      autocorrect: false,
                      enableSuggestions: false,
                      decoration: InputDecoration(
                        labelText: tr(context, 'Адрес SSH'),
                        hintText: '203.0.113.7',
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      controller: fields.port,
                      enabled: editable && !done,
                      keyboardType: TextInputType.number,
                      decoration: InputDecoration(
                        labelText: tr(context, 'Порт'),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              TextField(
                controller: fields.username,
                enabled: editable && !done,
                autocorrect: false,
                enableSuggestions: false,
                decoration: InputDecoration(
                  labelText: tr(context, 'Пользователь'),
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: fields.password,
                enabled: editable && !done,
                obscureText: true,
                decoration: InputDecoration(
                  labelText: tr(context, 'Пароль SSH'),
                ),
              ),
              const SizedBox(height: 8),
              ExpansionTile(
                tilePadding: EdgeInsets.zero,
                childrenPadding: const EdgeInsets.only(bottom: 8),
                title: Text(tr(context, 'Вход по ключу вместо пароля')),
                children: [
                  TextField(
                    controller: fields.key,
                    enabled: editable && !done,
                    maxLines: 4,
                    autocorrect: false,
                    enableSuggestions: false,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11,
                    ),
                    decoration: InputDecoration(
                      labelText: tr(context, 'Приватный ключ (OpenSSH)'),
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: fields.passphrase,
                    enabled: editable && !done,
                    obscureText: true,
                    decoration: InputDecoration(
                      labelText: tr(context, 'Пароль ключа'),
                    ),
                  ),
                ],
              ),
              CheckboxListTile(
                value: purge,
                onChanged: _busy || done ? null : (v) => onPurge(v == true),
                contentPadding: EdgeInsets.zero,
                controlAffinity: ListTileControlAffinity.leading,
                title: Text(
                  tr(context, 'Очистить сервер перед установкой'),
                ),
                subtitle: Text(
                  tr(
                    context,
                    'Удаляет все компоненты XIO на этом хосте и оставляет пакеты ОС и чужие службы. Отключите VPN.',
                  ),
                ),
              ),
              const SizedBox(height: 6),
              Align(alignment: Alignment.centerLeft, child: action),
            ],
            if (evidence.isNotEmpty) ...[
              const SizedBox(height: 10),
              for (final line in evidence)
                Padding(
                  padding: const EdgeInsets.only(bottom: 3),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(
                        Icons.check,
                        size: 15,
                        color: theme.colorScheme.primary,
                      ),
                      const SizedBox(width: 6),
                      Expanded(
                        child: SelectableText(
                          line,
                          style: theme.textTheme.bodySmall,
                        ),
                      ),
                    ],
                  ),
                ),
            ],
          ],
        ),
      ),
    );
  }
}
