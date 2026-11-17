import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'cascade_native.dart';
import 'core.dart';
import 'l10n.dart';
import 'managed_service.dart';
import 'server_address.dart';

/// Opens a connection to one server. Injectable so a widget test can drive the
/// dialog without a host; production uses [VpsService].
typedef CascadeSshOpener = Future<VpsService> Function(
  SshTarget target,
  String password,
  String privateKey,
  String passphrase,
);

/// One action for the whole cascade.
///
/// The wizard used to be two buttons with two separate proofs. A cascade is one
/// operation with a fixed order — the exit is installed first, the bridge second,
/// because the bridge key must be authorized on the exit before the bridge unit
/// starts — so it is one button now. While it runs, the plan of each server is
/// drawn with the step being applied and the line that proved the previous one;
/// when a step fails, the reason is shown together with the host output and the
/// service journal, so the operator does not have to open an SSH session to learn
/// what happened.
class CascadeWizardDialog extends StatefulWidget {
  const CascadeWizardDialog({
    super.key,
    required this.store,
    this.bridgeHint,
    this.openSsh,
    this.cleanServer,
  });

  final AppStore store;
  final String? bridgeHint;

  /// Connection seam for tests. When null the dialog opens a real [VpsService].
  final CascadeSshOpener? openSsh;

  /// Removal seam for tests. When null the dialog purges through
  /// [ManagedService], which is what the checkbox always meant.
  final Future<void> Function(VpsService ssh)? cleanServer;

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

/// SSH fields for one host. Kept as a plain holder so both servers look the same
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
  final _exit = _HostFields();
  final _bridge = _HostFields();
  VpsService? _exitSsh, _bridgeSsh;
  bool _busy = false;
  bool _finished = false;
  String? _error;
  CascadeStageFailure? _failure;
  final Map<String, CascadeStepState> _stepStates = {};
  final Map<String, String> _stepDetails = {};
  final List<String> _logs = [];
  final GlobalKey _resultKey = GlobalKey();
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

  static String _key(CascadeInstallStage stage, String id) =>
      '${stage.name}:$id';

  /// The plan of one server with the current choice of cleanup, so the checkbox
  /// adds its step to the picture instead of hiding work behind the button.
  List<CascadePlanStep> _plan(CascadeInstallStage stage) => cascadePlanSteps(
    stage,
    clean: stage == CascadeInstallStage.exit ? _purgeExit : _purgeBridge,
  );

  bool get _showSteps =>
      _busy || _finished || _failure != null || _stepStates.isNotEmpty;

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

  Future<VpsService> _openSsh(
    SshTarget target,
    String password,
    String privateKey,
    String passphrase,
  ) async {
    final ssh = VpsService();
    await ssh.open(target, password, privateKey, passphrase);
    return ssh;
  }

  Future<VpsService> _connect(
    _HostFields fields,
    CascadeInstallStage stage,
  ) async {
    final target = SshTarget(
      normalizeServerHost(fields.host.text),
      int.parse(fields.port.text.trim()),
      fields.username.text.trim(),
      '',
    );
    try {
      final opener = widget.openSsh ?? _openSsh;
      return await opener(
        target,
        fields.password.text,
        fields.key.text,
        fields.passphrase.text,
      );
    } catch (error) {
      throw CascadeStageFailure(cascadeStageTitle(stage), switch (error) {
        FormatException(:final message) => message,
        StateError(:final message) => message,
        _ => '$error',
      });
    }
  }

  Future<void> _clean(VpsService ssh) async {
    final custom = widget.cleanServer;
    if (custom != null) return custom(ssh);
    await ManagedService(ssh).purge(widget.store);
  }

  void _onStep(CascadeStepEvent event) {
    if (!mounted) return;
    final key = _key(event.stage, event.id);
    setState(() {
      _stepStates[key] = event.state;
      final detail = event.detail;
      if (detail != null && detail.isNotEmpty) _stepDetails[key] = detail;
    });
  }

  /// One pass over both servers. Nothing is saved until the bridge has proven
  /// the tunnel; a failure keeps the dialogs's connections usable for a retry.
  Future<void> _install() async {
    final problem = _validate(_exit, 'Exit') ?? _validate(_bridge, 'Bridge');
    if (problem != null) return setState(() => _error = problem);
    final exitHost = normalizeServerHost(_exit.host.text);
    final bridgeHost = normalizeServerHost(_bridge.host.text);
    await _exitSsh?.close();
    await _bridgeSsh?.close();
    _exitSsh = null;
    _bridgeSsh = null;
    setState(() {
      _busy = true;
      _error = null;
      _failure = null;
      _finished = false;
      _logs.clear();
      _stepStates.clear();
      _stepDetails.clear();
      _egress = '';
    });
    try {
      final exitSsh = await _connect(_exit, CascadeInstallStage.exit);
      _exitSsh = exitSsh;
      final bridgeSsh = await _connect(_bridge, CascadeInstallStage.bridge);
      _bridgeSsh = bridgeSsh;
      await installCascade(
        exitSsh: exitSsh,
        bridgeSsh: bridgeSsh,
        exitHost: exitHost,
        cleanExit: _purgeExit ? _clean : null,
        cleanBridge: _purgeBridge ? _clean : null,
        onStep: _onStep,
      );
      final egress = await cascadeEgressIp(exitSsh);
      final saved = await widget.store.setCascadeServers(
        bridge: bridgeHost,
        exit: exitHost,
      );
      _exit.password.clear();
      _exit.key.clear();
      _exit.passphrase.clear();
      _bridge.password.clear();
      _bridge.key.clear();
      _bridge.passphrase.clear();
      if (!mounted) return;
      setState(() {
        _finished = true;
        _egress = egress;
        _exitHost = exitHost;
        _bridgeHost = bridgeHost;
        if (!saved) {
          _error = tr(context, 'Каскад поднят, но адрес не сохранён');
        }
      });
      _revealResult();
    } on CascadeStageFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _failure = failure;
        _logs
          ..clear()
          ..addAll(failure.logs);
      });
      _revealResult();
    } catch (error) {
      if (mounted) setState(() => _error = _message(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String _message(Object error) => switch (error) {
    CascadeStageFailure(:final stage, :final message) => '$stage: $message',
    StateError(:final message) => message,
    FormatException(:final message) => message,
    _ => tr(
      context,
      'Не удалось выполнить этап. Проверьте SSH-доступ и состояние сервера.',
    ),
  };

  Future<void> _copyLogs() async {
    final failure = _failure;
    final text = <String>[
      if (failure != null) failure.toString(),
      if (failure != null) '',
      ..._logs,
    ].join('\n');
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(tr(context, 'Логи скопированы'))));
  }

  /// Moves the scroll view to the success or failure card: it sits below both
  /// server cards, and a failure that stays off-screen is the same as no failure
  /// message at all.
  void _revealResult() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final context = _resultKey.currentContext;
      if (context == null) return;
      Scrollable.ensureVisible(
        context,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
        alignment: 0.15,
      );
    });
  }

  void _close() {
    _exitSsh?.close();
    _bridgeSsh?.close();
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final plan = <CascadePlanStep>[
      ..._plan(CascadeInstallStage.exit),
      ..._plan(CascadeInstallStage.bridge),
    ];
    final done = plan
        .where(
          (step) =>
              _stepStates[_key(step.stage, step.id)] == CascadeStepState.done,
        )
        .length;
    return Dialog(
      insetPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 24),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 780, maxHeight: 760),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 18, 16, 8),
              child: Row(
                children: [
                  const Icon(Icons.hub_outlined),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      tr(context, 'Мастер каскада'),
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  Text(
                    '$done/${plan.length}',
                    style: theme.textTheme.labelMedium,
                  ),
                ],
              ),
            ),
            LinearProgressIndicator(
              value: plan.isEmpty ? 0 : done / plan.length,
            ),
            Flexible(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _serverCard(
                      stage: CascadeInstallStage.exit,
                      fields: _exit,
                      title: tr(context, 'Exit · зарубежный VPS'),
                      hint: tr(
                        context,
                        'Этот сервер будет выпускать трафик в интернет.',
                      ),
                      details: const [
                        'tun0 10.250.0.2/30 and fd78:2::2/64',
                        'IP forwarding and NAT for cascade clients',
                        'PermitTunnel yes in a drop-in, sshd -t before reload',
                      ],
                      purge: _purgeExit,
                      onPurge: (value) => setState(() => _purgeExit = value),
                    ),
                    const SizedBox(height: 12),
                    _serverCard(
                      stage: CascadeInstallStage.bridge,
                      fields: _bridge,
                      title: tr(context, 'Bridge · точка входа'),
                      hint: tr(
                        context,
                        'Клиенты подключаются сюда, трафик уходит на exit.',
                      ),
                      details: const [
                        'tun0 10.250.0.1/30 and fd78:2::1/64',
                        'key /root/.ssh/xio_cascade authorized on exit',
                        'policy iif xio* → table 51888, fwmark 0x518, SNAT, MSS clamp',
                      ],
                      purge: _purgeBridge,
                      onPurge: (value) => setState(() => _purgeBridge = value),
                    ),
                    if (_finished) ...[
                      const SizedBox(height: 12),
                      KeyedSubtree(key: _resultKey, child: _successCard(theme)),
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
                    if (_failure != null) ...[
                      const SizedBox(height: 10),
                      KeyedSubtree(
                        key: _resultKey,
                        child: _failureCard(theme, _failure!),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 6, 16, 14),
              // A Wrap, not a Row: at 360 px the two buttons do not fit on one
              // line and a Row would overflow instead of wrapping.
              child: Wrap(
                alignment: WrapAlignment.spaceBetween,
                crossAxisAlignment: WrapCrossAlignment.center,
                spacing: 8,
                runSpacing: 4,
                children: [
                  TextButton(
                    onPressed: _busy ? null : _close,
                    child: Text(
                      _finished
                          ? tr(context, 'Закрыть')
                          : tr(context, 'Отмена'),
                    ),
                  ),
                  if (!_finished)
                    FilledButton.icon(
                      onPressed: _busy ? null : _install,
                      icon: const Icon(Icons.bolt),
                      label: Text(tr(context, 'Установить каскад')),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _severityIcon(CascadeInstallStage stage, List<CascadePlanStep> plan) {
    final theme = Theme.of(context);
    final states = <CascadeStepState?>[
      for (final step in plan) _stepStates[_key(step.stage, step.id)],
    ];
    if (_failure?.stage == cascadeStageTitle(stage) ||
        states.contains(CascadeStepState.failed)) {
      return Icon(Icons.error, size: 18, color: theme.colorScheme.error);
    }
    if (states.contains(CascadeStepState.running)) {
      return const SizedBox(
        width: 15,
        height: 15,
        child: CircularProgressIndicator(strokeWidth: 2),
      );
    }
    if (states.isNotEmpty && states.every((s) => s == CascadeStepState.done)) {
      return Icon(
        Icons.check_circle,
        size: 18,
        color: theme.colorScheme.primary,
      );
    }
    return Icon(
      Icons.radio_button_unchecked,
      size: 18,
      color: theme.colorScheme.outlineVariant,
    );
  }

  Widget _serverCard({
    required CascadeInstallStage stage,
    required _HostFields fields,
    required String title,
    required String hint,
    required List<String> details,
    required bool purge,
    required ValueChanged<bool> onPurge,
  }) {
    final theme = Theme.of(context);
    final plan = _plan(stage);
    final done = plan
        .where(
          (step) =>
              _stepStates[_key(step.stage, step.id)] == CascadeStepState.done,
        )
        .length;
    final editable = !_busy && !_finished;
    final prefix = stage == CascadeInstallStage.exit ? 'exit' : 'bridge';
    return Card(
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(
          color: done == plan.length && plan.isNotEmpty
              ? theme.colorScheme.primary
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
                _severityIcon(stage, plan),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    title,
                    style: const TextStyle(fontWeight: FontWeight.w600),
                  ),
                ),
                if (_showSteps)
                  Text(
                    '$done/${plan.length}',
                    style: theme.textTheme.labelSmall,
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
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  flex: 3,
                  child: TextField(
                    key: ValueKey('cascade-$prefix-host'),
                    controller: fields.host,
                    enabled: editable,
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
                    enabled: editable,
                    keyboardType: TextInputType.number,
                    decoration: InputDecoration(labelText: tr(context, 'Порт')),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            TextField(
              controller: fields.username,
              enabled: editable,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: tr(context, 'Пользователь'),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              key: ValueKey('cascade-$prefix-password'),
              controller: fields.password,
              enabled: editable,
              obscureText: true,
              decoration: InputDecoration(labelText: tr(context, 'Пароль SSH')),
            ),
            const SizedBox(height: 8),
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              childrenPadding: const EdgeInsets.only(bottom: 8),
              title: Text(tr(context, 'Вход по ключу вместо пароля')),
              children: [
                TextField(
                  controller: fields.key,
                  enabled: editable,
                  maxLines: 4,
                  autocorrect: false,
                  enableSuggestions: false,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                  decoration: InputDecoration(
                    labelText: tr(context, 'Приватный ключ (OpenSSH)'),
                  ),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: fields.passphrase,
                  enabled: editable,
                  obscureText: true,
                  decoration: InputDecoration(
                    labelText: tr(context, 'Пароль ключа'),
                  ),
                ),
              ],
            ),
            CheckboxListTile(
              value: purge,
              onChanged: editable ? (value) => onPurge(value == true) : null,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              title: Text(tr(context, 'Очистить сервер перед установкой')),
              subtitle: Text(
                tr(
                  context,
                  'Удаляет все компоненты XIO на этом хосте и оставляет пакеты ОС и чужие службы. Отключите VPN.',
                ),
              ),
            ),
            if (_showSteps) ...[
              const Divider(height: 18),
              for (final step in plan) _stepRow(step),
            ],
          ],
        ),
      ),
    );
  }

  Widget _stepRow(CascadePlanStep step) {
    final theme = Theme.of(context);
    final key = _key(step.stage, step.id);
    final state = _stepStates[key];
    final detail = _stepDetails[key];
    final failed = state == CascadeStepState.failed;
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 18,
            height: 18,
            child: Center(
              child: switch (state) {
                null => Icon(
                  Icons.radio_button_unchecked,
                  size: 13,
                  color: theme.colorScheme.outlineVariant,
                ),
                CascadeStepState.running => const SizedBox(
                  width: 13,
                  height: 13,
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
                CascadeStepState.done => Icon(
                  Icons.check_circle,
                  size: 15,
                  color: theme.colorScheme.primary,
                ),
                CascadeStepState.failed => Icon(
                  Icons.error,
                  size: 15,
                  color: theme.colorScheme.error,
                ),
              },
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  step.label,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: failed ? theme.colorScheme.error : null,
                    fontWeight: state == CascadeStepState.running
                        ? FontWeight.w600
                        : null,
                  ),
                ),
                if (detail != null && detail.isNotEmpty)
                  Text(
                    detail,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: failed
                          ? theme.colorScheme.error
                          : theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _successCard(ThemeData theme) => Card(
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
                  style: const TextStyle(fontWeight: FontWeight.w600),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          SelectableText('$_bridgeHost → $_exitHost'),
          Text('IPv4 egress: $_egress'),
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
  );

  Widget _failureCard(ThemeData theme, CascadeStageFailure failure) {
    final title = failure.step.isEmpty
        ? failure.stage
        : '${failure.stage} · ${failure.step}';
    return Card(
      color: theme.colorScheme.errorContainer,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.error_outline),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    title,
                    style: const TextStyle(fontWeight: FontWeight.w600),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            SelectableText(failure.message),
            if (_logs.isNotEmpty) ...[
              const SizedBox(height: 8),
              Row(
                children: [
                  Text(tr(context, 'Логи'), style: theme.textTheme.labelLarge),
                  const Spacer(),
                  TextButton.icon(
                    onPressed: _copyLogs,
                    icon: const Icon(Icons.copy_all, size: 16),
                    label: Text(tr(context, 'Копировать')),
                  ),
                ],
              ),
              Container(
                width: double.infinity,
                constraints: const BoxConstraints(maxHeight: 220),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surface,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(8),
                  child: SelectableText(
                    _logs.join('\n'),
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11,
                    ),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
