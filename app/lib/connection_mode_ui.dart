import 'package:flutter/material.dart';

import 'connection_attempt.dart';
import 'l10n.dart';
import 'policy_publication.dart';

/// Narrow seam between the frozen durable connection-mode Store API
/// (WIRE-V2 §7) and the two settings surfaces (Full and Client).
///
/// The Store stays authoritative. This interface only *reports* what the Store
/// publishes — `connectionPolicy`, `connectionModeConfirmation`,
/// `connectionModeConfirmed`, `connectionModePending`,
/// `canChangeConnectionMode`, `connectionPolicyError` — and forwards the two
/// publishing methods plus the two explicit recovery methods.
///
/// Reporting is not confirmation: [connectionPolicy] can be durable/requested
/// state that no live receipt covers, so "not pending and no error" is not
/// evidence that the engine bound this exact policy. Only
/// [connectionModeConfirmed] is a positive authoritative signal.
///
/// [connectionPolicyError] is a stable **blocker code**, not display text. The
/// UI localizes it with its own catalogue keys and never renders the Store's
/// English diagnostic ([AppStore.connectionPolicyMessage]).
///
/// Implementations must never cache a confirmed mode the Store has not
/// published, must never translate pending persisted intent into "applied",
/// must never describe a mode publication as an applied tunnel, and must never
/// choose a replacement profile when the manual selection is missing or
/// unusable.
abstract class ConnectionModeSource implements Listenable {
  /// Current durable/requested mode ([AppStore.connectionPolicy]). It may exist
  /// without any live native receipt. A draft is never stored here.
  ConnectionPolicy get connectionPolicy;

  /// What actually backs the displayed mode
  /// ([AppStore.connectionModeConfirmation]): only `native` is an ACK.
  ConnectionModeConfirmation get connectionModeConfirmation;

  /// Positively true only when an exact live native READY receipt describes the
  /// current generation ([AppStore.connectionModeConfirmed]). It does NOT mean
  /// an active tunnel, and a stored/legacy default must never show as confirmed.
  bool get connectionModeConfirmed;

  /// A publication/reconciliation round is outstanding or its outcome is
  /// unknown, or the store is not ready, or a document mutation is in flight
  /// ([AppStore.connectionModePending]).
  bool get connectionModePending;

  /// Idle-only admission for a new mode publication
  /// ([AppStore.canChangeConnectionMode]): exactly `connectionPolicyError ==
  /// null` in the Store. The Store guard remains authoritative; this value is
  /// what the control reflects.
  bool get canChangeConnectionMode;

  /// Stable blocker code ([AppStore.connectionPolicyError]): `loading`,
  /// `corrupt`, `publishPending`, `persistence`, `busy`, `reconcileRequired`,
  /// `disposed`, or null when a mode edit is admissible. Null does NOT mean
  /// confirmed: only [connectionModeConfirmed] does.
  String? get connectionPolicyError;

  /// True when the durable profile selection resolves to a usable candidate.
  /// False means manual mode has nothing to connect: the user has to pick a
  /// profile, the UI never repairs the selection silently.
  bool get selectedProfileUsable;

  /// One frozen settings+mode snapshot under one owner and one rename
  /// (`AppStore.saveConnectionSettings(..., policy:)`). A rejected mode leaves
  /// every field unmodified; a post-rename failure never reports success.
  Future<void> saveConnectionSettings(
    String site,
    String priority, {
    int? timeoutSeconds,
    bool? siteCheck,
    bool? reconnect,
    required ConnectionPolicy policy,
  });

  /// Explicit recovery for a preserved malformed durable policy
  /// ([AppStore.repairConnectionPolicy]). Never called implicitly.
  Future<void> repairConnectionPolicy(ConnectionPolicy policy);

  /// Bounded retry for `publishPending`/`reconcileRequired`
  /// ([AppStore.retryPolicyReconciliation]).
  Future<void> retryPolicyReconciliation();
}

/// Russian source strings for the mode UI: every value is a catalogue key, so
/// [LText] translates it and no surface invents its own wording.
class ConnectionModeText {
  const ConnectionModeText._();

  static String label(ConnectionPolicy policy) =>
      policy == ConnectionPolicy.selectedOnly
      ? 'Ручной режим'
      : 'Автоматический режим';

  /// Describes what each mode does to candidate selection, so the explanation
  /// next to the control is never an unconditional "falls back" claim.
  static String explanation(ConnectionPolicy policy) =>
      policy == ConnectionPolicy.selectedOnly
      ? 'Ручной режим: только выбранный профиль. Другие протоколы, профили и адреса не используются, в том числе при автозапуске и переподключении.'
      : 'Автоматический режим: при неудаче можно использовать другие протоколы, профили и адреса, в том числе при автозапуске и переподключении.';

  static String reconnect(ConnectionPolicy policy) =>
      policy == ConnectionPolicy.selectedOnly
      ? 'Пока туннель активен, приложение проверяет связь и при потере поднимает соединение заново только с выбранным профилем — другие протоколы, профили и адреса не используются.'
      : 'Пока туннель активен, приложение проверяет связь и при потере поднимает соединение заново — выбранный сервер, затем другой протокол, затем другой профиль.';

  /// The site-probe text used to name the next protocol on failure; manual mode
  /// never invents that next protocol.
  static String siteCheck({
    required bool enabled,
    required ConnectionPolicy policy,
  }) {
    final manual = policy == ConnectionPolicy.selectedOnly;
    if (enabled) {
      return manual
          ? 'Сайт проверяется после подключения. При раздельном туннелировании запрос следует правилам приложения; успешный ответ сам по себе не подтверждает маршрут всего трафика. Проверяется только выбранный профиль: запасной протокол не подбирается.'
          : 'Сайт проверяется после подключения. При раздельном туннелировании запрос следует правилам приложения; успешный ответ сам по себе не подтверждает маршрут всего трафика. Сначала проверяется приоритетный протокол; при неудаче — следующий из профиля пользователя.';
    }
    return manual
        ? 'Проверка сайта выключена: соединение подтверждается самим туннелем (свежий handshake, счётчики, DNS-ответ через туннель). Проверяется только выбранный профиль: запасной протокол не подбирается.'
        : 'Проверка сайта выключена: соединение подтверждается самим туннелем (свежий handshake, счётчики, DNS-ответ через туннель). При неудаче проверяется следующий протокол из профиля пользователя.';
  }

  /// Row label used when the current mode is only a stored setting: no live
  /// receipt covers it, so no "confirmed" badge may be shown.
  static const storedSetting = 'Сохранённая настройка';

  /// Explains the stored-setting row: the engine has not confirmed this mode.
  static const storedSettingNotice =
      'Движок ещё не подтвердил этот режим. Показана сохранённая настройка, а не подтверждённый режим.';

  /// Fallback for any blocker code the UI does not know, and the `busy` text.
  ///
  /// Deliberately reason-neutral: the blocker may be connection work (where
  /// disconnecting helps) or an unfinished document write (where it cannot).
  static const modeUnavailable =
      'Изменение режима недоступно: другая операция ещё не завершена. Дождитесь её завершения или согласования; при активном соединении сначала отключитесь.';

  /// Localized text for the Store's stable blocker code
  /// (`connectionPolicyError`). The codes are the Store contract; the sentences
  /// are UI keys. Unknown codes fall back to [modeUnavailable].
  static String blocker(String? code) => switch (code) {
    'loading' => 'Режим ещё загружается. Дождитесь окончания загрузки настроек.',
    'persistence' =>
      'Ещё одно сохранение не завершено. Дождитесь его окончания, прежде чем менять режим.',
    'busy' => modeUnavailable,
    'publishPending' =>
      'Сохранение или согласование режима не завершено. Подтверждение ещё не получено.',
    'reconcileRequired' =>
      'Режим требует согласования с движком. Подключение заблокировано до согласования.',
    'corrupt' =>
      'Сохранённый режим повреждён. Подключение заблокировано до явного восстановления; обычное переключение режима недоступно.',
    'disposed' => 'Настройки закрыты. Откройте их заново.',
    _ => modeUnavailable,
  };

  /// Explicit recovery action for a preserved malformed policy (`corrupt`).
  static const repairAction = 'Восстановить режим';

  /// Explicit bounded retry for `publishPending`/`reconcileRequired`.
  static const retryAction = 'Повторить согласование';

  /// An explicit recovery attempt failed; the blocker line still describes the
  /// state, so this only reports the attempt.
  static const recoveryFailed =
      'Восстановление не удалось. Режим по-прежнему заблокирован.';

  /// Stable, locale-independent token for a rejected or unconfirmed
  /// publication: a `PolicyFailure.code` or a `PublicationFailure.phase` name.
  static String? failureToken(Object error) {
    if (error is PolicyFailure) return error.code;
    if (error is PublicationFailure) return error.phase.name;
    return null;
  }

  /// Localized explanation for a failed publication. Only already-localized
  /// validation/storage messages (`FormatException`, `StateError`) pass through;
  /// every policy code and publication phase is mapped, so neither an English
  /// diagnostic nor a raw exception type reaches the UI.
  ///
  /// Each sentence states only what its phase proves (WIRE-V2 §5).
  static String saveFailure(Object error) {
    if (error is FormatException) return error.message.toString();
    if (error is StateError) return error.message.toString();
    if (error is PolicyFailure) {
      return switch (error.code) {
        'POLICY_BUSY' => modeUnavailable,
        'POLICY_PENDING' =>
          'Сохранение или согласование режима не завершено. Подтверждение ещё не получено.',
        'POLICY_INVALID' =>
          'Сохранённый режим повреждён. Подключение заблокировано до явного восстановления; обычное переключение режима недоступно.',
        'POLICY_UNKNOWN' =>
          'Режим требует согласования с движком. Подключение заблокировано до согласования.',
        'POLICY_UNSUPPORTED' =>
          'Этот движок не подтверждает выбранный режим. Ручной режим недоступен до обновления движка.',
        // Controller-local preflight (core `policy_channel`): the frozen
        // validation bundle is too large. Localized, never the English
        // diagnostic.
        'POLICY_OVERSIZE' =>
          'Слишком большой объём данных для публикации настроек. Уменьшите размер профилей и повторите.',
        _ => 'Операция не завершена. Проверьте профиль и разрешения.',
      };
    }
    if (error is PublicationFailure) {
      return switch (error.phase) {
        // The rename did not happen. That is NOT proof the previous mode is
        // still confirmed: a begin may already have fenced native READY.
        PublicationPhase.beforeRename =>
          'Файл не изменён: переименование не произошло. Движок режим не подтвердил, требуется согласование.',
        // The document may be renamed and the native commit may even have
        // succeeded with a lost ACK: "unconfirmed", never "not applied".
        PublicationPhase.renamedNativeUnconfirmed =>
          'Настройки сохранены; движок не подтвердил режим. Требуется согласование.',
        // Neither the durable file nor the native state is proven either way.
        PublicationPhase.pendingUnknown =>
          'Результат неизвестен: не подтверждены ни файл, ни режим в движке. Требуется согласование.',
        PublicationPhase.committed => 'Операция не завершена. Проверьте профиль и разрешения.',
      };
    }
    return 'Операция не завершена. Проверьте профиль и разрешения.';
  }
}

/// Shared mode control: the emphasised part of both connection-settings
/// surfaces.
///
/// The dropdown holds a *draft*. It is deliberately separate from
/// [ConnectionModeSource.connectionPolicy]: while a save is pending, or after a
/// failure/native-unknown result, the widget never renders the draft as a
/// confirmed mode.
class ConnectionModeControl extends StatefulWidget {
  const ConnectionModeControl({
    super.key,
    required this.source,
    required this.draft,
    required this.onChanged,
    this.saving = false,
  });

  final ConnectionModeSource source;

  /// Unsaved choice shown in the picker. Saving it is what asks the Store to
  /// publish a new mode.
  final ConnectionPolicy draft;

  final ValueChanged<ConnectionPolicy> onChanged;

  /// The enclosing form is currently awaiting its own save future.
  final bool saving;

  @override
  State<ConnectionModeControl> createState() => _ConnectionModeControlState();
}

class _ConnectionModeControlState extends State<ConnectionModeControl> {
  /// Local outcome of an explicit recovery action; never a mode claim.
  String? actionError;
  bool actionBusy = false;

  ConnectionModeSource get source => widget.source;

  Future<void> runAction(Future<void> Function() action) async {
    // A second tap in the same frame must not start a duplicate recovery; the
    // Store's own admission remains the second line of defence.
    if (actionBusy) return;
    setState(() {
      actionBusy = true;
      actionError = null;
    });
    try {
      await action();
    } catch (error) {
      if (mounted) {
        setState(() => actionError = ConnectionModeText.recoveryFailed);
      }
    } finally {
      if (mounted) setState(() => actionBusy = false);
    }
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: source,
    builder: (context, _) => buildControl(context),
  );

  Widget buildControl(BuildContext context) {
    final pending = source.connectionModePending;
    final blocker = source.connectionPolicyError;
    final busy = widget.saving || pending || actionBusy;
    // Explicit recovery is gated on a genuinely in-flight UI action, not on the
    // persisted unconfirmed state it exists to settle. The Store admission (and
    // its refusal) stays authoritative for the action itself.
    final recoveryLocked = widget.saving || actionBusy;
    // A corrupt policy blocks publishing, but the explicit repair path takes a
    // chosen replacement mode, so the draft stays editable in that state.
    final canEditDraft =
        (source.canChangeConnectionMode || blocker == 'corrupt') && !busy;
    // Only the Store's positive native receipt may show the badge.
    final confirmed =
        source.connectionModeConfirmed &&
        source.connectionModeConfirmation == ConnectionModeConfirmation.native &&
        !busy;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const LText(
          'Режим подключения',
          style: TextStyle(fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: 4),
        if (busy)
          const LText(
            'Сохранение или согласование режима не завершено. Подтверждение ещё не получено.',
          )
        else if (confirmed)
          // Wrap, not Row: the confirmed label and the mode name must survive
          // narrow phones and long translations without clipping.
          Wrap(
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              const LText('Подтверждённый режим'),
              const Text(': '),
              LText(ConnectionModeText.label(source.connectionPolicy)),
            ],
          )
        else
          // No live receipt: shown as a stored setting, never with a
          // confirmed-native badge.
          Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Wrap(
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  const LText(ConnectionModeText.storedSetting),
                  const Text(': '),
                  LText(ConnectionModeText.label(source.connectionPolicy)),
                ],
              ),
              const SizedBox(height: 4),
              const LText(ConnectionModeText.storedSettingNotice),
            ],
          ),
        const SizedBox(height: 12),
        DropdownButtonFormField<ConnectionPolicy>(
          key: const ValueKey('connection-mode-draft'),
          initialValue: widget.draft,
          isExpanded: true,
          decoration: InputDecoration(
            labelText: tr(context, 'Черновик режима'),
          ),
          items: [
            for (final policy in ConnectionPolicy.values)
              DropdownMenuItem(
                value: policy,
                child: LText(ConnectionModeText.label(policy)),
              ),
          ],
          onChanged: canEditDraft
              ? (value) {
                  if (value != null) widget.onChanged(value);
                }
              : null,
        ),
        const SizedBox(height: 8),
        LText(ConnectionModeText.explanation(widget.draft)),
        if (widget.draft == ConnectionPolicy.selectedOnly &&
            !source.selectedProfileUsable)
          const Padding(
            padding: EdgeInsets.only(top: 8),
            child: LText(
              'Выберите доступный профиль в списке подключений. Ручной режим не выбирает замену автоматически.',
            ),
          ),
        if (!source.canChangeConnectionMode && blocker != null)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: LText(ConnectionModeText.blocker(blocker)),
          ),
        // Explicit recovery paths: only the Store decides whether they apply,
        // and none of them publishes a mode on its own.
        if (!actionBusy && blocker == 'corrupt')
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: OutlinedButton(
              key: const ValueKey('connection-mode-repair'),
              onPressed: () =>
                  runAction(() => source.repairConnectionPolicy(widget.draft)),
              child: const LText(ConnectionModeText.repairAction),
            ),
          ),
        if (!actionBusy &&
            (blocker == 'publishPending' || blocker == 'reconcileRequired'))
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: OutlinedButton(
              key: const ValueKey('connection-mode-retry'),
              onPressed: () => runAction(source.retryPolicyReconciliation),
              child: const LText(ConnectionModeText.retryAction),
            ),
          ),
        if (actionError != null)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: LText(actionError!),
          ),
        const SizedBox(height: 16),
      ],
    );
  }
}
