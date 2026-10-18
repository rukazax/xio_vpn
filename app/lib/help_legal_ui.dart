import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'dart:convert';

import 'core.dart';
import 'l10n.dart';
import 'legal_record.dart';

String get legalLanguage => AppLanguages.effective == 'ru' ? 'ru' : 'en';
Future<String> legalText() =>
    rootBundle.loadString('assets/help/legal.$legalLanguage.txt');
String _androidVpnText() => AppLanguages.effective == 'ru'
    ? 'XIO использует Android VpnService для передачи выбранного вами трафика через выбранный VPN-сервер. Между устройством и VPN-сервером трафик шифруется. Владелец сервера может видеть ваш IP, адреса назначения и сетевые метаданные; содержимое HTTPS защищается самим HTTPS.\n\nПрофили, SSH-секреты и запись ознакомления сохраняются на устройстве. При управлении VPS по SSH на него отправляются команды, ключи и настройки пользователей. Сервер хранит пользователей, статус и счётчики трафика. Для флага страны адрес сервера может отправляться ipapi.co. Проверка соединения обращается к выбранному сайту (по умолчанию youtube.com), который видит адрес выхода.\n\nВ этой сборке нет встроенной рекламы и аналитического SDK. XIO не перенаправляет рекламу ради монетизации. Экспорт профиля передаёт его секреты выбранному вами получателю. Не используйте чужой VPS без разрешения.\n\nAndroid отдельно запросит системное разрешение VPN при первом подключении. Если вы не согласны, закройте приложение; подключение не начнётся. Эти сведения доступны в разделе лицензии.'
    : 'XIO uses Android VpnService to send selected device traffic through your selected VPN server. Traffic between device and VPN endpoint is encrypted. The server operator may observe your IP address, destinations and network metadata; HTTPS content is protected by HTTPS.\n\nProfiles, SSH secrets and the acknowledgement are stored on this device. VPS administration sends commands, keys and user settings over SSH to that VPS. The server stores users, status and traffic counters. Server addresses may be sent to ipapi.co for country flags. Connectivity checks contact your selected website (youtube.com by default), which sees the exit address.\n\nThis build has no advertising or analytics SDK and does not redirect advertising for monetisation. Exporting profiles shares their secrets with your selected recipient. Only administer servers you are authorised to manage.\n\nAndroid requests separate system VPN permission on first connection. If you do not agree, close the app; no connection starts. These disclosures remain available in the licence section.';

String vpnText() {
  if (Platform.isAndroid) return _androidVpnText();
  final ru = AppLanguages.effective == 'ru';
  final platform = Platform.isIOS
      ? 'iOS Network Extension'
      : 'a separate administrator-authorised local VPN helper';
  if (ru) {
    return 'XIO передаёт выбранный трафик через ваш VPN-сервер. Соединение от устройства до VPN-сервера шифруется; содержимое HTTPS дополнительно защищается самим HTTPS. Владелец сервера может видеть адрес подключения, направления и метаданные трафика.\n\n'
        '${Platform.isIOS ? 'На iPhone используется отдельное VPN-расширение iOS. Система запросит разрешение на VPN. В этой версии iOS встроены RIVET/H3 и RIVET/S1; остальные конфигурации сохраняются для переноса между платформами.' : 'В Ubuntu и Windows изменение сетевых маршрутов и DNS выполняет отдельный локальный помощник с подтверждением прав администратора. Интерфейс работает без повышенных прав. IPv4-туннель и поддерживаемые движки определяются для этой платформы; работа на другой ОС требует отдельной проверки.'}\n\n'
        'Профили, SSH-доступ и запись ознакомления хранятся на устройстве. Управление VPS передаёт команды, настройки и ключи на выбранный сервер по SSH. Экспорт профиля передаёт его секреты получателю. Для флага страны адрес сервера может передаваться ipapi.co; проверка соединения обращается к выбранному HTTPS-сайту (по умолчанию youtube.com), а DNS — к настроенному DNS-серверу.\n\n'
        'Встроенной рекламы и аналитического SDK нет. Если вы не согласны, закройте приложение без подтверждения: новое подключение не начнётся. Сведения остаются доступны в разделе лицензии.';
  }
  return 'XIO uses $platform to route device traffic through your selected VPN endpoint. Device-to-endpoint traffic is encrypted; HTTPS provides additional application encryption. The server operator may see your connection address, destinations and network metadata.\n\n'
      '${Platform.isIOS ? 'iOS requests separate system VPN permission. This iOS version integrates RIVET/H3 and RIVET/S1; other imported configurations are retained for cross-platform portability.' : 'On Ubuntu and Windows the local helper changes routes and DNS only after system administrator authorisation. The UI runs without elevated privileges. Engine and IPv4 tunnel availability are platform specific.'}\n\n'
      'Profiles, SSH access and acknowledgements stay on this device. VPS administration sends commands, settings and keys over SSH to that server. Exports share profile secrets. Server addresses may be sent to ipapi.co for country flags; checks contact your chosen HTTPS website (youtube.com by default), and DNS contacts the configured DNS server.\n\n'
      'There is no built-in advertising or analytics SDK. If you disagree, close this screen without consenting: no new VPN connection starts. These disclosures remain available in the licence section.';
}

class FirstRunGate extends StatelessWidget {
  final AppStore store;
  final Widget child;
  const FirstRunGate({super.key, required this.store, required this.child});
  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: store,
    builder: (context, _) {
      if (!store.ready) {
        return const Scaffold(body: Center(child: CircularProgressIndicator()));
      }
      if (store.legalRecord?.current != true) {
        return _Acknowledgement(
          key: const ValueKey('terms-screen'),
          store: store,
          vpn: false,
        );
      }
      if (store.vpnDisclosure != vpnDisclosureRevision) {
        return _Acknowledgement(
          key: const ValueKey('vpn-screen'),
          store: store,
          vpn: true,
        );
      }
      return child;
    },
  );
}

class _Acknowledgement extends StatefulWidget {
  final AppStore store;
  final bool vpn;
  const _Acknowledgement({super.key, required this.store, required this.vpn});
  @override
  State<_Acknowledgement> createState() => _AcknowledgementState();
}

class _AcknowledgementState extends State<_Acknowledgement> {
  bool checked = false, saving = false;
  late final Future<String> text = widget.vpn
      ? Future.value(vpnText())
      : legalText();
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: LText(
        widget.vpn ? 'Как работает VPN' : 'Лицензия и ответственность',
      ),
    ),
    body: SafeArea(
      child: FutureBuilder<String>(
        future: text,
        builder: (context, s) {
          if (s.hasError) {
            return const Center(child: LText('Не удалось загрузить документ'));
          }
          if (!s.hasData) {
            return const Center(child: CircularProgressIndicator());
          }
          return ListView(
            padding: const EdgeInsets.all(20),
            children: [
              SelectableText(s.data!),
              if (!widget.vpn)
                TextButton(
                  onPressed: () => Navigator.of(
                    context,
                  ).push(MaterialPageRoute(builder: (_) => const _FullGpl())),
                  child: const LText("Полный текст GPLv3"),
                ),
              const SizedBox(height: 16),
              CheckboxListTile(
                key: ValueKey(widget.vpn ? 'vpn-ack' : 'legal-ack'),
                value: checked,
                controlAffinity: ListTileControlAffinity.leading,
                title: LText(
                  widget.vpn ? 'Я согласен с описанным использованием VPN' : 'Я ознакомился с лицензией и уведомлением об ответственности',
                ),
                onChanged: saving
                    ? null
                    : (v) => setState(() => checked = v ?? false),
              ),
              FilledButton(
                key: const ValueKey('ack-continue'),
                onPressed: !checked || saving
                    ? null
                    : () async {
                        setState(() => saving = true);
                        try {
                          if (widget.vpn) {
                            await widget.store.acknowledgeVpn();
                          } else {
                            await widget.store.acknowledgeLegal(
                              s.data!,
                              legalLanguage,
                            );
                          }
                        } catch (_) {
                          if (context.mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: LText(
                                  'Не удалось сохранить подтверждение',
                                ),
                              ),
                            );
                          }
                        } finally {
                          if (mounted) {
                            setState(() {
                              saving = false;
                              checked = false;
                            });
                          }
                        }
                      },
                child: const LText('Продолжить'),
              ),
            ],
          );
        },
      ),
    ),
  );
}

class LegalDetails extends StatelessWidget {
  final AppStore store;
  const LegalDetails({super.key, required this.store});
  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: store,
    builder: (context, _) => Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ListTile(
          leading: Icon(
            store.consentReady ? Icons.verified_outlined : Icons.info_outline,
          ),
          title: LText(
            store.consentReady
                ? 'Ознакомление подтверждено на этом устройстве'
                : 'Ознакомление не подтверждено',
          ),
          subtitle: Text(
            'GPL-3.0-only · $legalRevision\n${store.legalRecord?.timestamp ?? "—"}\nVPN: ${store.vpnDisclosure ?? "—"}',
          ),
        ),
        if (store.legalRecord != null)
          SelectableText(
            'SHA-256: ${store.legalRecord!.textSha256}',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        const SizedBox(height: 16),
        FutureBuilder<String>(
          future: legalText(),
          builder: (context, s) => SelectableText(s.data ?? '…'),
        ),
        const SizedBox(height: 16),
        const SelectableText(
          'Исходники / Source code: supplied with each release.\nCopyright © 2026 Ерёмин Константин Александрович\ner-ka@mail.ru',
        ),
        TextButton(
          onPressed: () =>
              Navigator.of(context)
                  .push(MaterialPageRoute(builder: (_) => const _FullGpl())),
          child: const LText('Полный текст GPLv3'),
        ),
        TextButton(
          onPressed: () =>
              Navigator.of(context)
                  .push(MaterialPageRoute(builder: (_) => const PrivacyPage())),
          child: const LText('Политика конфиденциальности'),
        ),
        TextButton(
          onPressed: () => showLicensePage(
            context: context,
            applicationName: 'XIO',
            applicationVersion: '0.18.0',
          ),
          child: const LText('Лицензии компонентов'),
        ),
        ExpansionTile(
          title: const LText('Как работает VPN'),
          children: [
            Padding(
              padding: const EdgeInsets.all(12),
              child: SelectableText(vpnText()),
            ),
          ],
        ),
      ],
    ),
  );
}

class _FullGpl extends StatefulWidget {
  const _FullGpl();
  @override
  State<_FullGpl> createState() => _FullGplState();
}

class _FullGplState extends State<_FullGpl> {
  late final text = rootBundle.loadString('assets/licenses/XIO-GPL-3.0.txt');
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('GNU GPLv3')),
    body: FutureBuilder<String>(
      future: text,
      builder: (context, s) => SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: SelectableText(s.data ?? '…'),
      ),
    ),
  );
}

class HelpContent extends StatefulWidget {
  const HelpContent({super.key});
  @override
  State<HelpContent> createState() => _HelpContentState();
}

class _HelpContentState extends State<HelpContent> {
  late final Future<List<dynamic>> content = rootBundle
      .loadString('assets/help/faq.$legalLanguage.json')
      .then((v) => jsonDecode(v) as List);
  @override
  Widget build(BuildContext context) => FutureBuilder<List<dynamic>>(
    future: content,
    builder: (context, s) => Column(
      children: [
        if (s.hasError) const LText('Не удалось загрузить документ'),
        for (final row in s.data ?? [])
          ExpansionTile(
            title: Text(row['q'] as String),
            children: [
              Padding(
                padding: const EdgeInsets.all(12),
                child: SelectableText(row['a'] as String),
              ),
            ],
          ),
      ],
    ),
  );
}

class PrivacyPage extends StatefulWidget {
  const PrivacyPage({super.key});
  @override
  State<PrivacyPage> createState() => _PrivacyPageState();
}

class _PrivacyPageState extends State<PrivacyPage> {
  late final text = rootBundle.loadString(
    'assets/help/privacy.$legalLanguage.txt',
  );
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Политика конфиденциальности')),
    body: FutureBuilder<String>(
      future: text,
      builder: (context, s) => SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: SelectableText(s.data ?? '…'),
      ),
    ),
  );
}
