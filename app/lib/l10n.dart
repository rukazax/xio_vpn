import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Shared by Flutter and Android notifications. Catalogues are bundled, offline.
class AppLanguages {
  static const names = <String, String>{
    'ru': 'Русский',
    'en': 'English',
    'de': 'Deutsch',
    'es': 'Español',
    'fr': 'Français',
    'it': 'Italiano',
    'pt': 'Português',
    'zh': '中文',
    'ja': '日本語',
    'ko': '한국어',
    'tr': 'Türkçe',
    'hi': 'हिन्दी',
    'ar': 'العربية',
  };
  static const locales = [
    Locale('ru'),
    Locale('en'),
    Locale('de'),
    Locale('es'),
    Locale('fr'),
    Locale('it'),
    Locale('pt'),
    Locale('zh'),
    Locale('ja'),
    Locale('ko'),
    Locale('tr'),
    Locale('hi'),
    Locale('ar'),
  ];
  static final revision = ValueNotifier<int>(0);
  static final Map<String, Map<String, String>> catalogs = {};
  static String? selected;
  static bool loaded = false;
  static String resolve(Iterable<Locale> locales) {
    for (final locale in locales) {
      if (names.containsKey(locale.languageCode)) return locale.languageCode;
    }
    return 'en';
  }

  static String get effective =>
      selected ?? resolve(WidgetsBinding.instance.platformDispatcher.locales);
  static Future<void> load() async {
    final results = await Future.wait(
      names.keys.map(
        (code) async => MapEntry(
          code,
          Map<String, String>.from(
            jsonDecode(await rootBundle.loadString('assets/l10n/$code.json'))
                as Map,
          ),
        ),
      ),
    );
    catalogs.addEntries(results);
    _templates = catalogs["ru"]!.keys.where((k) => k.contains("{0}")).toList()
      ..sort(
        (a, b) => b
            .replaceAll(RegExp(r"\{\d+\}"), "")
            .length
            .compareTo(a.replaceAll(RegExp(r"\{\d+\}"), "").length),
      );
    loaded = true;
  }

  static void set(String? code) {
    if (code != null && !names.containsKey(code)) {
      throw ArgumentError.value(code, 'language');
    }
    selected = code;
    revision.value++;
  }

  static final _patterns = <String, RegExp>{};
  static List<String> _templates = [];
  static String text(
    String input, {
    String? language,
    bool isolateArguments = false,
  }) {
    final code = language ?? effective;
    // Uninitialised standalone widget/test hosts retain the source language.
    if (!loaded || code == 'ru') return input;
    final catalog = catalogs[code] ?? catalogs['en']!;
    final direct = catalog[input];
    if (direct != null) return direct;
    for (final key in _templates) {
      final pattern = _patterns.putIfAbsent(
        key,
        () => RegExp(
          '^${RegExp.escape(key).replaceAllMapped(RegExp(r'\\\{(\d+)\\\}'), (_) => r'(.+?)')}'
          r'$',
          dotAll: true,
        ),
      );
      final match = pattern.firstMatch(input);
      if (match != null) {
        final indices = RegExp(r'\{(\d+)\}')
            .allMatches(key)
            .map((m) => m[1]!)
            .toList();
        var value = catalog[key] ?? catalogs['en']![key] ?? key;
        final values = <String, String>{};
        for (var i = 0; i < indices.length; i++) {
          values[indices[i]] = match.group(i + 1)!;
        }
        value = value.replaceAllMapped(RegExp(r'\{(\d+)\}'), (m) {
          final argument = values[m[1]] ?? m[0]!;
          // LRI/PDI affects presentation only; stored names/configurations stay plain.
          return isolateArguments &&
                  code == 'ar' &&
                  RegExp(r'^[\x20-\x7E]+$').hasMatch(argument)
              ? '\u2066$argument\u2069'
              : argument;
        });
        return value;
      }
    }
    // Session log timestamps and lines are structural, messages remain localised.
    if (input.contains('\n')) {
      return input
          .split('\n')
          .map(
            (line) =>
                text(line, language: code, isolateArguments: isolateArguments),
          )
          .join('\n');
    }
    final log = RegExp(r'^(\d\d:\d\d:\d\d  )(.*)$').firstMatch(input);
    if (log != null) {
      return '${log[1]}${text(log[2]!, language: code, isolateArguments: isolateArguments)}';
    }
    return input;
  }
}

String tr(BuildContext context, String value) {
  // Register a locale dependency, including labels and validation descriptions.
  Localizations.localeOf(context);
  return AppLanguages.text(
    value,
    isolateArguments: Directionality.of(context) == TextDirection.rtl,
  );
}

/// Keeps already-open routes/dialogs localised without recreating their forms.
class LText extends StatelessWidget {
  final String data;
  final TextStyle? style;
  final TextAlign? textAlign;
  final int? maxLines;
  final TextOverflow? overflow;
  final bool? softWrap;
  final String? semanticsLabel;
  const LText(
    this.data, {
    super.key,
    this.style,
    this.textAlign,
    this.maxLines,
    this.overflow,
    this.softWrap,
    this.semanticsLabel,
  });
  @override
  Widget build(BuildContext context) => ValueListenableBuilder<int>(
    valueListenable: AppLanguages.revision,
    builder: (context, _, _) => Text(
      tr(context, data),
      style: style,
      textAlign: textAlign,
      maxLines: maxLines,
      overflow: overflow,
      softWrap: softWrap,
      semanticsLabel: semanticsLabel == null
          ? null
          : tr(context, semanticsLabel!),
    ),
  );
}
