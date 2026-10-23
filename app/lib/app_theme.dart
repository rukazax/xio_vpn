import 'package:flutter/material.dart';

ThemeData x1oTheme(Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final background = Color(dark ? 0xff0c1119 : 0xfff2f5ef);
  final surface = Color(dark ? 0xff151e2a : 0xffffffff);
  final accent = Color(dark ? 0xffc0f57b : 0xff35620f);
  final scheme = ColorScheme.fromSeed(seedColor: accent, brightness: brightness)
      .copyWith(
        primary: accent,
        secondary: const Color(0xffc0f57b),
        onPrimary: const Color(0xff15220a),
        surface: surface,
        surfaceContainerLowest: background,
        surfaceContainerLow: surface,
        surfaceContainer: Color(dark ? 0xff192332 : 0xffffffff),
        surfaceContainerHigh: Color(dark ? 0xff192332 : 0xffffffff),
        surfaceContainerHighest: Color(dark ? 0xff27313e : 0xffe1e8db),
        onSurface: Color(dark ? 0xffe7efde : 0xff182117),
        onSurfaceVariant: Color(dark ? 0xff9baabc : 0xff53614f),
        outlineVariant: Color(dark ? 0xff27313e : 0xffd1dacd),
        error: Color(dark ? 0xffffba98 : 0xffa12f19),
      );
  return ThemeData(
    useMaterial3: true,
    dialogTheme: DialogThemeData(
      backgroundColor: Color(dark ? 0xff192332 : 0xffffffff),
      insetPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 24),
      constraints: const BoxConstraints.tightFor(width: 880),
    ),
    cardTheme: CardThemeData(
      color: surface,
      surfaceTintColor: Colors.transparent,
    ),
    appBarTheme: AppBarTheme(
      backgroundColor: surface,
      foregroundColor: scheme.onSurface,
      surfaceTintColor: Colors.transparent,
    ),
    brightness: brightness,
    scaffoldBackgroundColor: background,
    colorScheme: scheme,
    fontFamily: 'X1oSans', // Original XIO Noto Sans typography.
    fontFamilyFallback: const ['X1oArabic', 'X1oDevanagari', 'X1oCJK'],
    textTheme: const TextTheme(
      headlineLarge: TextStyle(
        fontSize: 36,
        fontWeight: FontWeight.w700,
        letterSpacing: -1.2,
      ),
      titleLarge: TextStyle(fontSize: 21, fontWeight: FontWeight.w600),
      bodyMedium: TextStyle(height: 1.5, fontSize: 14),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: background,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide.none,
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: const Color(0xffc0f57b),
        foregroundColor: const Color(0xff15220a),
        minimumSize: const Size(48, 48),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        minimumSize: const Size(48, 48),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      ),
    ),
    navigationBarTheme: NavigationBarThemeData(
      height: 64,
      backgroundColor: surface,
      surfaceTintColor: Colors.transparent,
      indicatorColor: accent.withValues(alpha: dark ? .16 : .12),
      labelTextStyle: WidgetStateProperty.resolveWith(
        (states) => TextStyle(
          fontSize: 10.5,
          fontWeight: states.contains(WidgetState.selected)
              ? FontWeight.w700
              : FontWeight.w500,
          height: 1.05,
          color: states.contains(WidgetState.selected)
              ? accent
              : scheme.onSurfaceVariant,
        ),
      ),
      iconTheme: WidgetStateProperty.resolveWith(
        (states) => IconThemeData(
          size: 22,
          color: states.contains(WidgetState.selected)
              ? accent
              : scheme.onSurfaceVariant,
        ),
      ),
    ),
  );
}
