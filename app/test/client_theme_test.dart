import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/app_theme.dart';

double contrast(Color a, Color b) {
  final x = a.computeLuminance(), y = b.computeLuminance();
  return ((x > y ? x : y) + .05) / ((x < y ? x : y) + .05);
}

void main() {
  for (final mode in Brightness.values) {
    test('client amber palette has readable text in ${mode.name}', () {
      final t = x1oTheme(mode, client: true);
      final s = t.colorScheme;
      expect(s.primary.r, greaterThan(s.primary.g));
      expect(s.primary.g, greaterThan(s.primary.b));
      for (final pair in [
        (s.onSurface, s.surface),
        (s.onSurface, t.scaffoldBackgroundColor),
        (s.onSurfaceVariant, s.surface),
        (s.onPrimary, s.primary),
        (s.onSecondary, s.secondary),
        (s.primary, t.scaffoldBackgroundColor),
      ]) {
        expect(contrast(pair.$1, pair.$2), greaterThanOrEqualTo(4.5));
      }
      final button = t.filledButtonTheme.style!;
      expect(button.backgroundColor!.resolve({}), s.primary);
      expect(button.foregroundColor!.resolve({}), s.onPrimary);
    });
  }
  test('full app keeps its original green identity', () {
    expect(
      x1oTheme(Brightness.dark).colorScheme.primary,
      const Color(0xffc0f57b),
    );
    expect(
      x1oTheme(Brightness.light).colorScheme.primary,
      const Color(0xff35620f),
    );
  });
}
