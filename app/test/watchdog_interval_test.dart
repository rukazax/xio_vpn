import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

void main() {
  test('watchdog halves its cadence only after a stable run', () {
    expect(watchdogIntervalFor(0), const Duration(seconds: 15));
    expect(watchdogIntervalFor(5), const Duration(seconds: 15));
    expect(watchdogIntervalFor(6), const Duration(seconds: 20));
    expect(watchdogIntervalFor(7), const Duration(seconds: 20));
  });
}
