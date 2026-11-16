// ignore_for_file: avoid_print
// Plain-Dart runner for the shared Windows fixture scenarios. This exists so
// the regression can execute in the allowed Windows plain-Dart mode without
// the blocked Flutter test frontend; it uses the same scenario bodies as the
// Flutter wrapper in `test/issuance_vault_windows_fixture_test.dart`.
import '../test/windows_fixture_support.dart' as support;

Future<void> main() async {
  await support.scenarioPreflightCollision();
  await support.scenarioEraseBeforeOpen();
  await support.scenarioEraseAfterOpen();
  await support.scenarioFreshEmptyReopen();
  print('RESULT pass=4 fail=0');
}
