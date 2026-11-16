import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'windows_fixture_support.dart' as support;

void main() {
  test(
    'existing valid XIOJ DB with its sole row erased is corrupt at open',
    support.scenarioEraseBeforeOpen,
    skip: !Platform.isWindows,
  );
  test(
    'post-open row erasure makes read and write corrupt, never absent',
    support.scenarioEraseAfterOpen,
    skip: !Platform.isWindows,
  );
  test(
    'preflight collision never claims or deletes a pre-existing sentinel',
    support.scenarioPreflightCollision,
    skip: !Platform.isWindows,
  );
  test(
    'fresh empty reopen keeps exactly one authenticated tombstone row',
    support.scenarioFreshEmptyReopen,
    skip: !Platform.isWindows,
  );
}
