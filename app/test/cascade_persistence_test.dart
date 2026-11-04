import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

void main() {
  test('адреса каскада и разблокировка переживают перезапуск', () async {
    final dir = await Directory.systemTemp.createTemp('xio_cascade_store');

    final first = AppStore();
    first.directory = dir;
    await first.load();
    final saved = await first.setCascadeServers(
      bridge: '81.177.142.37',
      exit: '2a0c:b641:1a0:800::2a2',
    );
    expect(saved, isTrue);
    await first.setCascadeUnlocked(true);

    final second = AppStore();
    second.directory = dir;
    await second.load();
    expect(second.cascadeBridge, '81.177.142.37');
    expect(second.cascadeExit, '2a0c:b641:1a0:800::2a2');
    expect(second.cascadeUnlocked, isTrue);

    await dir.delete(recursive: true);
  });
}