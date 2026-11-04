import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_probe.dart';
import 'package:xio/core.dart';

void main() {
  group('Выбор сервера для проверки', () {
    final first = ManagedServer(id: 'a', host: '10.0.0.1');
    final bridge = ManagedServer(
      id: 'b',
      host: '81.177.142.37',
      publicHost: 'bridge.example.com',
    );

    test('точное совпадение SSH-хоста важнее порядка', () {
      expect(selectCascadeServer([first, bridge], '81.177.142.37'), bridge);
      expect(
        selectCascadeServer(<ManagedServer>[first], '81.177.142.37'),
        first,
      );
    });

    test('совпадение по VPN-адресу (publicHost)', () {
      expect(
        selectCascadeServer([first, bridge], 'bridge.example.com'),
        bridge,
      );
    });

    test('адрес без сервера — берём первый сохранённый', () {
      expect(selectCascadeServer([first, bridge], ''), first);
      expect(selectCascadeServer([first, bridge], 'unknown.example'), first);
    });

    test('без серверов проверять нечего', () {
      expect(
        selectCascadeServer(const <ManagedServer>[], '81.177.142.37'),
        isNull,
      );
    });
  });

  group('Команда проверки', () {
    test('сначала настоящий healthcheck, затем встроенная проба', () {
      expect(cascadeHealthCommand, contains('cascade-healthcheck.sh'));
      expect(cascadeHealthCommand, contains("'--role', 'bridge'"));
      expect(cascadeHealthCommand, contains('--json-strict'));
      expect(cascadeHealthCommand, contains('systemctl'));
      expect(cascadeHealthCommand, contains('tun0'));
      expect(cascadeHealthCommand, contains('exit.egress6'));
      expect(cascadeHealthCommand, contains('egress6'));
    });

    test('команда только читает состояние и не трогает каскад', () {
      for (final forbidden in const <String>[
        'systemctl restart',
        'systemctl start',
        'systemctl stop',
        'ip link set',
        'ip route replace',
        'nft ',
      ]) {
        expect(
          cascadeHealthCommand,
          isNot(contains(forbidden)),
          reason: forbidden,
        );
      }
    });
  });
}
