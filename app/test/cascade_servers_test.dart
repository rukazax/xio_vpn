import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_model.dart';

void main() {
  group('Серверы каскада: валидация', () {
    test('bridge принимает IPv4 и домен, отвергает мусор', () {
      expect(validateCascadeBridge('81.177.142.37'), '81.177.142.37');
      expect(validateCascadeBridge('vpn.example.com'), 'vpn.example.com');
      expect(validateCascadeBridge('  BRIDGE.example '), 'bridge.example');
      expect(validateCascadeBridge(''), isNull);
      expect(validateCascadeBridge('2001:db8::1'), isNull);
      expect(validateCascadeBridge('https://x.example'), isNull);
      expect(validateCascadeBridge('999.1.1.1'), isNull);
      expect(validateCascadeBridge('localhost'), isNull);
    });

    test('exit принимает literal IPv4 и IPv6', () {
      expect(
        validateCascadeExit('2a0c:b641:1a0:800::2a2'),
        '2a0c:b641:1a0:800::2a2',
      );
      expect(validateCascadeExit('[fd79:1::fe]'), 'fd79:1::fe');
      expect(validateCascadeExit(''), isNull);
      expect(validateCascadeExit('81.177.142.37'), '81.177.142.37');
      expect(validateCascadeExit('2001:db8::zz'), isNull);
    });

    test('маршрут из адресов: настроен и не настроен', () {
      final configured = cascadeRouteFromAddresses(
        bridge: '81.177.142.37',
        exit: '2a0c:b641:1a0:800::2a2',
        stage: CascadeStage.active,
        pingMs: 12,
      );
      expect(configured.bridge.address, '81.177.142.37');
      expect(configured.exit.address, '2a0c:b641:1a0:800::2a2');
      expect(configured.stage, CascadeStage.active);
      expect(configured.pingMs, 12);
      expect(configured.isTunnelActive, isTrue);

      final empty = cascadeRouteFromAddresses(bridge: '', exit: '');
      expect(empty.stage, CascadeStage.idle);
      expect(empty.bridge.address, 'не настроен');
      expect(empty.exit.address, 'не настроен');
      expect(empty.pingMs, isNull);
      expect(empty.isTunnelActive, isFalse);
    });

    test('полу-настроенный маршрут не считается активным', () {
      final half = cascadeRouteFromAddresses(
        bridge: '81.177.142.37',
        exit: '',
        stage: CascadeStage.active,
      );
      expect(half.stage, CascadeStage.idle);
      expect(half.exit.address, 'не настроен');
    });
  });
}
