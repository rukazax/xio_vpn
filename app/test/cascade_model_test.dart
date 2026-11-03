import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_model.dart';

void main() {
  group('flagEmoji', () {
    test('собирает флаг из двухбуквенного ISO-кода', () {
      expect(flagEmoji('RU'), '🇷🇺');
      expect(flagEmoji('NL'), '🇳🇱');
      expect(flagEmoji('SE'), '🇸🇪');
    });

    test('не зависит от регистра и пробелов', () {
      expect(flagEmoji('ru'), '🇷🇺');
      expect(flagEmoji(' Nl '), '🇳🇱');
    });

    test('для неизвестного кода отдаёт белый флаг', () {
      expect(flagEmoji(''), '🏳');
      expect(flagEmoji('RUS'), '🏳');
      expect(flagEmoji('1!'), '🏳');
    });
  });

  group('CascadeRoute JSON', () {
    final route = CascadeRoute(
      device: const CascadeHop(
        countryCode: '',
        label: 'Устройство',
        address: '192.168.1.10 · IPv4',
        state: CascadeHopState.connected,
      ),
      bridge: const CascadeHop(
        countryCode: 'NL',
        label: 'Bridge',
        address: '185.14.30.7 · IPv4',
        state: CascadeHopState.connected,
      ),
      exit: const CascadeHop(
        countryCode: 'SE',
        label: 'Exit',
        address: '2001:db8::7 · IPv6',
        state: CascadeHopState.connecting,
      ),
      stage: CascadeStage.bridgeToExit,
      pingMs: 42,
      updatedAt: DateTime.utc(2026, 11, 3, 8, 56, 12),
    );

    test('toJson содержит все поля', () {
      final json = route.toJson();
      expect(json['stage'], 'bridgeToExit');
      expect(json['pingMs'], 42);
      expect(json['updatedAt'], '2026-11-03T08:56:12.000Z');
      expect((json['bridge'] as Map<String, Object?>)['countryCode'], 'NL');
      expect((json['exit'] as Map<String, Object?>)['state'], 'connecting');
    });

    test('проходит через jsonEncode/jsonDecode и обратно', () {
      final decoded = jsonDecode(jsonEncode(route.toJson()));
      final restored = CascadeRoute.fromJson(decoded);
      expect(restored.stage, CascadeStage.bridgeToExit);
      expect(restored.pingMs, 42);
      expect(restored.updatedAt, DateTime.utc(2026, 11, 3, 8, 56, 12));
      expect(restored.device.label, 'Устройство');
      expect(restored.bridge.countryCode, 'NL');
      expect(restored.bridge.flag, '🇳🇱');
      expect(restored.bridge.state, CascadeHopState.connected);
      expect(restored.exit.address, '2001:db8::7 · IPv6');
      expect(restored.exit.state, CascadeHopState.connecting);
      // Повторная сериализация даёт тот же JSON.
      expect(restored.toJson(), route.toJson());
    });

    test('без pingMs и updatedAt сериализуется с null', () {
      final idle = CascadeRoute.idle();
      final json = idle.toJson();
      expect(json['pingMs'], isNull);
      expect(json['updatedAt'], isNull);
      final restored = CascadeRoute.fromJson(json);
      expect(restored.stage, CascadeStage.idle);
      expect(restored.pingMs, isNull);
      expect(restored.updatedAt, isNull);
      expect(restored.isAnimating, isFalse);
      expect(restored.isTunnelActive, isFalse);
    });

    test('терпит мусор вместо полей', () {
      final restored = CascadeRoute.fromJson(<String, Object?>{
        'stage': 'неизвестная стадия',
        'bridge': 'строка вместо объекта',
        'pingMs': 'много',
      });
      expect(restored.stage, CascadeStage.idle);
      expect(restored.pingMs, isNull);
      expect(restored.bridge.label, 'Bridge');
      expect(restored.bridge.state, CascadeHopState.idle);
      expect(CascadeRoute.fromJson(null).stage, CascadeStage.idle);
    });
  });

  group('CascadeStage / CascadeHopState', () {
    test('имена стадий стабильны (используются в JSON)', () {
      expect(
        CascadeStage.values.map((stage) => stage.name),
        <String>[
          'idle',
          'deviceToBridge',
          'bridgeToExit',
          'active',
          'degraded',
          'failed',
        ],
      );
      expect(cascadeStageFromName('active'), CascadeStage.active);
      expect(cascadeStageFromName('bridgeToExit'), CascadeStage.bridgeToExit);
      expect(cascadeStageFromName(null), CascadeStage.idle);
      expect(cascadeHopStateFromName('connected'), CascadeHopState.connected);
    });

    test('isAnimating только на переходных стадиях', () {
      final route = CascadeRoute.idle();
      expect(route.copyWith(stage: CascadeStage.deviceToBridge).isAnimating,
          isTrue);
      expect(
          route.copyWith(stage: CascadeStage.bridgeToExit).isAnimating, isTrue);
      expect(route.copyWith(stage: CascadeStage.active).isAnimating, isFalse);
      expect(
          route.copyWith(stage: CascadeStage.active).isTunnelActive, isTrue);
    });
  });

  group('Подписка (заглушка)', () {
    test('по умолчанию подписки нет', () {
      const subscription = CascadeSubscription();
      expect(subscription.entitled, isFalse);
      expect(subscription.planLabel, 'Подписка не подключена');
    });

    test('CascadeFeatureGate выключен', () {
      expect(CascadeFeatureGate.enabled, isFalse);
      expect(CascadeFeatureGate.instance, isA<CascadeFeatureGate>());
    });

    test('requestActivation() возвращает false', () async {
      const gate = CascadeFeatureGate();
      expect(await gate.requestActivation(), isFalse);
    });
  });
}
