import 'package:flutter_test/flutter_test.dart';
import 'package:xio/credentials.dart';

void main() {
  for (final desktop in [false, true]) {
    test('strict credential namespace desktop=$desktop', () {
      for (final prefix in ['ssh', 'vpn', if (desktop) 'state']) {
        for (final hex in ['0' * 64, 'abcdef0123456789' * 4]) {
          expect(
            () => validateCredentialId('$prefix$hex', desktop: desktop),
            returnsNormally,
          );
        }
      }
      for (final id in [
        '',
        '../outside',
        r'..\outside',
        '/absolute',
        'ssh${'a' * 63}',
        'vpn${'a' * 65}',
        'state${'a' * 63}',
        'state${'a' * 65}',
        'ssh${'A' * 64}',
        'state${'A' * 64}',
        'vpn${'g' * 64}',
        'arbitrary${'a' * 64}',
        for (final prefix in ['ssh', 'vpn', 'state']) ...[
          '$prefix${'a' * 64}\n',
          '$prefix${'a' * 64}\r\n',
          '$prefix${'a' * 64}\u0000',
          '$prefix${'a' * 64}/../outside',
          '$prefix${'a' * 64}\\outside',
          ' $prefix${'a' * 64}',
        ],
        if (!desktop) 'state${'a' * 64}',
      ]) {
        expect(
          () => validateCredentialId(id, desktop: desktop),
          throwsFormatException,
          reason: id,
        );
      }
    });
  }
}
