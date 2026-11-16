import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';

const _manifestAsset = 'assets/xio-server-release.json';
const _archiveAsset = 'assets/xio-server.tar.gz';
const _updaterAsset = 'assets/xio-server-update.py';
const _updater = '# inert updater fixture; never executed';
const _pin = 'SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
final _goodArchive = List<int>.generate(257, (i) => i & 255);

class _Assets extends CachingAssetBundle {
  _Assets(this.archive, this.events);
  final List<int> archive;
  final List<String> events;

  @override
  Future<ByteData> load(String key) async {
    events.add('asset:$key');
    if (key != _archiveAsset) throw StateError('Unexpected asset: $key');
    // Exercise the ByteData slice as well: neither sentinel is archive data.
    final storage = Uint8List.fromList([99, ...archive, 98]);
    return ByteData.sublistView(storage, 1, storage.length - 1);
  }

  @override
  Future<String> loadString(String key, {bool cache = true}) async {
    events.add('asset:$key');
    if (key == _updaterAsset) return _updater;
    if (key != _manifestAsset) throw StateError('Unexpected asset: $key');
    return jsonEncode({
      'schema': 1,
      'recipeVersion': 28,
      'sha256': digestOfBytes(_goodArchive),
    });
  }
}

class _Store extends AppStore {
  _Store(this.trace);
  final List<String> trace;

  @override
  void changed() {
    trace.add('maintenance:$serverMaintenance');
    super.changed();
  }

  @override
  Future<void> saveNativePlan({
    bool? androidForTesting,
    Map<String, dynamic>? document,
  }) async {
    trace.add('plan:$serverMaintenance');
  }
}

class _Ssh extends VpsService {
  _Ssh(this.store, this.events) {
    verifiedFingerprint = _pin;
  }
  final _Store store;
  final List<String> events;
  final updates = <({String command, List<int> input})>[];
  final uploads = <String>[];

  @override
  Future<void> upload(String path, List<int> bytes) async {
    uploads.add(path);
    throw StateError('Unexpected SFTP upload');
  }

  @override
  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    if (command == 'python3 /usr/local/lib/xio-managed/admin.py') {
      final request = jsonDecode(utf8.decode(input));
      expect(request, {'action': 'inspect'});
      events.add('inspect');
      expect(store.serverMaintenance, isFalse);
      return utf8.encode(
        jsonEncode({
          'ok': true,
          'server': {'id': 'fixture-server', 'recipeVersion': 27},
        }),
      );
    }
    // Record only; no SSH connection or updater process is ever created.
    events.add('update');
    expect(store.serverMaintenance, isTrue);
    expect(timeout, const Duration(minutes: 12));
    updates.add((command: command, input: List<int>.from(input)));
    return utf8.encode('{"ok":true}');
  }
}

class _GatedService extends ManagedService {
  _GatedService(super.ssh, {required super.assets, required this.events});
  final List<String> events;
  final verificationStarted = Completer<void>();
  final allowVerification = Completer<void>();

  @override
  Future<void> verifyUpdateArchive(
    ServerRelease release,
    List<int> bytes,
  ) async {
    events.add('verify:start');
    verificationStarted.complete();
    await allowVerification.future;
    try {
      // Keep the real off-thread digest and error behavior in both cases.
      await super.verifyUpdateArchive(release, bytes);
      events.add('verify:accepted');
    } catch (_) {
      events.add('verify:rejected');
      rethrow;
    }
  }
}

ManagedServer _server() =>
    ManagedServer(id: 'fixture-server', host: 'fixture.example', hostKey: _pin);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final corrupt in [false, true]) {
    test(
      'update awaits digest and ${corrupt ? 'returns mismatch without side effects' : 'advances only after acceptance'}',
      () async {
        final events = <String>[];
        final store = _Store(events);
        addTearDown(store.dispose);
        final ssh = _Ssh(store, events);
        final archive = corrupt ? [..._goodArchive, 0] : _goodArchive;
        final service = _GatedService(
          ssh,
          assets: _Assets(archive, events),
          events: events,
        );
        var completed = false;
        // Attach the error handler before releasing verification. A detached
        // digest failure would still be an unhandled test-zone error, not this
        // returned Future's result.
        final result = service
            .ensureUpdated(store, _server())
            .then<Object?>(
              (_) {
                completed = true;
                return null;
              },
              onError: (Object error, StackTrace stack) {
                completed = true;
                return error;
              },
            );
        try {
          await service.verificationStarted.future;
          await pumpEventQueue();
          expect(completed, isFalse);
          expect(events, [
            'asset:$_manifestAsset',
            'inspect',
            'asset:$_archiveAsset',
            'verify:start',
          ]);
          expect(ssh.updates, isEmpty);
          expect(ssh.uploads, isEmpty);
          expect(store.serverMaintenance, isFalse);
        } finally {
          service.allowVerification.complete();
        }

        final error = await result;
        expect(completed, isTrue);
        expect(store.serverMaintenance, isFalse);
        expect(ssh.uploads, isEmpty);
        if (corrupt) {
          expect(
            error,
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('Архив серверного релиза'),
            ),
          );
          expect(events, [
            'asset:$_manifestAsset',
            'inspect',
            'asset:$_archiveAsset',
            'verify:start',
            'verify:rejected',
          ]);
          expect(ssh.updates, isEmpty);
          expect(store.events, isEmpty);
        } else {
          expect(error, isNull);
          expect(events, [
            'asset:$_manifestAsset',
            'inspect',
            'asset:$_archiveAsset',
            'verify:start',
            'verify:accepted',
            'asset:$_updaterAsset',
            'maintenance:true',
            'plan:true',
            'update',
            'plan:false',
            'maintenance:false',
          ]);
          expect(ssh.updates.single.input, _goodArchive);
          expect(ssh.updates.single.command, contains(_updater));
          expect(
            ssh.updates.single.command,
            contains(digestOfBytes(_goodArchive)),
          );
          expect(ssh.updates.single.command, contains('fixture-server'));
          expect(store.events.single, contains('Сервер XIO обновлён'));
        }
      },
    );
  }

  test(
    'default service returns real digest mismatch before updater load',
    () async {
      final events = <String>[];
      final store = _Store(events);
      addTearDown(store.dispose);
      final ssh = _Ssh(store, events);
      final service = ManagedService(
        ssh,
        assets: _Assets([..._goodArchive, 0], events),
      );

      await expectLater(
        service.ensureUpdated(store, _server()),
        throwsStateError,
      );
      expect(events, [
        'asset:$_manifestAsset',
        'inspect',
        'asset:$_archiveAsset',
      ]);
      expect(ssh.updates, isEmpty);
      expect(ssh.uploads, isEmpty);
      expect(store.serverMaintenance, isFalse);
      expect(store.events, isEmpty);
    },
  );
}
