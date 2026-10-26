import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/update_service.dart';

class Headers implements HttpHeaders {
  final values = <String, String>{};
  @override
  void set(String name, Object value, {bool preserveHeaderCase = false}) {
    values[name] = value.toString();
  }

  @override
  String? value(String name) => values[name];
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class Response extends Stream<List<int>> implements HttpClientResponse {
  final List<int> bytes;
  @override
  final int statusCode;
  @override
  final headers = Headers();
  Response(this.bytes, {this.statusCode = 200});
  @override
  int get contentLength => bytes.length;
  @override
  StreamSubscription<List<int>> listen(
    void Function(List<int>)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => Stream<List<int>>.fromIterable([bytes]).listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class Request implements HttpClientRequest {
  final Response response;
  Request(this.response);
  @override
  final headers = Headers();
  @override
  set followRedirects(bool value) {}
  @override
  Future<HttpClientResponse> close() async => response;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class Client implements HttpClient {
  final Response response;
  int requests = 0;
  bool closed = false;
  Client(this.response);
  @override
  set connectionTimeout(Duration? value) {}
  @override
  Future<HttpClientRequest> getUrl(Uri uri) async {
    requests++;
    if (closed) throw const HttpException('Cancelled');
    return Request(response);
  }

  @override
  void close({bool force = false}) {
    closed = true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  Future<Directory> temp() =>
      Directory.systemTemp.createTemp('xio-update-http');
  XioRelease release(String hash, int size) => XioRelease({
    'schema': 1,
    'tag': 'v0.22.0',
    'version': '0.22.0',
    'build': 5004,
    'notes': 'Test',
    'assets': {
      'android-x86_64': {
        'url': '$githubUrl/releases/download/v0.22.0/XIO.apk',
        'size': size,
        'sha256': hash,
      },
    },
  });
  for (final valid in [true, false]) {
    test(
      'download ${valid ? 'commits verified bytes' : 'rejects corrupted bytes and deletes partials'}',
      () async {
        final dir = await temp();
        addTearDown(() => dir.delete(recursive: true));
        final bytes = utf8.encode('apk fixture');
        final client = Client(Response(bytes));
        final updater = UpdateService(
          directory: () async => dir,
          random: Random(0),
          clientFactory: () => client,
        );
        await updater.initialize();
        final r = release(
          valid ? sha256.convert(bytes).toString() : '0' * 64,
          bytes.length,
        );
        final operation = updater.download(
          r,
          r.forPlatform('android-x86_64')!,
          (_) {},
        );
        if (valid) {
          final file = await operation;
          expect(await file.readAsBytes(), bytes);
          expect(updater.state['installBuild'], 5004);
        } else {
          await expectLater(operation, throwsFormatException);
          expect(
            await Directory('${dir.path}/update-staging').list().length,
            0,
          );
        }
        expect(client.closed, true);
        expect(updater.downloading, false);
      },
    );
  }
  test(
    'concurrent checks share one HTTP request and rate-limit immediate retries',
    () async {
      final dir = await temp();
      addTearDown(() => dir.delete(recursive: true));
      final client = Client(Response(utf8.encode('[]')));
      final updater = UpdateService(
        directory: () async => dir,
        clientFactory: () => client,
      );
      final a = updater.check(manual: true);
      final b = updater.check(manual: true);
      expect(identical(a, b), true);
      expect(await a, null);
      expect(await b, null);
      expect(client.requests, 1);
      await expectLater(updater.check(manual: true), throwsStateError);
      expect(client.requests, 1);
    },
  );
  test('untrusted redirect never receives a request', () async {
    final dir = await temp();
    addTearDown(() => dir.delete(recursive: true));
    final response = Response([], statusCode: 302);
    response.headers.set('location', 'https://attacker.invalid/package');
    final client = Client(response);
    final updater = UpdateService(
      directory: () async => dir,
      clientFactory: () => client,
    );
    await expectLater(updater.check(manual: true), throwsFormatException);
    expect(client.requests, 1);
  });
}
