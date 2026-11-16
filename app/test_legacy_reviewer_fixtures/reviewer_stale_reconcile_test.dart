import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/policy_publication.dart';
import 'reviewer_core_policy_test.dart' show Boundary;
class StateGate extends Boundary {
  StateGate(super.directory);
  bool armed=false;
  final entered=Completer<void>(), gate=Completer<void>();
  @override Future<Object?> handle(MethodCall call) async {
    if(call.method=='policyState' && armed) {
      armed=false;
      final response=await super.handle(call);
      entered.complete();await gate.future;return response;
    }
    if(call.method=='policyReconcile') {
      calls.add(call.method);
      // Conservative native peer refuses the obsolete reconciliation. It does
      // not repair Dart's profiles.json and never falsely ACKs the old plan.
      throw PlatformException(code:'POLICY_STALE');
    }
    return super.handle(call);
  }
}
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('old retry must not overwrite a newer mode document after its native READY',() async {
    debugDefaultTargetPlatformOverride=TargetPlatform.linux;
    final dir=await Directory.systemTemp.createTemp('policy-stale-reconcile-');
    final boundary=StateGate(dir);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(native,boundary.handle);
    final s=AppStore()..directory=dir;
    try {
      final file=File('${dir.path}/profiles.json');
      await file.writeAsString(jsonEncode({'schema':2,'profiles':[],'priorityProtocol':'awg','checkSite':'https://example.invalid/','siteCheckEnabled':false,'protocolTimeoutSeconds':15}));
      await s.load();
      await s.setConnectionPolicy(ConnectionPolicy.selectedOnly);
      boundary.armed=true;
      Object? failure;
      final old=s.retryPolicyReconciliation().catchError((Object e){failure=e;});
      await boundary.entered.future;
      await s.setConnectionPolicy(ConnectionPolicy.automatic);
      expect(s.connectionModeConfirmed,true);
      final newer=jsonDecode(await file.readAsString()) as Map;
      expect((newer['connectionPolicy'] as Map)['mode'],'automatic');
      final transaction=(newer['connectionPlanReceipt'] as Map)['transactionId'];
      boundary.gate.complete();await old;
      expect(failure,isA<PublicationFailure>());
      final finalDocument=jsonDecode(await file.readAsString()) as Map;
      expect((finalDocument['connectionPolicy'] as Map)['mode'],'automatic',reason:'native rejection of obsolete retry cannot undo its already-issued Dart rename');
      expect((finalDocument['connectionPlanReceipt'] as Map)['transactionId'],transaction);
    } finally {
      s.dispose();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(native,null);
      debugDefaultTargetPlatformOverride=null;
      await dir.delete(recursive:true);
    }
  });
}
