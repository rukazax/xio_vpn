import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'reviewer_core_policy_test.dart' show Boundary;

class CutABoundary extends Boundary {
  CutABoundary(super.directory);
  bool pending=true;
  static const dead='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  @override Future<Object?> handle(MethodCall call) async {
    if(call.method=='policyState' && pending) {
      calls.add(call.method);
      return {'version':1,'instanceNonce':Boundary.instance,'state':'pending','phase':'pending','resourceState':'owned','pendingTransaction':dead};
    }
    if(call.method=='policyAbort') {
      expect((call.arguments as Map)['transactionId'],dead);
      pending=false;
    }
    return super.handle(call);
  }
}
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory dir;
  late Boundary boundary;
  setUp(() async {
    debugDefaultTargetPlatformOverride=TargetPlatform.linux;
    dir=await Directory.systemTemp.createTemp('policy-followup-');
    boundary=Boundary(dir);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(native,(c)=>boundary.handle(c));
  });
  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(native,null);
    debugDefaultTargetPlatformOverride=null;
    await dir.delete(recursive:true);
  });
  Future<AppStore> loaded({bool versioned=false}) async {
    await File('${dir.path}/profiles.json').writeAsString(jsonEncode({
      'schema':2,'profiles':[],'priorityProtocol':'awg','checkSite':'https://example.invalid/',
      'siteCheckEnabled':false,'protocolTimeoutSeconds':15,
      if(versioned)'connectionPolicy':{'mode':'automatic','roundMillis':30000},
    }));
    final s=AppStore()..directory=dir;await s.load();return s;
  }
  test('observed native BLOCKED state must clear Store live READY confirmation',() async {
    final s=await loaded();
    try {
      await s.setConnectionPolicy(ConnectionPolicy.selectedOnly);
      expect(s.connectionModeConfirmed,true);
      // Boundary now returns an explicit valid BLOCKED state: model native loss.
      await s.settleNativePending();
      expect(boundary.calls.last,'policyState');
      expect(s.connectionModeConfirmed,false);
    } finally {s.dispose();}
  });
  test('retry reconciliation must acquire admission before its first file await',() async {
    final s=await loaded();
    try {
      await s.setConnectionPolicy(ConnectionPolicy.selectedOnly);
      final pending=s.retryPolicyReconciliation();
      final fenced=s.documentMutationPending;
      final modeAllowed=s.canChangeConnectionMode;
      await pending;
      expect(fenced,true,reason:'reconciliation is a document/native writer, not an unowned background read');
      expect(modeAllowed,false);
    } finally {s.dispose();}
  });
  test('recovery cut A settles dead native pending and reconciles actual old automatic document',() async {
    boundary=CutABoundary(dir);
    final s=await loaded(versioned:true);
    try {
      expect(boundary.calls,contains('policyAbort'));
      expect(boundary.calls,contains('policyReconcile'));
      expect(s.connectionPolicy,ConnectionPolicy.automatic);
      expect(s.connectionModeConfirmed,true);
      final doc=jsonDecode(await File('${dir.path}/profiles.json').readAsString()) as Map;
      expect((doc['connectionPolicy'] as Map)['mode'],'automatic');
      expect((doc['connectionPlanReceipt'] as Map)['transactionId'],isNot(CutABoundary.dead));
      expect((doc['connectionPlanReceipt'] as Map)['planGeneration'],s.committedReceipt!.planGeneration);
    } finally {s.dispose();}
  });
}
