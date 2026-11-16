import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/policy_publication.dart';
import 'package:xio/store_writer_owner.dart';

class GateOwner extends Fake implements ProductStoreWriterOwner {
  GateOwner(this.real);
  final ProductStoreWriterOwner real;
  final entered = Completer<void>(), gate = Completer<void>();
  bool armed = true;
  @override String get storeIdentity => real.storeIdentity;
  @override String get controllerNonce => real.controllerNonce;
  @override bool get acceptsWrites => real.acceptsWrites;
  @override int get pendingWrites => real.pendingWrites;
  @override Future<void> closeWhenSettled() => real.closeWhenSettled();
  @override Future<T> io<T>(Future<T> Function() action) => real.io(() async {
    if (armed) { armed = false; entered.complete(); await gate.future; }
    return action();
  });
}
class RenameFailure extends AppStore {
  @override Future<void> saveNativePlan({bool? androidForTesting, Map<String,dynamic>? document}) async {
    throw StateError('controlled post-rename publication failure');
  }
}
class Boundary {
  Boundary(this.directory);
  final Directory directory;
  final calls = <String>[];
  Map<String,dynamic>? ready;
  String? validated;
  Completer<void>? commitGate, commitEntered;
  static const instance = 'cccccccccccccccccccccccccccccccc';
  Map<String,Object?> ack(Map a, String state) => {
    'version':1, 'instanceNonce':instance, 'controllerNonce':a['controllerNonce'],
    'transactionId':a['transactionId'], 'planGeneration':a['planGeneration'], 'state':state,
  };
  Future<Object?> handle(MethodCall call) async {
    calls.add(call.method);
    final a = call.arguments is Map ? Map<String,dynamic>.from(call.arguments as Map) : <String,dynamic>{};
    switch(call.method) {
      case 'policyCapabilities': return {'version':1,'instanceNonce':instance,'state':'blocked','resourceState':'clean','validation':1};
      case 'policyState': return {'version':1,'instanceNonce':instance,'state':'blocked','phase':'blocked','resourceState':'clean'};
      case 'policyBegin': ready=null; return ack(a,'pending');
      case 'policyValidate':
        final v=Map<String,dynamic>.from(a['validation'] as Map);
        validated=utf8.decode(base64Decode(v['documentBytesBase64'] as String));
        final digest=sha256.convert(utf8.encode(validated!)).toString();
        if (digest != v['documentDigest']) throw PlatformException(code:'POLICY_INVALID');
        return {'version':1,'instanceNonce':instance,'controllerNonce':a['controllerNonce'],'transactionId':a['transactionId'],'documentDigest':digest};
      case 'policyCommit':
      case 'policyReconcile':
        if (commitGate != null) { commitEntered!.complete(); await commitGate!.future; }
        final disk=await File('${directory.path}/profiles.json').readAsString();
        if (disk != validated) throw PlatformException(code:'POLICY_STALE',message:'disk differs from validated bytes');
        final doc=jsonDecode(disk) as Map;
        if (jsonEncode((doc['connectionPlanReceipt'] as Map)['plan']) != jsonEncode(a['plan'])) throw PlatformException(code:'POLICY_STALE');
        ready=a; return ack(a,'ready');
      case 'policyAbort': ready=null; return {'version':1,'state':'blocked','transactionId':a['transactionId']};
      case 'supportedProtocols': return ['awg'];
      case 'status': return {'active':false,'phase':'disconnected'};
      case 'connectionBusy': return false;
      case 'readConfig': return '[Interface]\nPrivateKey = review\n[Peer]\nEndpoint = 192.0.2.1:51820\n';
      case 'secureScreen': return null;
      default: return null;
    }
  }
}
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory dir;
  late Boundary boundary;
  setUp(() async {
    debugDefaultTargetPlatformOverride=TargetPlatform.linux;
    dir=await Directory.systemTemp.createTemp('review-policy-core-');
    boundary=Boundary(dir);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(native,boundary.handle);
  });
  tearDown(() async {
    debugDefaultTargetPlatformOverride=null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(native,null);
    await dir.delete(recursive:true);
  });
  Future<AppStore> loaded() async {
    await File('${dir.path}/profiles.json').writeAsString(jsonEncode({'schema':2,'profiles':[],'priorityProtocol':'awg','checkSite':'https://example.invalid/','siteCheckEnabled':false,'protocolTimeoutSeconds':15}));
    final s=AppStore()..directory=dir;
    await s.load();
    return s;
  }
  test('foreign Store ticket has zero document and native effects',() async {
    final a=AppStore(), b=AppStore()..directory=dir;
    final ticket=a.beginOwnedDocumentMutation();
    try {
      await expectLater(b.commitOwnedDocument(ticket),throwsA(isA<PolicyFailure>()));
      expect(await File('${dir.path}/profiles.json').exists(),false);
      expect(boundary.calls,isEmpty);
    } finally {ticket.release();a.dispose();b.dispose();}
  });
  for(final explicit in [true,false]) {
    test('${explicit ? "explicit owned" : "ordinary"} save must not rename after disposal at physical IO gate',() async {
      final s=AppStore()..directory=dir;
      final real=await ProductStoreWriterOwner.acquire(dir);
      final owner=GateOwner(real);s.attachProductWriter(owner);
      final ticket=explicit?s.beginOwnedDocumentMutation():null;
      final file=File('${dir.path}/profiles.json');await file.writeAsString('old');
      Object? failure;
      final pending=(explicit?s.commitOwnedDocument(ticket!):s.save()).catchError((Object e){failure=e;});
      await owner.entered.future;
      s.dispose();
      await expectLater(ProductStoreWriterOwner.acquire(dir),throwsStateError);
      owner.gate.complete();await pending;
      ticket?.release();await owner.closeWhenSettled();
      expect(await file.readAsString(),'old');
      expect(failure,isA<PublicationFailure>());
    });
  }
  test('ordinary plan-sensitive edit must replace receipt or remove native confirmation',() async {
    final s=await loaded();
    try {
      await s.setConnectionPolicy(ConnectionPolicy.selectedOnly);
      expect(s.connectionModeConfirmed,true);
      final oldGeneration=s.committedReceipt!.planGeneration;
      await s.saveConnectionSettings('https://changed.invalid/','awg');
      final doc=jsonDecode(await File('${dir.path}/profiles.json').readAsString()) as Map;
      expect(doc['checkSite'],'https://changed.invalid/');
      expect(s.connectionModeConfirmed && s.committedReceipt?.planGeneration==oldGeneration,false,
        reason:'settled new admission settings cannot retain old native READY confirmation');
    } finally {s.dispose();}
  });
  test('product writer cannot hand over while Store native commit is outstanding',() async {
    final s=await loaded();
    final owner=await ProductStoreWriterOwner.acquire(dir);s.attachProductWriter(owner);
    boundary.commitGate=Completer<void>();boundary.commitEntered=Completer<void>();
    Object? error;
    final pending=s.setConnectionPolicy(ConnectionPolicy.selectedOnly).catchError((Object e){error=e;});
    await boundary.commitEntered!.future;
    s.dispose();
    await owner.closeWhenSettled();
    ProductStoreWriterOwner? successor;
    try {successor=await ProductStoreWriterOwner.acquire(dir);} catch (_) {}
    boundary.commitGate!.complete();await pending;
    await successor?.closeWhenSettled();
    expect(successor,isNull,reason:'old native physical commit is still outstanding at ownership handover');
    // The completion may refuse after disposal; never claim a fresh live owner.
    expect(s.connectionModeConfirmed,false);
  });
  test('post-rename remove failure must not restore obsolete in-memory graph',() async {
    final s=RenameFailure()..directory=dir;
    s.profiles.add(const Profile(id:'p1',name:'one',protocol:'awg',endpoint:'192.0.2.1:51820'));
    s.selectedId='p1';
    try {
      await expectLater(s.remove('p1'),throwsA(isA<PublicationFailure>().having((e)=>e.phase,'phase',PublicationPhase.renamedNativeUnconfirmed)));
      final doc=jsonDecode(await File('${dir.path}/profiles.json').readAsString()) as Map;
      expect(doc['profiles'],isEmpty);
      expect(s.profiles,isEmpty,reason:'disk rename removed it; no blanket pre-rename rollback is valid');
    } finally {s.dispose();}
  });
}
