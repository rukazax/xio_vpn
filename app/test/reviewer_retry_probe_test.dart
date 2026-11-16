import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/connection_mode_ui.dart';
import 'package:xio/connection_attempt.dart';
import 'package:xio/store_mode_source.dart';
import 'package:xio/store_writer_owner.dart';
import 'package:xio/l10n.dart';
import 'package:xio/legal_record.dart';

class PostRenameFaultStore extends AppStore {
  PostRenameFaultStore():super(nativeTunnelOverride:false);
  bool fail=false;
  int retries=0;
  Future<void>? retried;
  @override Future<void> retryPolicyReconciliation(){retries++;return retried=super.retryPolicyReconciliation();}
  @override Future<void> saveNativePlan({bool? androidForTesting,Map<String,dynamic>? document}) async {
    if(fail) throw StateError('injected post-rename native publication failure');
  }
}
void main(){
 TestWidgetsFlutterBinding.ensureInitialized();
 testWidgets('real Store settled post-rename uncertainty exposes explicit retry', (tester) async {
  late Directory dir; late ProductStoreWriterOwner writer; late PostRenameFaultStore store;
  await tester.runAsync(() async {
   await AppLanguages.load();AppLanguages.set('ru');
   dir=await Directory.systemTemp.createTemp('review-ui-retry-');writer=await ProductStoreWriterOwner.acquire(dir);
   store=PostRenameFaultStore()..directory=dir;store.attachProductWriter(writer);await store.load();store.setForeground(false);
   store.legalRecord=LegalRecord.acknowledge('fixture','ru');store.vpnDisclosure=vpnDisclosureRevision;
   store.fail=true;
   try{await store.saveConnectionSettings(store.checkSite,store.priorityProtocol,policy:ConnectionPolicy.selectedOnly);}catch(e){print('Injected real save result: ${e.runtimeType} $e');}
  });
  final source=StoreConnectionModeSource(store);
  try {
   expect(store.connectionPolicyError,'publishPending');
   expect(store.connectionModePending,isTrue);
   expect(store.connectionModeConfirmed,isFalse);
   print('Settled actual Store: blocker=${store.connectionPolicyError}, pending=${store.connectionModePending}');
   await tester.pumpWidget(MaterialApp(home:Scaffold(body:SingleChildScrollView(child:ConnectionModeControl(source:source,draft:store.connectionPolicy,onChanged:(_){})))));
   await tester.pump();
   final retry=find.byKey(const ValueKey('connection-mode-retry'));
   expect(tester.widget<DropdownButtonFormField<ConnectionPolicy>>(find.byKey(const ValueKey('connection-mode-draft'))).onChanged,isNull);
   print('Rendered retry widgets=${retry.evaluate().length}; physical settings future already settled');
   expect(retry,findsOneWidget,reason:'Unresolved durable/native uncertainty must offer explicit retry after the physical save settled');
   expect(tester.widget<OutlinedButton>(retry).onPressed,isNotNull);
   await tester.runAsync(() async {await tester.tap(retry);expect(store.retries,1);await store.retried;});
   await tester.pump();
   expect(store.connectionModePending,isFalse);
   expect(store.connectionPolicyError,isNull);
   print('PASS UI retry tap called real Store and settled recovery');
  } finally {
   await tester.pumpWidget(const SizedBox.shrink());source.dispose();
   await tester.runAsync(() async {store.dispose();await writer.closeWhenSettled().timeout(const Duration(seconds:3));await dir.delete(recursive:true);});
  }
 });
}
