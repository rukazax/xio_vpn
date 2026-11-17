import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/routing_domains.dart';
class ClockLookup implements DomainAddressLookup {
  int calls=0;
  @override Future<List<String>> lookup(String host,{required Duration timeout}) async {calls++;return ['192.0.2.1'];}
}
void main() {
  test('OBSERVATION ONLY real DNS age nine minutes, wall clock rewind inside cache window',() async {
    final origin=DateTime.utc(2026,11,6);
    var wall=origin;
    final lookup=ClockLookup();
    final allowance=<int>[];
    final sync=SplitDomainSync(clock:()=>wall,resolver:SplitDomainResolver(lookup:lookup),apply:(_) async{});
    Future<void> apply(List<String> addresses,Duration remaining) async {allowance.add(remaining.inMilliseconds);}
    await sync.refresh(rules:['old.example.org'],applyCurrent:apply);
    expect(allowance,[600000]);
    // Real monotonic elapsed 9m; user/network wall time corrected backwards 8m.
    // No system clock is touched: only the explicitly supported injected clock.
    const realBegin=540000;
    wall=origin.add(const Duration(minutes:9));
    wall=wall.subtract(const Duration(minutes:8));
    sync.invalidate(discardCache:false);
    await sync.refresh(rules:['old.example.org'],applyCurrent:apply);
    expect(lookup.calls,1);expect(allowance,[600000,540000]);
    final root=Platform.environment['REVIEW_ROOT']!;
    File('$root/cross-clock-allowance.txt').writeAsStringSync('$realBegin\n${allowance.last}\n');
    print('OBSERVED ONLY: actual SplitDomainSync reused old DNS at real age540000ms and wall age60000ms; new validForMillis=${allowance.last}. Actual Kotlin gate independently consumes these emitted inputs next.');
  });
}
