package app.xio.xio;
import java.nio.file.Files;
import java.nio.file.Path;

/** Source-wired worker-catch tabletop with actual production PublicationLease.
 * No Android/Kotlin/JNI execution. Desired invariant intentionally fails while
 * the actual failed-before-owner worker catch still unconditionally disconnects.
 */
public final class ReviewObsoleteCleanupInvariant {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 public static void main(String[] args)throws Exception{
  String src=Files.readString(Path.of(args[0]));
  int start=src.indexOf("private fun connect(request: ConnectRequest)");
  String handler=src.substring(start,src.indexOf("private fun preparePendingVpn",start));
  check(handler.contains("request.budget.remainingMillis()")&&handler.contains("Engine.cancelConnect(request.roundId,request.budget)")&&handler.contains("Engine.disconnect(request.round)"),"source worker catch changed: inspect wiring before running this negative fixture");
  long[] clock={1000};PublicationLease gate=new PublicationLease();
  ConnectionBudget rootB=new ConnectionBudget(30000,()->clock[0]);
  long bToken=gate.register(rootB);ConnectionBudget childB=rootB.cap(25000);
  gate.begin(bToken,childB,"tile-B");
  clock[0]=2000;
  ConnectionBudget rootA=new ConnectionBudget(30000,()->clock[0]);gate.register(rootA);ConnectionBudget childA=rootA.cap(15000);
  clock[0]=18000; // A's queued child expired, B can still complete inside its budget.
  childB.remainingMillis();gate.release(rootB); // B won before worker A gets admitted.
  boolean acquiredA=false,scopedCancelledB=false;
  try {childA.remainingMillis();acquiredA=true;}catch(ConnectionBudget.Expired expired){
   // Actual scoped cancellation correctly rejects A because B owns the gate.
   scopedCancelledB=gate.retire("foreground-A",childA);
   // But the actual subsequent catch is global Engine.disconnect(...), whose
   // first publication action is invalidate(), with no owner guard.
   gate.invalidate();
  }
  check(!acquiredA&&!scopedCancelledB,"negative ordering did not model failure before owner acquisition");
  System.out.println("Mock actual worker catch: AAcquiredOwner="+acquiredA+" scopedCancelAccepted="+scopedCancelledB+" BStillPublishable="+gate.accepts(bToken));
  check(gate.accepts(bToken),"DESIRED INVARIANT FAILED: obsolete queued A cleanup invalidated unrelated winning B despite never acquiring A's owner");
 }
}
