package app.xio.xio;
import java.nio.file.Files;
import java.nio.file.Path;

/** Actual gate + exact Engine replacement wiring; no Android/JNI execution. */
public final class ReviewReplacementPublicationInvariant {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 public static void main(String[] args)throws Exception{
  String src=Files.readString(Path.of(args[0]));
  int start=src.indexOf("fun connect(id: String");String activation=src.substring(start,src.indexOf("class MainActivity",start));
  check(activation.contains("check(!isUp())")&&activation.indexOf("Mobile.stopWithTimeout")<activation.indexOf("publication.begin(publicationToken,budget,roundId)"),"actual failed-owner replacement path changed; inspect this negative fixture");
  check(!activation.contains("publication.invalidate()")&&!activation.contains("publication.revoke()"),"actual replacement now revokes old publication; inspect fixture");
  PublicationLease gate=new PublicationLease();
  ConnectionBudget rootB=new ConnectionBudget(30000,()->1000L);long admittedB=gate.register(rootB);ConnectionBudget childB=rootB.cap(15000);
  gate.begin(admittedB,childB,"owner-B");
  ConnectionBudget rootA=new ConnectionBudget(30000,()->1000L);long admittedA=gate.register(rootA);ConnectionBudget childA=rootA.cap(15000);
  long queuedOldUp=gate.token(); // Old B's UP is already queued, not a late JNI callback.
  gate.release(rootB);
  // B's native session failed and Mobile.stopWithTimeout joined it. Unlike
  // Engine.disconnect, this actual path does not invalidate the gate epoch.
  gate.begin(admittedA,childA,"replacement-A");
  boolean accepted=gate.accepts(queuedOldUp)&&ConnectionBudget.canPublishUp(false,false,childA,queuedOldUp,gate.token());
  System.out.println("Mock actual failed-owner replacement: oldUPToken="+queuedOldUp+" newOwnerToken="+gate.token()+" oldUPAccepted="+accepted+" oldChildOwns="+gate.owns("owner-B",childB));
  check(!accepted,"DESIRED INVARIANT FAILED: a queued old owner UP was accepted under a different owner's live setup budget");
 }
}
