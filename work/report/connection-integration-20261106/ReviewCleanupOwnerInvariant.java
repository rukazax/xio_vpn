package app.xio.xio;
import java.nio.file.Files;
import java.nio.file.Path;

/** Source-wired actual production owner predicate, no Kotlin/JNI/OS teardown. */
public final class ReviewCleanupOwnerInvariant {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 public static void main(String[] args)throws Exception{
  Path kotlin=Path.of(args[0]);String engine=Files.readString(kotlin.resolve("MainActivity.kt")),controller=Files.readString(kotlin.resolve("VpnControlService.kt"));
  int start=engine.indexOf("fun disconnectOwned(");check(start>=0,"missing owner-scoped production cleanup");
  String helper=engine.substring(start,engine.indexOf("fun retireRound(",start));
  check(helper.contains("ownedRoundId==roundId && publication.owns(roundId,expectedBudget)")&&helper.contains("disconnect(budget)"),"actual worker cleanup lacks both owner fences/original cleanup budget");
  check(engine.contains("Engine.disconnectOwned(request.roundId,request.budget,request.round)")&&engine.contains("disconnectOwned(roundId,expectedBudget,budget)"),"Activity catch or queued retirement still uses global cleanup");
  check(controller.contains("attemptOwner=attempt")&&controller.contains("Engine.disconnectOwned(roundId,it,owner)")&&controller.contains("Engine.disconnectOwned(roundId,it,round)"),"controller cleanup loses exact current attempt or original round");
  long[] clock={1000};PublicationLease gate=new PublicationLease();
  ConnectionBudget rootB=new ConnectionBudget(30000,()->clock[0]);long admittedB=gate.register(rootB);ConnectionBudget b=rootB.cap(25000);gate.begin(admittedB,b,"B");long winningB=gate.token();
  clock[0]=2000;ConnectionBudget rootA=new ConnectionBudget(30000,()->clock[0]);gate.register(rootA);ConnectionBudget a=rootA.cap(15000);
  clock[0]=18000;gate.release(rootB);int effects=0;
  try{a.remainingMillis();throw new AssertionError("A did not expire before acquiring owner");}catch(ConnectionBudget.Expired expected){if(gate.owns("A",a)){effects++;gate.invalidate();}}
  check(effects==0&&gate.accepts(winningB)&&b.availableMillis()>0,"obsolete queued A cleanup touched B");
  // Another child of the SAME root/round is a different cleanup owner too.
  ConnectionBudget next=rootB.cap(10000);gate.begin(gate.register(rootB),next,"B");long winningNext=gate.token();
  if(gate.owns("B",b)){effects++;gate.invalidate();}
  check(effects==0&&gate.accepts(winningNext),"old same-round child cleanup touched its replacement");
  next.cancel();long originalCleanup=rootB.cleanupMillis();
  if(gate.owns("B",next)){effects++;gate.invalidate();}
  check(effects==1&&!gate.accepts(winningNext)&&rootB.cleanupMillis()==originalCleanup&&rootB.availableMillis()>0,"matching canceled child lost cleanup authority or poisoned/renewed root");
  System.out.println("PASS independent actual owner predicate +source wiring: expired-before-owner A preserves B, same-round old child preserves next winner, matching canceled child retains independent original cleanup authority");
 }
}
