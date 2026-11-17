package app.xio.xio;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/** Independent pure production-gate + source-wiring checks; never JNI/Android. */
public final class ReviewCancellationOwnershipInvariant {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 public static void main(String[] args)throws Exception{
  String src=Files.readString(Path.of(args[0]));
  String cancel=src.substring(src.indexOf("fun cancelConnect("),src.indexOf("fun retireRound("));
  check(cancel.contains("publication.retire(roundId,expectedBudget)")&&cancel.contains("publication.reserveCancellation()")&&cancel.contains("finally { publication.finishCancellation() }"),"actual cancel call chain lacks child identity/reservation/finally");
  check(src.contains("cancelConnect(roundId,budget)")&&src.contains("Engine.cancelConnect(request.roundId,request.budget)"),"actual callsites omit exact child");
  long[] now={1000};PublicationLease gate=new PublicationLease();
  ConnectionBudget root=new ConnectionBudget(30000,()->now[0]);gate.register(root);
  ConnectionBudget[] old={null};
  int winner=root.runCandidates(2,10000,new ConnectionBudget.Attempts(){
   public void connect(int i,ConnectionBudget child)throws Exception{
    long admission=gate.register(root);gate.begin(admission,child,"same-root");long token=gate.token();
    if(i==0){
     old[0]=child;now[0]+=700;
     synchronized(gate){check(gate.retire("same-root",child),"wrong owner not retired");gate.reserveCancellation();}
     try{throw new IllegalStateException("synthetic JNI cancel failure");}
     finally{gate.finishCancellation();}
    }
    check(gate.idle(),"cancel exception leaked reservation");
    check(!gate.retire("same-root",old[0]),"late old child canceled same-root next winner");
    check(gate.accepts(token)&&root.availableMillis()==29300,"parent poisoned/renewed or winner not current");
   }
   public void cleanup(ConnectionBudget original){gate.invalidate();check(original==root&&root.availableMillis()==29300,"cleanup lost original parent/deadline");}
  });
  check(winner==1&&root.availableMillis()==29300,"real runCandidates did not reach second winner");

  PublicationLease blocked=new PublicationLease();ConnectionBudget queued=new ConnectionBudget(30000,()->1000L);long first=blocked.register(queued);
  ConnectionBudget child=queued.cap(10000);blocked.begin(first,child,"round");long firstOwner=blocked.token();
  CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);AtomicReference<Throwable> error=new AtomicReference<>();
  Thread canceller=new Thread(()->{try{
   synchronized(blocked){check(blocked.retire("round",child),"cancel ownership lost");blocked.reserveCancellation();}
   entered.countDown();try{release.await();}finally{blocked.finishCancellation();}
  }catch(Throwable e){error.set(e);entered.countDown();}},"review-fake-native-cancel");
  canceller.setDaemon(true);canceller.start();entered.await();check(error.get()==null,"canceller failed before reservation");
  // Nested physical cancellation must not clear an older unjoined reservation.
  blocked.reserveCancellation();blocked.finishCancellation();check(!blocked.idle(),"nested completion released other cancel owner");
  blocked.revoke();check(!blocked.accepts(firstOwner)&&queued.availableMillis()==0,"external DOWN failed while cancel unjoined");
  ConnectionBudget fresh=new ConnectionBudget(30000,()->1000L);long replacement=blocked.register(fresh);
  try{blocked.begin(replacement,fresh,"new-root");throw new AssertionError("new owner admitted while old cancel paused");}catch(IllegalStateException expected){}
  release.countDown();canceller.join(2000);check(!canceller.isAlive()&&error.get()==null&&blocked.idle(),"physical cancel did not join/release exactly its reservation");
  blocked.begin(replacement,fresh,"new-root");long winningToken=blocked.token();
  check(!blocked.retire("round",child)&&blocked.accepts(winningToken),"old completion/child poisoned new owner");
  try{blocked.finishCancellation();throw new AssertionError("cancellation underflow accepted");}catch(IllegalStateException expected){}
  check(blocked.idle()&&blocked.accepts(winningToken),"underflow changed a winning reservation");
  System.out.println("PASS independent source-wired actual gate: automatic second winner/original deadline, cancel exception finally, paused/nested cancel reservation, external DOWN, exact-child replacement, underflow (no JNI)");
 }
}
