package app.xio.xio;
import java.nio.file.*;
/** Independent desired invariants against actual gate; modeled queue, not Android/JNI. */
public final class ReviewPublicationFinalInvariant {
 static void check(boolean v,String m){if(!v)throw new AssertionError(m);}
 public static void main(String[] args)throws Exception {
  Path p=Path.of(args[0]);String e=Files.readString(p.resolve("MainActivity.kt")), c=Files.readString(p.resolve("VpnControlService.kt")),s=Files.readString(p.resolve("XioVpnService.kt"));
  String activation=e.substring(e.indexOf("fun connect(id: String"),e.indexOf("class MainActivity"));
  check(activation.indexOf("Mobile.stopWithTimeout")<activation.indexOf("publication.begin(admissionToken,budget,roundId)"),"failed-native-owner must join before replacement");
  check(activation.contains("val token=publication.begin(admissionToken,budget,roundId)")&&activation.contains("return publicationToken"),"return actual new publication token");
  check(e.contains("val publicationToken=Engine.connect(")&&e.contains("Engine.acceptsUpPublication(publicationToken)"),"Activity own success must not use admission token");
  String cancel=e.substring(e.indexOf("fun cancelConnect("),e.indexOf("// Called only by the serialized worker"));
  check(cancel.contains("val token=synchronized(publication)")&&cancel.indexOf("publication.token()")<cancel.indexOf("backend.cancelPendingHandshake()")&&cancel.lastIndexOf("publication.token()")==cancel.indexOf("publication.token()")&&cancel.contains("return token"),"retirement token must be captured under same gate before native cancellation, never re-read late");
  check(c.contains("Engine.cancelConnect(roundId)?.let {XioVpnService.stateChanged(false,it)}"),"rejected obsolete cancellation must emit no DOWN");
  check(s.contains("fun stateChanged(up: Boolean, token:Long)")&&s.contains("if(token!=Engine.publicationToken())return@post"),"queue must reject old DOWN too");
  String awg=e.substring(e.indexOf("private fun activationTunnel"),e.indexOf("@Synchronized fun initialize"));
  check(awg.indexOf("if(!publication.accepts(token))return")<awg.indexOf("clearActiveId(")&&awg.contains("acceptsUpPublication(token),token)")&&awg.contains("@Volatile var tunnel:Tunnel"),"AWG activation callback must fence preference/UI writes and retain current handle");
  long[] clock={1000};PublicationLease g=new PublicationLease();ConnectionBudget rb=new ConnectionBudget(30000,()->clock[0]),ra=new ConnectionBudget(30000,()->clock[0]);
  long ab=g.register(rb),aa=g.register(ra);ConnectionBudget b=rb.cap(15000),a=ra.cap(15000);long old=g.begin(ab,b,"B");g.release(rb);
  long own=g.begin(aa,a,"A");
  check(old!=own&&!g.accepts(old)&&g.accepts(own),"queued old UP must fail and own UP pass after joined replacement");
  check(!ConnectionBudget.canPublishUp(false,false,a,old,g.token())&&ConnectionBudget.canPublishUp(false,false,a,own,g.token()),"actual budget publication predicate");
  check(!g.owns("B",b)&&g.owns("A",a),"exact child ownership");
  long down; synchronized(g){check(g.retire("A",a),"own retire");g.reserveCancellation();down=g.token();}
  check(down==g.token(),"own matching DOWN allowed despite revoked UP");
  g.finishCancellation(); // Force B.begin BETWEEN actual cancellation return and modeled main-loop DOWN execution.
  ConnectionBudget rb2=new ConnectionBudget(30000,()->clock[0]);long b2=g.begin(g.register(rb2),rb2,"B2");
  check(down!=g.token()&&g.accepts(b2),"retired queued DOWN must not stop new winner");
  int downPosts=0; if(g.retire("A",a))downPosts++;
  check(downPosts==0&&g.accepts(b2),"rejected old owner must post NONE");
  long before=g.admissionToken();ConnectionBudget permission=new ConnectionBudget(30000,()->clock[0]);g.register(permission);g.revoke();
  check(permission.availableMillis()==0&&!g.accepts(b2),"global DOWN cancels pending root and live publication");
  ConnectionBudget fresh=new ConnectionBudget(30000,()->clock[0]);try{g.begin(before,fresh,"old-permission");throw new AssertionError("stale admission accepted");}catch(ConnectionBudget.Expired expected){}
  check(g.accepts(g.begin(g.register(fresh),fresh,"new")),"new admission/own UP allowed");
  System.out.println("PASS independent final gate/source: old queued UP drops, own UP passes; own DOWN allowed, replacement between cancellation return and DOWN post drops old DOWN, rejected owner emits NONE; AWG captured callback before writes; permission/root DOWN");
 }
}
