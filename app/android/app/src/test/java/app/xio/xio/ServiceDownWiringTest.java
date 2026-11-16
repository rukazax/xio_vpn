package app.xio.xio;

import java.nio.file.Files;
import java.nio.file.Path;

/** Actual production gate plus source-entry ordering, NOT a Kotlin/JNI test. */
public final class ServiceDownWiringTest {
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    private static String section(String source, String start, String end) {
        return source.substring(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
    }
    private static void prequeue(String handler) {
        int fence = handler.indexOf("Engine.revokePublication()");
        int queue = handler.indexOf("Engine.worker.execute");
        check(fence >= 0 && queue > fence, "DOWN must revoke before queue admission");
        String prefix = handler.substring(0, queue);
        check(!prefix.contains(".commit()") && !prefix.contains("Mobile.") && !prefix.contains("Engine.disconnect("),
                "DOWN fence must not perform storage/JNI/joined teardown");
    }
    public static void main(String[] args) throws Exception {
        Path kotlin = Path.of(args[0]);
        String service = new String(Files.readAllBytes(kotlin.resolve("XioVpnService.kt")), java.nio.charset.StandardCharsets.UTF_8);
        String engine = new String(Files.readAllBytes(kotlin.resolve("MainActivity.kt")), java.nio.charset.StandardCharsets.UTF_8);
        String controller = new String(Files.readAllBytes(kotlin.resolve("VpnControlService.kt")), java.nio.charset.StandardCharsets.UTF_8);
        prequeue(section(service,"if (intent?.action == DISCONNECT)","if((intent==null"));
        prequeue(section(service,"override fun onRevoke()","override fun onDestroy()"));
        prequeue(section(controller,"override fun onStartCommand","if(Engine.backgroundBusy) return"));
        String revoke = section(engine,"fun revokePublication(","fun cancelConnect(");
        check(revoke.contains("publication.revoke()") && revoke.contains("operationBudget?.cancel()"), "actual Engine must wire both gates");
        check(!revoke.contains("Mobile.") && !revoke.contains("backend.") && !revoke.contains(".commit()"), "pure immediate fence");
        String scoped = section(engine,"fun cancelConnect(","fun retireRound(");
        check(scoped.contains("if(roundId == null) revokePublication()") && scoped.contains("publication.retire(roundId,expectedBudget)"), "actual Engine child failure must not globally revoke parent roots");
        check(engine.contains("publication.accepts(token)"), "actual Engine uses production lease");
        check(engine.contains("cancelConnect(roundId,budget)") && engine.contains("Engine.cancelConnect(request.roundId,request.budget)") && engine.contains("publication.owns(roundId,expectedBudget)"), "scoped cancel/retirement must match actual child identity");
        check(scoped.contains("publication.reserveCancellation()") && scoped.indexOf("publication.reserveCancellation()") < scoped.indexOf("backend.cancelPendingHandshake()") && scoped.contains("finally { publication.finishCancellation() }") && engine.contains("!cleanupIncomplete && publication.idle()"), "actual Engine must reserve native cancellation until it returns");
        check(engine.contains("Engine.registerConnect(round)"), "permission/queued Activity admission must be captured before worker");
        check(controller.contains("Engine.registerConnect(round)"), "controller queued budget must be revocable");
        for (boolean pending : new boolean[]{false,true}) {
            PublicationLease gate = new PublicationLease();
            ConnectionBudget round = new ConnectionBudget(30000, () -> 1000L);
            ConnectionBudget attempt = round.cap(15000);
            long admission = gate.register(round);
            long old = gate.begin(admission, attempt);
            check(gate.accepts(old), "live before DOWN");
            gate.revoke(); // Production pure method invoked synchronously by service.
            check(!gate.accepts(old), "old callback accepted after service DOWN returns");
            check(round.availableMillis()==0 && attempt.availableMillis()==0, "queued/active budget not canceled");
            check(!ConnectionBudget.canPublishUp(true,true,pending?attempt:null,old,gate.token()), "actual predicate accepted late UP");
            try { gate.begin(admission,attempt); throw new AssertionError("old lease restarted after DOWN"); }
            catch(ConnectionBudget.Expired expected) { }
            ConnectionBudget replacement = new ConnectionBudget(30000, () -> 1000L);
            long freshAdmission = gate.register(replacement);
            long fresh = gate.begin(freshAdmission,replacement);
            check(gate.accepts(fresh) && !gate.accepts(old), "replacement/old callback fence");
            gate.release(round); // Late old release must not cancel a winning replacement.
            check(gate.accepts(fresh) && replacement.availableMillis()>0, "obsolete cleanup poisoned winner");
        }
        PublicationLease gate = new PublicationLease();
        ConnectionBudget root = new ConnectionBudget(30000, () -> 1000L);
        gate.register(root);
        root.cap(1000).cancel();
        gate.invalidate(); // Internal candidate cleanup, unlike external DOWN.
        check(root.availableMillis()>0, "candidate retirement canceled automatic parent");
        String activityWorker=section(engine,"private fun connect(request:","private fun preparePendingVpn");
        check(activityWorker.contains("Engine.disconnectOwned(request.roundId,request.budget,request.round)") && !activityWorker.contains("Engine.disconnect(request.round)"),"actual failed-before-owner Activity catch must not globally disconnect another winner");
        check(controller.contains("attemptOwner=attempt") && controller.contains("Engine.disconnectOwned(roundId,it,owner)") && controller.contains("Engine.disconnectOwned(roundId,it,round)"),"actual controller attempt/outer failure cleanup must be owner-scoped");
        String ownedDisconnect=section(engine,"fun disconnectOwned(","fun retireRound(");
        check(ownedDisconnect.contains("ownedRoundId==roundId && publication.owns(roundId,expectedBudget)") && ownedDisconnect.contains("disconnect(budget)"),"physical cleanup must require exact round and child ownership");
        check(engine.contains("val token=publication.begin(admissionToken,budget,roundId)") && engine.contains("return publicationToken") && activityWorker.contains("val publicationToken=Engine.connect(") && activityWorker.contains("admissionToken=request.admissionToken") && activityWorker.contains("Engine.acceptsUpPublication(publicationToken)") && !activityWorker.contains("request.publicationToken"),"actual own success must use unique returned activation token, not queued admission identity");
        check(service.contains("fun stateChanged(up: Boolean, token:Long)") && service.contains("token!=Engine.publicationToken()"),"service queue must consume caller-owned publication token");
        check(controller.contains("Engine.cancelConnect(roundId)?.let {XioVpnService.stateChanged(false,it)}") && scoped.contains("publication.token()") && scoped.contains("return token"),"retired DOWN must carry the token captured inside the same cancellation gate");
        check(engine.contains("tunnel=activationTunnel(publicationToken)") && engine.contains("if(!publication.accepts(token))return") && engine.contains("acceptsUpPublication(token),token)"),"actual AWG callback must capture activation identity");
        for(String backend:new String[]{"RivetBackend.kt","XrayBackend.kt","OpenVpnBackend.kt"}) {
            String body=new String(Files.readAllBytes(kotlin.resolve(backend)), java.nio.charset.StandardCharsets.UTF_8);
            check(body.contains("val token=Engine.publicationToken()") && body.contains("Engine.requireActivation(token)") && body.contains("XioVpnService.stateChanged(true,token)"),"native backend must pass its captured owner token: "+backend);
            if(backend.equals("OpenVpnBackend.kt"))check(body.contains("Client(service,token)") && body.contains("Engine.acceptsUpPublication(token)"),"OpenVPN Client event must retain activation token");
        }
        long[] clock = {1000L};
        PublicationLease fallback = new PublicationLease();
        ConnectionBudget original = new ConnectionBudget(30000, () -> clock[0]);
        fallback.register(original);
        ConnectionBudget[] first = {null}, activeChild = {null};
        int winner = original.runCandidates(2,10000,new ConnectionBudget.Attempts() {
            public void connect(int index, ConnectionBudget attempt) throws Exception {
                long epoch = fallback.begin(fallback.admissionToken(),attempt,"same-controller-round");activeChild[0]=attempt;
                if(index==0) {
                    first[0]=attempt;clock[0]+=700;
                    check(fallback.retire("same-controller-round",attempt),"failed child not retired");
                    check(!fallback.accepts(epoch) && attempt.availableMillis()==0 && original.availableMillis()==29300,"failed child retained UP or canceled/renewed parent");
                    throw new Exception("synthetic first candidate failure");
                }
                check(!fallback.retire("same-controller-round",first[0]),"late old child canceled next candidate sharing roundId");
                check(!fallback.retire("obsolete-round",null),"late old round canceled winner");
                check(fallback.accepts(epoch) && original.availableMillis()==29300,"child failure renewed or canceled original round");
            }
            public void cleanup(ConnectionBudget round) { fallback.invalidate();check(round==original && round.availableMillis()==29300,"cleanup replaced/canceled original root"); }
        });
        check(winner==1 && original.availableMillis()==29300,"automatic second candidate did not win within original deadline");
        int ownedCleanup=0;
        if(fallback.owns("same-controller-round",first[0]))ownedCleanup++;
        check(ownedCleanup==0 && fallback.accepts(fallback.token()),"obsolete same-round child cleanup touched winner");
        if(fallback.owns("same-controller-round",activeChild[0]))ownedCleanup++;
        check(ownedCleanup==1,"matching successful owner could not clean up");

        long[] queuedClock={1000};
        PublicationLease owners=new PublicationLease();
        ConnectionBudget bRound=new ConnectionBudget(30000,()->queuedClock[0]);
        long bAdmission=owners.register(bRound);
        ConnectionBudget b=bRound.cap(30000);
        ConnectionBudget aRound=new ConnectionBudget(30000,()->queuedClock[0]),a=aRound.cap(15000);
        long aAdmission=owners.register(aRound);long bEpoch=owners.begin(bAdmission,b,"winning-tile-B");
        queuedClock[0]=17000;owners.release(bRound);int obsoleteCleanup=0;
        try {a.remainingMillis();owners.begin(aAdmission,a,"queued-A");throw new AssertionError("expired A acquired owner");}
        catch(ConnectionBudget.Expired expected) {if(owners.owns("queued-A",a))obsoleteCleanup++;}
        check(obsoleteCleanup==0 && owners.accepts(bEpoch) && b.availableMillis()==14000,"expired before-owner A cleaned up live B or renewed B deadline");

        PublicationLease reserved = new PublicationLease();
        ConnectionBudget queued = new ConnectionBudget(30000, () -> 1000L);
        long before = reserved.register(queued);
        ConnectionBudget oldChild = queued.cap(10000), nextChild = queued.cap(10000);
        reserved.begin(before,oldChild,"round");reserved.retire("round",oldChild);
        reserved.reserveCancellation(); // Native cancel admitted, but deliberately not yet joined.
        long retiredDown = reserved.token();
        long nextAdmission = reserved.admissionToken();
        try { reserved.begin(nextAdmission,nextChild,"round");throw new AssertionError("replacement entered while old JNI cancel was unjoined"); }
        catch(IllegalStateException expected) { }
        check(queued.availableMillis()==30000,"child cancellation killed queued parent");
        reserved.finishCancellation();long next=reserved.begin(nextAdmission,nextChild,"round");
        check(retiredDown!=next && !reserved.accepts(retiredDown),"queued retired DOWN/UP was rebound to successor after cancellation joined");
        check(!reserved.retire("round",oldChild) && reserved.accepts(next),"delayed old child touched replacement");
        reserved.reserveCancellation();
        reserved.revoke(); // External DOWN remains immediate even during an admitted native cancel.
        check(!reserved.idle() && !reserved.accepts(next) && queued.availableMillis()==0 && nextChild.availableMillis()==0,"external DOWN failed to revoke all roots without joining native cancel");
        reserved.finishCancellation();
        check(!reserved.accepts(next),"late cancellation completion resurrected UP");
        PublicationLease replacementGate=new PublicationLease();
        ConnectionBudget oldRoot=new ConnectionBudget(30000,()->1000L),newRoot=new ConnectionBudget(30000,()->1000L);
        long oldAdmission=replacementGate.register(oldRoot),newAdmission=replacementGate.register(newRoot);
        ConnectionBudget oldAttempt=oldRoot.cap(15000),newAttempt=newRoot.cap(15000);
        long oldUp=replacementGate.begin(oldAdmission,oldAttempt,"failed-B");
        replacementGate.release(oldRoot); // Old native owner joined without an explicit disconnect/invalidate.
        long ownUp=replacementGate.begin(newAdmission,newAttempt,"replacement-A");
        check(ownUp!=oldUp && !replacementGate.accepts(oldUp) && replacementGate.accepts(ownUp),"already queued old UP survived failed-owner replacement");
        check(!ConnectionBudget.canPublishUp(false,false,newAttempt,oldUp,replacementGate.token()) && ConnectionBudget.canPublishUp(false,false,newAttempt,ownUp,replacementGate.token()),"new child budget revived old UP or rejected its own UP");
        check(!replacementGate.owns("failed-B",oldAttempt) && replacementGate.owns("replacement-A",newAttempt),"replacement lost exact child ownership");
        PublicationLease permissionGate=new PublicationLease();
        ConnectionBudget pendingRoot=new ConnectionBudget(30000,()->1000L);
        long pendingAdmission=permissionGate.register(pendingRoot);
        permissionGate.revoke();
        ConnectionBudget freshRoot=new ConnectionBudget(30000,()->1000L);
        long freshAdmission=permissionGate.register(freshRoot);
        try {permissionGate.begin(pendingAdmission,freshRoot);throw new AssertionError("old permission admission accepted even with uncanceled budget");}
        catch(ConnectionBudget.Expired expected) { }
        long freshOwn=permissionGate.begin(freshAdmission,freshRoot);
        check(permissionGate.accepts(freshOwn),"DOWN admission fence rejected legitimate new owner's own UP");
        System.out.println("PASS: actual source wiring + production gate external DOWN/admission, unique per-activation UP/DOWN, replacement/own-success, automatic fallback/deadline, obsolete cleanup and cancel-owner invariants (no Kotlin/JNI execution)");
    }
}
