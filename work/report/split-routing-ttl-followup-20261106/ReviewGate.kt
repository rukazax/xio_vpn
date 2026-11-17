package app.xio.xio
import java.io.File
import java.lang.reflect.Modifier
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
object ReviewGate {
 @JvmStatic fun main(args:Array<String>) {
  if(args.firstOrNull()=="clock") {
   val inputs=File(args[1]).readLines().map{it.toLong()}
   var mono=0L
   val actual=RoutingResolutionGate{mono}
   actual.begin("r1","first");actual.commit("r1","first",600000){}
   mono=inputs[0]
   check(actual.ready("r1"))
   actual.begin("r1","reapply-cached")
   actual.commit("r1","reapply-cached",inputs[1]){}
   mono=660000
   val ready=actual.ready("r1")
   println("OBSERVED actual gate: originalDNSage=${mono}ms originalDeadline=600000ms secondBegin=${inputs[0]}ms DartActualRemaining=${inputs[1]}ms readyAt11minutes=$ready")
   check(!ready){"CONTRACT FAILURE: cached DNS older than original10m remains activatable after backward wall-clock correction; actual Dart allowance + actual Kotlin gate, no native/clock mutation"}
   return
  }
  for(name in listOf("begin","cancel","invalidate","commit","ready")) {
   val methods=RoutingResolutionGate::class.java.declaredMethods.filter{it.name==name}
   check(methods.isNotEmpty() && methods.all{Modifier.isSynchronized(it.modifiers)}){"$name lacks same-instance JVM monitor"}
  }
  var now=1000L
  val gate=RoutingResolutionGate{now}
  gate.begin("r1","one");gate.commit("r1","one",600000){}
  now=600999;check(gate.ready("r1"));now=601000;check(!gate.ready("r1"))
  gate.begin("r1","two");var writes=0
  try {gate.commit("r1","one",10){writes++};error("stale owner accepted")} catch(_:IllegalStateException){}
  check(writes==0)
  gate.cancel("r1","one");gate.commit("r1","two",10){writes++};check(writes==1)
  now=601009;check(gate.ready("r1"));now=601010;check(!gate.ready("r1"))
  gate.begin("expire","during-write")
  try {gate.commit("expire","during-write",10){now+=10};error("write crossing TTL accepted")}catch(_:IllegalStateException){}
  check(!gate.ready("expire"))
  gate.begin("clock","one");gate.commit("clock","one",10){};now--;check(!gate.ready("clock"))
  check(!RoutingResolutionGate{now}.ready("r1"))
  val entered=CountDownLatch(1);val release=CountDownLatch(1)
  val editorAttempted=CountDownLatch(1);val editorEntered=CountDownLatch(1)
  val error=AtomicReference<Throwable?>(null)
  gate.begin("atomic","owner")
  val writer=Thread{try{gate.commit("atomic","owner"){entered.countDown();check(release.await(2,TimeUnit.SECONDS))}}catch(t:Throwable){error.compareAndSet(null,t)}}
  writer.start();check(entered.await(2,TimeUnit.SECONDS))
  val editor=Thread{try{editorAttempted.countDown();synchronized(gate){gate.invalidate();editorEntered.countDown()}}catch(t:Throwable){error.compareAndSet(null,t)}}
  editor.start();check(editorAttempted.await(2,TimeUnit.SECONDS))
  check(!editorEntered.await(100,TimeUnit.MILLISECONDS)){"policy editor interleaved within commit"}
  release.countDown();writer.join(2000);editor.join(2000)
  check(!writer.isAlive && !editor.isAlive && error.get()==null){"child thread failed: ${error.get()}"}
  check(editorEntered.count==0L && !gate.ready("atomic"))
  println("PASS independent actual compiled gate: synchronized JVM methods, stale owner no-write, exact cancel,599999/600000,short TTL,write-crossing-expiry,negative clock,restart,joined serialized editor/commit")
 }
}
