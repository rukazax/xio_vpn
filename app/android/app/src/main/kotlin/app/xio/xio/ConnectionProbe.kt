package app.xio.xio

import android.os.SystemClock
import java.net.URL
import java.util.Timer
import java.util.TimerTask
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection

/** One absolute deadline across DNS/TLS, redirects and fresh-handshake checks.
 * The watchdog closes the request, never starts or changes an Engine tunnel.
 * Engine's single worker finishes cleanup before the next candidate starts.
 */
object ConnectionProbe {
 fun verify(site: URL, started: Long, timeoutMillis: Long) {
  val deadline = SystemClock.elapsedRealtime() + timeoutMillis
  val active = AtomicReference<HttpsURLConnection?>()
  fun remaining(): Int {
   val left = deadline - SystemClock.elapsedRealtime()
   if (left <= 0) throw TimeoutException("Connection deadline")
   return left.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
  }
  val watchdog = Timer("xio-probe-deadline", true)
  watchdog.schedule(object : TimerTask() {
   override fun run() { active.get()?.disconnect() }
  }, timeoutMillis)
  try {
   var url = site
   var reachable = false
   for (redirect in 0..4) {
    require(url.protocol == "https" && url.host.isNotEmpty() && url.userInfo == null)
    val request = url.openConnection() as HttpsURLConnection
    active.set(request)
    request.connectTimeout = remaining(); request.readTimeout = remaining()
    request.instanceFollowRedirects = false
    try {
     val code = request.responseCode
     remaining()
     if (code in listOf(301, 302, 303, 307, 308)) {
      check(redirect < 4)
      url = URL(url, request.getHeaderField("Location") ?: error("Missing redirect"))
     } else {
      reachable = code in 200..299
      break
     }
    } finally { request.disconnect(); active.set(null) }
   }
   check(reachable)
   while (true) {
    val left = remaining()
    val hs=Engine.handshake()
    if (hs >= started - 2000) return
    Thread.sleep(minOf(250, left).toLong())
   }
  } finally {
   watchdog.cancel()
   active.getAndSet(null)?.disconnect()
  }
 }
}
