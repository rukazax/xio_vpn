package app.xio.xio

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * On-device diagnostic log for test builds.
 *
 * Deliberately separate from the user-facing session journal in Dart: this file
 * is written from both Dart and the VPN service, survives restarts, and can be
 * exported or uploaded as a bundle. It must never contain VPN keys, preshared
 * keys or profile URIs, so every line goes through [redact].
 */
object Diag {
    private const val FILE = "xio.log"
    private const val MAX_BYTES = 2L * 1024 * 1024
    private const val KEEP = 2
    private const val MAX_LINE = 4000

    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "xio-diag").apply { isDaemon = true }
    }
    @Volatile private var appContext: Context? = null
    @Volatile private var directory: File? = null
    @Volatile private var started = false

    fun init(context: Context) {
        if (started) return
        started = true
        appContext = context.applicationContext
        val dir = File(context.applicationContext.filesDir, "diag")
        try {
            dir.mkdirs()
        } catch (_: Exception) {
        }
        directory = dir
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            append("crash", "${thread.name}: ${error.javaClass.name}: ${error.message}")
            previous?.uncaughtException(thread, error)
        }
        append(
            "app",
            "start ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) " +
                "test=${BuildConfig.TEST_BUILD} sdk=${Build.VERSION.SDK_INT} " +
                "device=${Build.MANUFACTURER}/${Build.MODEL} abi=${Build.SUPPORTED_ABIS.firstOrNull() ?: ""}"
        )
    }

    fun append(tag: String, message: String) {
        val line = "${stamp()} $tag: ${redact(message)}"
        try {
            Log.i("XIO", line.take(MAX_LINE))
        } catch (_: Exception) {
        }
        executor.execute { write(line) }
    }

    private fun stamp(): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US).format(Date())

    /** Drop anything that could be a key, token or complete profile URI. */
    private fun redact(message: String): String {
        var out = message.replace('\u0000', ' ')
        for (marker in listOf("PrivateKey", "PresharedKey", "HeaderProtectionKey", "xio://", "vpn://")) {
            if (out.contains(marker, ignoreCase = true)) return "[redacted: $marker]"
        }
        out = out.replace(Regex("[A-Za-z0-9+/=_-]{80,}"), "[redacted:long-token]")
        return out.take(MAX_LINE)
    }

    private fun write(line: String) {
        val dir = directory ?: return
        synchronized(this) {
            try {
                val file = File(dir, FILE)
                if (file.length() + line.length + 1 > MAX_BYTES) rotate(dir)
                file.appendText(line + "\n")
            } catch (_: Exception) {
            }
        }
    }

    private fun rotate(dir: File) {
        try {
            for (index in KEEP downTo 1) {
                val older = File(dir, "$FILE.$index")
                if (!older.exists()) continue
                if (index == KEEP) older.delete() else older.renameTo(File(dir, "$FILE.${index + 1}"))
            }
            val current = File(dir, FILE)
            if (current.exists()) current.renameTo(File(dir, "$FILE.1"))
        } catch (_: Exception) {
        }
    }

    fun snapshot(maxBytes: Int = 200_000): String {
        val dir = directory ?: return ""
        val files = (0..KEEP).map { if (it == 0) File(dir, FILE) else File(dir, "$FILE.$it") }
        val out = StringBuilder()
        for (file in files.reversed()) {
            if (!file.exists()) continue
            try {
                val text = file.readText()
                if (out.length + text.length > maxBytes) {
                    out.append(text.takeLast((maxBytes - out.length).coerceAtLeast(0)))
                    break
                }
                out.append(text)
            } catch (_: Exception) {
            }
        }
        return out.toString()
    }

    /** `logcat` of this process only; apps may read their own UID's buffer. */
    fun logcat(): String {
        return try {
            val process = ProcessBuilder(
                "logcat", "-d", "-v", "threadtime", "-t", "4000", "--pid", android.os.Process.myPid().toString()
            ).redirectErrorStream(true).start()
            val text = process.inputStream.bufferedReader().use { it.readText() }
            if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroy()
            text.take(2_000_000)
        } catch (_: Exception) {
            ""
        }
    }

    private fun deviceInfo(): String = buildString {
        appendLine("version=${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        appendLine("testBuild=${BuildConfig.TEST_BUILD}")
        appendLine("package=${appContext?.packageName ?: ""}")
        appendLine("android=${Build.VERSION.RELEASE} sdk=${Build.VERSION.SDK_INT}")
        appendLine("device=${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})")
        appendLine("abis=${Build.SUPPORTED_ABIS.joinToString()}")
        appendLine("time=${stamp()}")
    }

    /** Zip with the session log, a logcat dump and non-identifying device facts. */
    fun bundle(): File? {
        val context = appContext ?: return null
        val dir = directory ?: return null
        return try {
            val shared = File(context.cacheDir, "shared_profiles").apply { mkdirs() }
            shared.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > 6 * 3600_000L }?.forEach { it.delete() }
            val out = File(shared, "XIO-diag-${System.currentTimeMillis()}.zip")
            ZipOutputStream(out.outputStream().buffered()).use { zip ->
                for (name in listOf(FILE, "$FILE.1", "$FILE.2")) {
                    val file = File(dir, name)
                    if (!file.exists()) continue
                    zip.putNextEntry(ZipEntry("diag/$name"))
                    file.inputStream().use { it.copyTo(zip) }
                    zip.closeEntry()
                }
                zip.putNextEntry(ZipEntry("diag/logcat.txt"))
                zip.write(logcat().toByteArray())
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("diag/device.txt"))
                zip.write(deviceInfo().toByteArray())
                zip.closeEntry()
            }
            out
        } catch (_: Exception) {
            null
        }
    }
}
