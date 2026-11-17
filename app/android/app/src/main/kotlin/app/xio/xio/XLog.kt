package app.xio.xio

/**
 * Logcat is a diagnostic channel, not a product feature.
 *
 * Release builds write nothing to logcat from this package: the whole object
 * compiles down to no-ops unless the build is a test build
 * (`-PxioTestBuild=true`). Debug builds keep full output.
 */
object XLog {
    fun i(tag: String, message: String) {
        if (BuildConfig.TEST_BUILD) android.util.Log.i(tag, message)
    }

    fun d(tag: String, message: String) {
        if (BuildConfig.TEST_BUILD) android.util.Log.d(tag, message)
    }

    fun w(tag: String, message: String) {
        if (BuildConfig.TEST_BUILD) android.util.Log.w(tag, message)
    }

    fun w(tag: String, message: String, error: Throwable) {
        if (BuildConfig.TEST_BUILD) android.util.Log.w(tag, message, error)
    }

    fun e(tag: String, message: String, error: Throwable? = null) {
        if (BuildConfig.TEST_BUILD) android.util.Log.e(tag, message, error)
    }
}
