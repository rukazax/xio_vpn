package app.x1o.x1o

import android.content.Context
import android.content.res.Resources
import org.json.JSONObject

/** Same offline catalogues as Flutter. Never translates configuration or secrets. */
object L10n {
    private val languages = setOf("ru", "en", "de", "es", "fr", "it", "pt", "zh", "ja", "ko", "tr", "hi", "ar")
    private val cache = mutableMapOf<String, JSONObject>()
    fun select(context: Context, code: String) {
        require(code.isEmpty() || code in languages)
        check(context.getSharedPreferences("x1o", 0).edit().putString("language", code).commit())
        X1oVpnService.languageChanged()
        VpnTileService.refresh(context)
    }
    private fun code(context: Context): String {
        val explicit = context.getSharedPreferences("x1o", 0).getString("language", "") ?: ""
        if (explicit in languages) return explicit
        val locales = Resources.getSystem().configuration.locales
        for (i in 0 until locales.size()) if (locales[i].language in languages) return locales[i].language
        return "en"
    }
    fun text(context: Context, source: String, vararg args: String): String {
        val language = code(context)
        var result = if (language == "ru") source else synchronized(cache) {
            val catalog = cache.getOrPut(language) {
                context.assets.open("flutter_assets/assets/l10n/$language.json").bufferedReader().use { JSONObject(it.readText()) }
            }
            catalog.optString(source, source)
        }
        args.forEachIndexed { i, arg -> result = result.replace("{$i}", arg) }
        return result
    }
}
