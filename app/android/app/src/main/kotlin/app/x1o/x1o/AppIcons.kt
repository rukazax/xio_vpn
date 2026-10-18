package app.x1o.x1o

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/** Launcher aliases only: the main activity, vault and VPN service stay intact. */
object AppIcons {
    private val variants = listOf("green", "white").flatMap { color ->
        listOf("dark", "clear").flatMap { background ->
            listOf(0, 90, 180, 270).map { "$color" + "_$background" + "_$it" }
        }
    }
    private fun component(context: Context, id: String) =
        ComponentName(context, "${context.packageName}.launcher.$id")
    private fun enabled(context: Context, id: String): Boolean {
        val state = context.packageManager.getComponentEnabledSetting(component(context, id))
        return state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED ||
            (id == variants.first() && state == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT)
    }
    fun ensureLauncher(context: Context) = select(context, current(context))
    fun current(context: Context): String {
        return variants.firstOrNull { enabled(context, it) } ?: variants.first()
    }
    @Synchronized fun select(context: Context, id: String) {
        require(id in variants)
        val pm = context.packageManager
        val previous = current(context)
        if (id == previous && enabled(context, id) && variants.count { enabled(context, it) } == 1) return
        if (Build.VERSION.SDK_INT >= 33) {
            pm.setComponentEnabledSettings(variants.map { value ->
                PackageManager.ComponentEnabledSetting(component(context, value),
                    if (value == id) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                    else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP)
            })
        } else {
            // Enable first so a failed switch can never leave no launcher entry.
            pm.setComponentEnabledSetting(component(context, id),
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
            try {
                variants.filter { it != id }.forEach { value ->
                    pm.setComponentEnabledSetting(component(context, value),
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
                }
            } catch (error: Exception) {
                pm.setComponentEnabledSetting(component(context, previous),
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
                pm.setComponentEnabledSetting(component(context, id),
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
                throw error
            }
        }
    }
}
