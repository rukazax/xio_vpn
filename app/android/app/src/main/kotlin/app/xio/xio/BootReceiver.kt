package app.xio.xio

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

/**
 * Автозапуск XIO после загрузки устройства.
 *
 * Ресивер объявлен в манифесте выключенным (`android:enabled="false"`), потому
 * что `BOOT_COMPLETED` доставляется только статически зарегистрированным
 * получателям. Настройка «Автозапуск при загрузке устройства» включает и
 * выключает компонент через `PackageManager` (метод канала `setAutostart`).
 *
 * При загрузке ресивер открывает приложение и — если включено
 * «Автоподключение после запуска» и выдано разрешение на уведомления — ставит
 * запрос на подключение, который Flutter забирает существующим
 * `consumeConnectRequest` при старте.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences("xio", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("autostart", false)) return

        // Без POST_NOTIFICATIONS VPN-служба не покажет постоянное уведомление,
        // поэтому подключение не запрашивается: пользователь увидит экран и
        // сможет выдать разрешение сам.
        val notificationsAllowed = Build.VERSION.SDK_INT < 33 ||
            context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (notificationsAllowed && prefs.getBoolean("autoConnectOnStart", false)) {
            prefs.edit().putBoolean("connectRequested", true).apply()
        } else {
            prefs.edit().remove("connectRequested").apply()
        }

        // Android 10+ может запретить запуск активности из фона. Если запуск
        // не удался, запрос на подключение остаётся и применяется при
        // следующем открытии приложения.
        try {
            context.startActivity(
                Intent(context, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    putExtra("bootStart", true)
                }
            )
        } catch (_: Exception) {
            // Флаг connectRequested уже сохранён.
        }
    }
}
