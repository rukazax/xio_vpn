package app.xio.xio

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.AtomicFile
import org.json.JSONObject
import org.json.JSONArray
import org.amnezia.awg.config.Config
import org.amnezia.awg.config.Interface
import org.amnezia.awg.config.Peer
import java.io.File

class RoutingException(message: String) : Exception(message)

/** One local policy for both engines and every activation entry point. */
class SplitRouting(private val context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "split-routing.json"))
    data class Policy(val mode: String, val packages: List<String>, val networks: List<String> = emptyList()) {
        fun map(): Map<String, Any> = mapOf("mode" to mode, "packages" to packages, "networks" to networks)
    }
    fun read(): Policy {
        if (!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists()) return Policy("all", emptyList())
        try {
            val json = file.openRead().use { JSONObject(it.readBytes().toString(Charsets.UTF_8)) }
            require(json.getInt("schema") == 1)
            val list = json.getJSONArray("packages")
            val networks = json.optJSONArray("networks") ?: JSONArray()
            return validate(json.getString("mode"), (0 until list.length()).map { list.getString(it) }, (0 until networks.length()).map { networks.getString(it) })
        } catch (_: Exception) {
            throw RoutingException("Не удалось прочитать правила. Откройте раздельное туннелирование и сохраните их заново.")
        }
    }
    private fun validate(mode: String, packages: List<String>, networks: List<String>): Policy {
        if (mode !in listOf("all", "include", "exclude", "ipInclude", "ipExclude") || packages.size > 1024 ||
            packages.any { !it.matches(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*")) })
            throw RoutingException("Некорректные правила приложений")
        if (mode == "include" && packages.isEmpty())
            throw RoutingException("Выберите хотя бы одно приложение для VPN")
        val normalized = try { IpRoutes.normalize(networks) } catch (_: Exception) {
            throw RoutingException("Укажите IPv4/IPv6 или подсети CIDR, не более 128. Домены не поддерживаются.")
        }
        if (mode.startsWith("ip") && normalized.isEmpty()) throw RoutingException("Добавьте хотя бы один IP-адрес или подсеть")
        return Policy(mode, if (mode in listOf("include", "exclude")) packages.distinct().sorted() else emptyList(), if (mode.startsWith("ip")) normalized else emptyList())
    }
    private fun requireInstalled(policy: Policy) {
        for (name in policy.packages) {
            try { context.packageManager.getApplicationInfo(name, 0) }
            catch (_: PackageManager.NameNotFoundException) {
                throw RoutingException("Приложение $name недоступно. Обновите список раздельного туннелирования.")
            }
        }
    }
    fun save(mode: String, packages: List<String>, networks: List<String>): Policy {
        val policy = validate(mode, packages, networks)
        requireInstalled(policy)
        val json = JSONObject().put("schema", 1).put("mode", policy.mode).put("packages", JSONArray(policy.packages)).put("networks", JSONArray(policy.networks))
        val stream = file.startWrite()
        try {
            stream.write(json.toString().toByteArray(Charsets.UTF_8))
            file.finishWrite(stream)
        } catch (e: Exception) { file.failWrite(stream); throw e }
        return policy
    }
    fun apply(config: Config, policy: Policy = read()): Config {
        requireInstalled(policy)
        // Imported per-app fields cannot silently override the visible UI policy.
        if (config.`interface`.includedApplications.isNotEmpty() || config.`interface`.excludedApplications.isNotEmpty())
            throw RoutingException("Настройте приложения в разделе раздельного туннелирования")
        val lines = config.`interface`.toAwgQuickString().lineSequence().filter { it.isNotBlank() }.toMutableList()
        if (policy.mode != "all" && policy.packages.isNotEmpty())
            lines.add((if (policy.mode == "include") "IncludedApplications" else "ExcludedApplications") + " = " + policy.packages.joinToString(", "))
        val builder = Config.Builder().setInterface(Interface.parse(lines))
        for (peer in config.peers) {
            if (!policy.mode.startsWith("ip")) { builder.addPeer(peer); continue }
            val routes = try { IpRoutes.select(peer.allowedIps.map { it.toString() }, policy.networks, policy.mode == "ipInclude") }
                catch (_: Exception) { throw RoutingException("Не удалось построить маршруты. Уменьшите список подсетей.") }
            if (routes.isEmpty()) throw RoutingException("Правила не оставляют маршрутов VPN в этом профиле")
            val peerLines = peer.toAwgQuickString().lineSequence().filter { it.isNotBlank() && !it.startsWith("AllowedIPs =") }.toMutableList()
            peerLines.add("AllowedIPs = " + routes.joinToString(", "))
            builder.addPeer(Peer.parse(peerLines))
        }
        return builder.build()
    }
    fun applyNative(builder: android.net.VpnService.Builder) {
        val policy=read(); requireInstalled(policy)
        for(name in policy.packages) {
            if(policy.mode=="include") builder.addAllowedApplication(name)
            if(policy.mode=="exclude") builder.addDisallowedApplication(name)
        }
        val defaults=listOf("0.0.0.0/0","::/0")
        val routes=if(policy.mode.startsWith("ip")) IpRoutes.select(defaults,policy.networks,policy.mode=="ipInclude") else defaults
        if(routes.isEmpty()) throw RoutingException("Правила не оставляют маршрутов VPN в этом профиле")
        for(route in routes){val fields=route.split("/");builder.addRoute(fields[0],fields[1].toInt())}
        if(policy.mode.startsWith("ip")){builder.allowFamily(android.system.OsConstants.AF_INET);builder.allowFamily(android.system.OsConstants.AF_INET6)}
    }
    fun applications(): List<Map<String, String>> {
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val names = pm.queryIntentActivities(intent, 0).map { it.activityInfo.packageName }.toMutableSet()
        names.add(context.packageName)
        // Retain missing entries in the editor, so the user can remove them explicitly.
        try { names.addAll(read().packages) } catch (_: RoutingException) { }
        return names.map { name ->
            val label = try { pm.getApplicationLabel(pm.getApplicationInfo(name, 0)).toString() } catch (_: Exception) { L10n.text(context, "Недоступно: {0}", name) }
            mapOf("package" to name, "label" to label)
        }.sortedWith(compareBy({ it["label"]?.lowercase() }, { it["package"] }))
    }
}
