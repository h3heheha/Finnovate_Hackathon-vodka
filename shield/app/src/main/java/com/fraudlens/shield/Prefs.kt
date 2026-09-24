package com.fraudlens.shield

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** Small settings store + the list of recent alerts (kept on the phone only). */
class Prefs(context: Context) {
    private val sp: SharedPreferences =
        context.applicationContext.getSharedPreferences("fraudlens_shield", Context.MODE_PRIVATE)

    /** Emulator -> laptop is 10.0.2.2. On a real phone use the laptop's Wi-Fi IP, e.g. http://192.168.1.20:8000 */
    var serverUrl: String
        get() = sp.getString("server_url", DEFAULT_SERVER) ?: DEFAULT_SERVER
        set(v) = sp.edit().putString("server_url", v.trim().trimEnd('/')).apply()

    var protectionOn: Boolean
        get() = sp.getBoolean("protection_on", true)
        set(v) = sp.edit().putBoolean("protection_on", v).apply()

    var callCheckOn: Boolean
        get() = sp.getBoolean("call_check_on", true)
        set(v) = sp.edit().putBoolean("call_check_on", v).apply()

    /** Anonymous id so the server can count independent reporters (anti-poisoning). */
    val deviceId: String
        get() {
            val existing = sp.getString("device_id", null)
            if (existing != null) return existing
            val id = "shield-" + UUID.randomUUID().toString().take(12)
            sp.edit().putString("device_id", id).apply()
            return id
        }

    fun recentAlerts(): List<JSONObject> {
        val arr = JSONArray(sp.getString("alerts", "[]") ?: "[]")
        return (0 until arr.length()).map { arr.getJSONObject(it) }
    }

    fun addAlert(alert: JSONObject) {
        val list = mutableListOf(alert)
        list.addAll(recentAlerts().take(MAX_ALERTS - 1))
        val arr = JSONArray()
        list.forEach { arr.put(it) }
        sp.edit().putString("alerts", arr.toString()).apply()
    }

    fun clearAlerts() = sp.edit().putString("alerts", "[]").apply()

    companion object {
        const val DEFAULT_SERVER = "http://10.0.2.2:8000"
        const val MAX_ALERTS = 20
    }
}
