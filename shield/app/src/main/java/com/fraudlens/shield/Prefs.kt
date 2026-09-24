package com.fraudlens.shield

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Everything the app keeps on the phone: settings, your checks, Shield's alerts and the last content
 * downloaded from the server (so examples, lessons and the quiz also work offline).
 */
class Prefs(context: Context) {
    private val sp: SharedPreferences =
        context.applicationContext.getSharedPreferences("fraudlens_shield", Context.MODE_PRIVATE)

    /** Emulator -> laptop is 10.0.2.2. On a real phone use the laptop's Wi-Fi IP, e.g. http://192.168.1.20:8000 */
    var serverUrl: String
        get() = sp.getString("server_url", DEFAULT_SERVER) ?: DEFAULT_SERVER
        set(v) = sp.edit().putString("server_url", normaliseUrl(v)).apply()

    var protectionOn: Boolean
        get() = sp.getBoolean("protection_on", true)
        set(v) = sp.edit().putBoolean("protection_on", v).apply()

    var callCheckOn: Boolean
        get() = sp.getBoolean("call_check_on", true)
        set(v) = sp.edit().putBoolean("call_check_on", v).apply()

    /** Trusted person for "Ask someone you trust" (set in Settings). */
    var guardianName: String
        get() = sp.getString("guardian_name", "") ?: ""
        set(v) = sp.edit().putString("guardian_name", v.trim().take(60)).apply()

    var guardianPhone: String
        get() = sp.getString("guardian_phone", "") ?: ""
        set(v) = sp.edit().putString("guardian_phone", v.trim().take(30)).apply()

    /** Whether the Android 13+ notification permission was requested before (to know when to open Settings). */
    var askedNotifications: Boolean
        get() = sp.getBoolean("asked_notifications", false)
        set(v) = sp.edit().putBoolean("asked_notifications", v).apply()

    /** Anonymous id so the server can count independent reporters (anti-poisoning). */
    val deviceId: String
        get() {
            val existing = sp.getString("device_id", null)
            if (existing != null) return existing
            val id = "shield-" + UUID.randomUUID().toString().take(12)
            sp.edit().putString("device_id", id).apply()
            return id
        }

    // ---- Shield alerts ---------------------------------------------------------------------------------
    fun recentAlerts(): List<JSONObject> = readList("alerts")

    fun addAlert(alert: JSONObject) = prepend("alerts", alert, MAX_ALERTS)

    fun clearAlerts() = sp.edit().putString("alerts", "[]").apply()

    // ---- your own checks (Scan tab) -------------------------------------------------------------------
    fun scans(): List<JSONObject> = readList("scans")

    /** Saves a check, newest first; the same analysis is never listed twice. */
    fun addScan(analysis: JSONObject) {
        val id = analysis.optString("analysis_id")
        val rest = scans().filter { id.isEmpty() || it.optString("analysis_id") != id }
        val arr = JSONArray().put(analysis)
        rest.take(MAX_SCANS - 1).forEach { arr.put(it) }
        sp.edit().putString("scans", arr.toString()).apply()
    }

    fun clearHistory() = sp.edit().putString("scans", "[]").putString("alerts", "[]").apply()

    // ---- content cache ----------------------------------------------------------------------------------
    fun cachedContent(): JSONObject? = sp.getString("content_cache", null)?.let {
        try { JSONObject(it) } catch (e: Exception) { null }
    }

    fun saveContent(content: JSONObject) = sp.edit().putString("content_cache", content.toString()).apply()

    // ---- helpers --------------------------------------------------------------------------------------------
    private fun readList(key: String): List<JSONObject> {
        val raw = sp.getString(key, "[]") ?: "[]"
        synchronized(parsed) {
            parsed[key]?.let { (src, list) -> if (src == raw) return list }  // unchanged: skip re-parsing
        }
        val list = try {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
        } catch (e: Exception) {
            emptyList()
        }
        synchronized(parsed) { parsed[key] = raw to list }
        return list
    }

    private fun prepend(key: String, item: JSONObject, max: Int) {
        val arr = JSONArray().put(item)
        readList(key).take(max - 1).forEach { arr.put(it) }
        sp.edit().putString(key, arr.toString()).apply()
    }

    companion object {
        /** Parsed history lists, reused while the stored text is unchanged (History is drawn often). */
        private val parsed = HashMap<String, Pair<String, List<JSONObject>>>()

        const val DEFAULT_SERVER = "http://10.0.2.2:8000"
        const val MAX_ALERTS = 30
        const val MAX_SCANS = 30

        /** Accepts "192.168.1.5:8000" or "http://192.168.1.5:8000/" and returns "http://192.168.1.5:8000". */
        fun normaliseUrl(v: String): String {
            var u = v.trim().trimEnd('/')
            if (u.isNotEmpty() && !u.startsWith("http://") && !u.startsWith("https://")) u = "http://$u"
            return u
        }
    }
}
