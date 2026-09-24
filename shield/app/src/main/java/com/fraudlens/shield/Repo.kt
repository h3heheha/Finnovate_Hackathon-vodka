package com.fraudlens.shield

import android.content.Context
import android.os.Handler
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.Executors

/** Runs blocking work (network) off the main thread and hands the result back on it. */
object Bg {
    private val pool = Executors.newFixedThreadPool(4)
    val main = Handler(Looper.getMainLooper())

    fun <R> run(work: () -> R, done: (Result<R>) -> Unit) {
        pool.execute {
            val r = runCatching(work)
            main.post { done(r) }
        }
    }

    fun ui(block: () -> Unit) { main.post(block) }
}

/** What went wrong, in words a user can act on. */
fun friendlyError(e: Throwable?): String = when {
    e is HttpException && e.code == 429 -> "Too many checks from this device in a minute. Wait a moment and try again."
    e is HttpException && e.code < 500 -> "The server refused this request (${e.code})."
    e is IOException -> "Can't reach the FraudLens server. Check the server address in Settings."
    else -> "Something went wrong: ${e?.message ?: "unknown error"}"
}

/** Is this an "offline" problem (no connection or server down), as opposed to a refused request? */
fun isOffline(e: Throwable?): Boolean = e is IOException && !(e is HttpException && e.code < 500)

/** One row of History: a message you checked, or a message/call Shield caught. */
class Entry(val data: JSONObject, val fromShield: Boolean) {
    val time: Long = if (fromShield) data.optLong("time") else data.optLong("_time")
    val analysis: JSONObject? = if (fromShield) data.optJSONObject("analysis") else data
    val isCall: Boolean = fromShield && data.optString("kind") == "call"
    val level: String = if (fromShield) data.optString("level", "low") else data.optString("risk_level", "low")
    val score: Int = if (fromShield) data.optInt("score") else data.optInt("risk_score")
    val title: String = when {
        isCall -> data.optString("verdict").ifBlank { "Suspicious caller" }
        else -> analysis?.optString("category_label")?.takeIf { it.isNotBlank() && it != "null" }
            ?: data.optString("verdict", "Message")
    }
    val preview: String = if (fromShield) data.optString("text") else data.optString("_text")
    val source: String = if (fromShield) data.optString("app", "Shield") else "You checked"
}

/**
 * The app's shared data: connection status, content (examples, lessons, quiz, verified contacts),
 * checks and the offline demo fallback. Screens listen for changes with [listen].
 */
object Repo {
    /** true = server reachable, false = offline demo, null = not known yet. */
    var online: Boolean? = null
        private set
    var samples = JSONArray(); private set
    var tactics = JSONArray(); private set
    var quiz = JSONArray(); private set
    var directory = JSONObject(); private set
    var health: JSONObject? = null; private set
    private var demoAnalyses = JSONObject()
    private var loaded = false
    private var lastRefresh = 0L

    fun secondsSinceRefresh(): Long = (System.currentTimeMillis() - lastRefresh) / 1000
    private val listeners = mutableListOf<() -> Unit>()

    fun listen(l: () -> Unit) { listeners.add(l) }
    fun unlisten(l: () -> Unit) { listeners.remove(l) }
    private fun changed() = listeners.toList().forEach { it() }

    /** Loads the last known content (or the bundled demo content) so every screen has something at once. */
    fun init(ctx: Context) {
        if (loaded) return
        loaded = true
        val demo = try {
            JSONObject(ctx.assets.open("demo_cache.json").bufferedReader().use { it.readText() })
        } catch (e: Exception) {
            JSONObject()
        }
        demoAnalyses = demo.optJSONObject("analyses") ?: JSONObject()
        val cached = Prefs(ctx).cachedContent()
        apply(cached ?: demo)
        if (cached != null) {  // fill any gap in an older cache from the bundled content
            if (samples.length() == 0) samples = demo.optJSONArray("samples") ?: JSONArray()
            if (tactics.length() == 0) tactics = demo.optJSONArray("tactics") ?: JSONArray()
            if (quiz.length() == 0) quiz = demo.optJSONArray("quiz") ?: JSONArray()
        }
    }

    private fun apply(c: JSONObject) {
        samples = c.optJSONArray("samples") ?: samples
        tactics = c.optJSONArray("tactics") ?: tactics
        quiz = c.optJSONArray("quiz") ?: quiz
        directory = c.optJSONObject("directory") ?: directory
    }

    fun api(ctx: Context) = ApiClient(Prefs(ctx).serverUrl)

    /** Checks the server and downloads fresh content. `done` gets true when the server answered. */
    fun refresh(ctx: Context, done: ((Boolean) -> Unit)? = null) {
        val app = ctx.applicationContext
        lastRefresh = System.currentTimeMillis()
        Bg.run({
            val api = api(app)
            val h = api.health()
            val content = JSONObject()
            // Content is optional: a failure here must not mark the server as offline.
            runCatching { content.put("samples", api.samples()) }
            runCatching { content.put("tactics", api.tactics()) }
            runCatching { content.put("quiz", api.quiz()) }
            runCatching { content.put("directory", api.directory()) }
            Pair(h, content)
        }) { r ->
            r.onSuccess { (h, content) ->
                health = h
                online = true
                apply(content)
                val merged = JSONObject()
                    .put("samples", samples).put("tactics", tactics).put("quiz", quiz).put("directory", directory)
                Prefs(app).saveContent(merged)
            }.onFailure {
                health = null
                online = false
            }
            changed()
            done?.invoke(online == true)
        }
    }

    /** Result of a check: the analysis, or a friendly error. `offline` = answered from the demo cache. */
    class Check(val analysis: JSONObject?, val offline: Boolean, val error: String?)

    fun analyze(ctx: Context, text: String, sender: String?, channel: String = "sms", done: (Check) -> Unit) {
        val app = ctx.applicationContext
        Bg.run({ api(app).analyze(text, sender, channel) }) { r ->
            val a = r.getOrNull()
            if (a != null) {
                if (online != true) { online = true; changed() }
                done(Check(stamp(a, text, sender), false, null))
                return@run
            }
            val e = r.exceptionOrNull()
            if (isOffline(e)) {
                if (online != false) { online = false; changed() }
                val cached = demoAnalyses.optJSONObject(text.trim())
                if (cached != null) {
                    done(Check(stamp(JSONObject(cached.toString()), text, sender), true, null))
                } else {
                    done(Check(null, true, friendlyError(e) + " The examples still work offline."))
                }
            } else {
                done(Check(null, false, friendlyError(e)))
            }
        }
    }

    /** Adds what the app needs later (the original text, sender and time) to an analysis. */
    private fun stamp(a: JSONObject, text: String, sender: String?): JSONObject =
        a.put("_text", text).put("_sender", sender ?: JSONObject.NULL).put("_time", System.currentTimeMillis())

    fun report(ctx: Context, analysis: JSONObject, label: String, done: (String) -> Unit) {
        val app = ctx.applicationContext
        val prefs = Prefs(app)
        val text = analysis.optString("_text")
        val sender = analysis.optString("_sender").takeIf { it.isNotBlank() && it != "null" }
        val category = analysis.optString("category").takeIf {
            label == "scam" && it.isNotBlank() && it != "none" && it != "null"
        }
        if (text.isBlank()) { done("Nothing to report."); return }
        Bg.run({ api(app).report(text, sender, prefs.deviceId, label, category) }) { r ->
            val res = r.getOrNull()
            val e = r.exceptionOrNull()
            done(when {
                res != null -> res.optString("message").ifBlank { "Thanks for your report." }
                isOffline(e) -> "Reports need a connection to the FraudLens server."
                else -> friendlyError(e)
            })
        }
    }

    // ---- history --------------------------------------------------------------------------------------
    fun timeline(ctx: Context): List<Entry> {
        val p = Prefs(ctx)
        return (p.scans().map { Entry(it, false) } + p.recentAlerts().map { Entry(it, true) })
            .sortedByDescending { it.time }
    }

    fun organisations(): List<JSONObject> {
        val arr = directory.optJSONArray("organisations") ?: return emptyList()
        return (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
    }
}
