package com.fraudlens.shield

import android.app.Notification
import android.app.Person
import android.content.ComponentName
import android.os.Build
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The heart of Shield, the background protection inside the FraudLens app.
 *
 * Android wakes this service ONLY when a notification is posted; nothing runs in the background
 * between messages. For each SMS / WhatsApp / email / chat notification we:
 *   1. read sender + text from the notification,
 *   2. run the on-phone Prefilter (milliseconds, English, French and Kreol),
 *   3. if suspicious, ask the FraudLens API (off the main thread),
 *   4. warn with a notification (+ overlay banner) when the risk is medium/high.
 * Each step is written to Shield's log (Shield tab → "What Shield saw"), on the phone only.
 */
class ShieldNotificationListener : NotificationListenerService() {

    private val worker: ExecutorService = Executors.newSingleThreadExecutor()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        try {
            handle(sbn)
        } catch (e: Exception) {
            Log.w(TAG, "Could not read notification", e)
        }
    }

    private fun handle(sbn: StatusBarNotification) {
        val pkg = sbn.packageName
        if (pkg == packageName) return
        val n = sbn.notification
        val channel = Prefilter.channelFor(pkg, n.category) ?: return
        if (sbn.isOngoing || (n.flags and Notification.FLAG_GROUP_SUMMARY) != 0) return

        val prefs = Prefs(this)
        val app = appLabel(pkg)
        if (!prefs.protectionOn) {
            prefs.log(app, "Paused", "Protection is off, so nothing was checked.")
            return
        }
        val (sender, text) = extract(n.extras)
        if (text.isBlank()) {
            prefs.log(app, "Skipped", "The notification had no message text (is \"hide content\" on in that app?).")
            return
        }
        if (!prefs.checkEverything && !Prefilter.isSuspicious(text)) {
            prefs.log(app, "Skipped", "Ordinary message: stayed on the phone.")
            return
        }
        if (Prefilter.isDuplicate(pkg, sender, text)) return

        val preview = text.replace('\n', ' ').take(50)
        val server = prefs.serverUrl
        worker.execute {
            try {
                val analysis = ApiClient(server).analyze(text, sender, channel)
                val level = analysis.optString("risk_level", "low")
                val score = analysis.optInt("risk_score")
                if (level == "high" || level == "medium") {
                    Alerts.showMessageAlert(this, analysis, text, sender, app)
                    prefs.log(app, "Warned", "$score/100 · \"$preview\"")
                } else {
                    prefs.log(app, "Checked", "$score/100, looks safe · \"$preview\"")
                }
            } catch (e: HttpException) {
                prefs.log(app, "Error", if (e.code == 429) "Too many checks in a minute: wait, then try again."
                                         else "Server error ${e.code}.")
            } catch (e: Exception) {
                prefs.log(app, "Error", "Can't reach the FraudLens server at $server.")
                Log.w(TAG, "FraudLens server not reachable: ${e.message}")
            }
        }
    }

    /** Pulls (sender, message) out of SMS, WhatsApp, email and chat notifications. */
    private fun extract(extras: Bundle): Pair<String?, String> {
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        val lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)

        // Chat apps (MessagingStyle, e.g. WhatsApp, Messages): take the newest message and its sender.
        try {
            @Suppress("DEPRECATION")
            val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
            if (messages != null && messages.isNotEmpty()) {
                val last = messages.last() as? Bundle
                val msgText = last?.getCharSequence("text")?.toString()
                var msgSender = last?.getCharSequence("sender")?.toString()
                if (msgSender == null && last != null && Build.VERSION.SDK_INT >= 28) {
                    last.classLoader = Person::class.java.classLoader
                    @Suppress("DEPRECATION")
                    msgSender = (last.getParcelable<Person>("sender_person"))?.name?.toString()
                }
                if (!msgText.isNullOrBlank()) return Pair(msgSender ?: title, msgText)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Couldn't read chat messages: ${e.message}")
        }
        // Email apps put "Subject\nPreview" in BIG_TEXT; SMS apps put the message in TEXT; inbox style uses lines.
        val body = listOfNotNull(bigText, text, lines?.lastOrNull()?.toString())
            .filter { it.isNotBlank() }
            .maxByOrNull { it.length } ?: ""
        return Pair(title, body)
    }

    private fun appLabel(pkg: String): String = try {
        val info = packageManager.getApplicationInfo(pkg, 0)
        packageManager.getApplicationLabel(info).toString()
    } catch (e: Exception) {
        pkg
    }

    override fun onListenerConnected() {
        Log.i(TAG, "Shield connected: listening for notifications")
        Alerts.ensureChannels(this)
    }

    override fun onListenerDisconnected() {
        // Some phones unbind listeners to save battery: ask Android to reconnect us.
        requestRebind(ComponentName(this, ShieldNotificationListener::class.java))
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "FraudLensShield"
    }
}
