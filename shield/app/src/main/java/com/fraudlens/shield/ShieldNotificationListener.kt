package com.fraudlens.shield

import android.app.Notification
import android.content.ComponentName
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
 * between messages. For each SMS / WhatsApp / email notification we:
 *   1. read sender + text from the notification,
 *   2. run the on-phone Prefilter (milliseconds),
 *   3. if suspicious, ask the FraudLens API (off the main thread),
 *   4. warn with a notification (+ overlay banner) when the risk is medium/high.
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
        val prefs = Prefs(this)
        if (!prefs.protectionOn) return
        val pkg = sbn.packageName
        if (pkg == packageName) return
        val channel = Prefilter.MONITORED[pkg] ?: return
        val n = sbn.notification
        if (sbn.isOngoing || (n.flags and Notification.FLAG_GROUP_SUMMARY) != 0) return

        val extras: Bundle = n.extras
        val (sender, text) = extract(extras)
        if (text.isBlank()) return
        if (!Prefilter.isSuspicious(text)) return
        if (Prefilter.isDuplicate(pkg, sender, text)) return

        val app = appLabel(pkg)
        val server = prefs.serverUrl
        worker.execute {
            try {
                val analysis = ApiClient(server).analyze(text, sender, channel)
                val level = analysis.optString("risk_level", "low")
                if (level == "high" || level == "medium") {
                    Alerts.showMessageAlert(this, analysis, text, sender, app)
                }
            } catch (e: Exception) {
                Log.w(TAG, "FraudLens server not reachable: ${e.message}")
            }
        }
    }

    /** Pulls (sender, message) out of SMS, WhatsApp and email notifications. */
    private fun extract(extras: Bundle): Pair<String?, String> {
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()

        // Chat apps (MessagingStyle): take the newest message and its sender
        @Suppress("DEPRECATION")
        val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
        if (messages != null && messages.isNotEmpty()) {
            val last = messages.last() as? Bundle
            val msgText = last?.getCharSequence("text")?.toString()
            val msgSender = last?.getCharSequence("sender")?.toString()
            if (!msgText.isNullOrBlank()) return Pair(msgSender ?: title, msgText)
        }
        // Email apps put "Subject\nPreview" in BIG_TEXT; SMS apps put the message in TEXT
        val body = when {
            !bigText.isNullOrBlank() -> bigText
            !text.isNullOrBlank() -> text
            else -> ""
        }
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
