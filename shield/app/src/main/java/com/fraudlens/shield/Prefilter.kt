package com.fraudlens.shield

/**
 * On-phone filter that runs in milliseconds for EVERY notification.
 * Only messages that pass are sent to the server, so normal chats never leave the phone
 * and battery/data use stays negligible.
 */
object Prefilter {

    /** Apps we watch, mapped to the "channel" the backend understands. */
    val MONITORED: Map<String, String> = mapOf(
        // SMS apps (Google Messages, AOSP/emulator, Samsung, Xiaomi, OnePlus)
        "com.google.android.apps.messaging" to "sms",
        "com.android.messaging" to "sms",
        "com.android.mms" to "sms",
        "com.samsung.android.messaging" to "sms",
        "com.miui.mms" to "sms",
        "com.oneplus.mms" to "sms",
        // Chat apps
        "com.whatsapp" to "whatsapp",
        "com.whatsapp.w4b" to "whatsapp",
        "org.telegram.messenger" to "social",
        "com.facebook.orca" to "social",
        "com.viber.voip" to "social",
        // Email apps (sender + subject + preview come in the notification)
        "com.google.android.gm" to "email",
        "com.microsoft.office.outlook" to "email",
        "com.samsung.android.email.provider" to "email",
        "com.yahoo.mobile.client.android.mail" to "email",
    )

    private val LINK = Regex("""(https?://|www\.)|\b[a-z0-9-]+\.(com|net|org|mu|info|xyz|top|click|live|online|site|ly|link|shop|app|me|co)\b""", RegexOption.IGNORE_CASE)
    private val NUMBER = Regex("""\+?\d[\d \-]{5,}\d""")
    private val MONEY = Regex("""\b(rs\.?|mur|rupees?|usdt|bitcoin|crypto|pay|payment|paid|fee|fees|transfer|send|deposit|refund|invest|account|bank|virement|payez|frais|compte|avoy|kas|larzan|kont)\b|[€£]|\${'$'}""", RegexOption.IGNORE_CASE)
    private val PRESSURE = Regex("""\b(otp|pin|password|passcode|code|verify|confirm|urgent|urgently|immediately|blocked|suspended|locked|won|winner|prize|congratulations|lottery|parcel|customs|new number|lost my phone|bloqu\w*|urgent|gagn\w*|pa dir|vit vit|nouvo nimero)\b""", RegexOption.IGNORE_CASE)

    private val seen = LinkedHashMap<Int, Long>()
    private const val DEDUPE_MS = 10 * 60 * 1000L

    /** True when the message is worth a server check. */
    fun isSuspicious(text: String): Boolean {
        if (text.length < 12) return false
        return LINK.containsMatchIn(text) || MONEY.containsMatchIn(text) ||
            PRESSURE.containsMatchIn(text) || NUMBER.containsMatchIn(text)
    }

    /** Same message re-posted (updates, group summaries, forwards) is only checked once in 10 minutes. */
    @Synchronized
    fun isDuplicate(pkg: String, sender: String?, text: String): Boolean {
        val now = System.currentTimeMillis()
        val it = seen.entries.iterator()
        while (it.hasNext()) if (now - it.next().value > DEDUPE_MS) it.remove()
        val key = (pkg + "|" + (sender ?: "") + "|" + text).hashCode()
        if (seen.containsKey(key)) return true
        seen[key] = now
        return false
    }
}
