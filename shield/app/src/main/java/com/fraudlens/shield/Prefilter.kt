package com.fraudlens.shield

import android.app.Notification
import java.text.Normalizer

/**
 * On-phone filter that runs in milliseconds for every message notification.
 * Only messages that pass are sent to the server, so ordinary chats never leave the phone.
 * It is deliberately generous (English, French and Kreol Morisien): the server makes the real decision.
 */
object Prefilter {

    /** Apps we watch, mapped to the "channel" the backend understands. */
    val MONITORED: Map<String, String> = mapOf(
        // SMS apps (Google, AOSP/emulator, Samsung, Xiaomi, OnePlus, Huawei, Honor, Oppo/Realme, Vivo, Motorola, Textra, Truecaller)
        "com.google.android.apps.messaging" to "sms",
        "com.android.messaging" to "sms",
        "com.android.mms" to "sms",
        "com.samsung.android.messaging" to "sms",
        "com.miui.mms" to "sms",
        "com.oneplus.mms" to "sms",
        "com.huawei.message" to "sms",
        "com.hihonor.mms" to "sms",
        "com.coloros.mms" to "sms",
        "com.oplus.mms" to "sms",
        "com.vivo.mms" to "sms",
        "com.motorola.messaging" to "sms",
        "com.textra" to "sms",
        "com.truecaller" to "sms",
        // Chat apps
        "com.whatsapp" to "whatsapp",
        "com.whatsapp.w4b" to "whatsapp",
        "org.telegram.messenger" to "social",
        "org.telegram.messenger.web" to "social",
        "com.facebook.orca" to "social",
        "com.facebook.mlite" to "social",
        "com.instagram.android" to "social",
        "com.viber.voip" to "social",
        "org.thoughtcrime.securesms" to "social",
        // Email apps (sender + subject + preview come in the notification)
        "com.google.android.gm" to "email",
        "com.google.android.gm.lite" to "email",
        "com.microsoft.office.outlook" to "email",
        "com.samsung.android.email.provider" to "email",
        "com.yahoo.mobile.client.android.mail" to "email",
        "com.android.email" to "email",
        "ch.protonmail.android" to "email",
        "com.readdle.spark" to "email",
        "com.my.mail" to "email",
    )

    /**
     * The channel for a notification, or null if Shield ignores that app. Apps that aren't listed still
     * count when Android marks the notification as a message or an email (other phone brands' SMS apps).
     */
    fun channelFor(pkg: String, category: String?): String? = MONITORED[pkg] ?: when (category) {
        Notification.CATEGORY_EMAIL -> "email"
        Notification.CATEGORY_MESSAGE -> if (pkg.contains("mms") || pkg.contains("sms") || pkg.contains("messag")) "sms" else "social"
        else -> null
    }

    private val LINK = Regex("""(https?://|www\.)|\b[a-z0-9-]+\.(com|net|org|mu|info|xyz|top|click|live|online|site|ly|link|shop|app|me|co|io|ru|cn|tk|ml|ga|cf|gq|buzz|icu|vip|club|store|win|bid|cc|gl|gd)\b""")
    private val PHONE = Regex("""\+?\d[\d \-]{5,}\d""")
    private val AMOUNT = Regex("""\b\d{1,3}(?:[ ,.]\d{3})+\b|\b\d{3,}\b|[€£$₹]""")

    // Word starts (accents removed, lower case). Short words that must match whole are in WORDS below.
    private val STEMS = listOf(
        // English
        "password", "passcode", "verif", "confirm", "urgent", "immediately", "block", "suspend", "locked", "expire",
        "update", "winner", "prize", "gift", "reward", "congrat", "lottery", "claim", "parcel", "package", "deliver",
        "customs", "payment", "pay ", "paid", "transfer", "send", "deposit", "refund", "invest", "profit", "crypto",
        "bitcoin", "usdt", "account", "bank", "card", "loan", "click", "link", "login", "log in", "new number",
        "lost my phone", "help me", "secret", "don't tell", "dont tell", "earn", "money", "cash", "code",
        // French
        "compte", "carte", "bancaire", "banque", "mot de passe", "virement", "paiement", "payer", "payez", "frais",
        "colis", "douane", "livraison", "gagne", "felicit", "cadeau", "recompense", "immediat", "suspendu", "bloque",
        "mise a jour", "mettez a jour", "mettre a jour", "cliquez", "cliquer", "rembours", "investi", "roupie",
        "argent", "envoy", "maman", "papa", "numero", "ne dites", "abonnement", "selectionne", "reclam", "gratuit",
        "offre", "urgence",
        // Kreol Morisien
        "avoy", "larzan", "labank", "bloke", "debloke", "vit vit", "zordi", "gagn", "kado", "felisitasion",
        "nimero", "telefonn", "portab", "klik", "peye", "verifye", "konfirm", "urzan", "pa dir", "roupi", "prete",
        "problem", "traka", "detay", "juice", "my.t", "blink", "lotri", "tiraz", "garson", "tifi",
    )
    private val WORDS = listOf(
        "otp", "pin", "won", "win", "fee", "fees", "rs", "mur", "usd", "eur", "free", "job", "pret", "lien", "prix",
        "kas", "kod", "kart", "kont", "voy", "fre", "led", "mum", "mom", "dad", "mama",
    )
    private val KEYWORDS = Regex(
        "(?:^|[^a-z0-9])(?:" + STEMS.joinToString("|") { Regex.escape(it) } + ")" +
            "|\\b(?:" + WORDS.joinToString("|") + ")\\b"
    )

    private val seen = LinkedHashMap<Int, Long>()
    private const val DEDUPE_MS = 10 * 60 * 1000L

    /** Lower case without accents, so "bloqué", "BLOQUE" and "bloque" all match. */
    fun normalise(text: String): String =
        Normalizer.normalize(text, Normalizer.Form.NFD).replace(Regex("\\p{Mn}+"), "").lowercase()

    /** True when the message is worth a server check. */
    fun isSuspicious(text: String): Boolean {
        if (text.trim().length < 12) return false
        val t = normalise(text)
        return LINK.containsMatchIn(t) || PHONE.containsMatchIn(t) || AMOUNT.containsMatchIn(t) ||
            KEYWORDS.containsMatchIn(t)
    }

    /** Same message re-posted (updates, group summaries, forwards) is only checked once in 10 minutes. */
    @Synchronized
    fun isDuplicate(pkg: String, sender: String?, text: String): Boolean {
        val now = System.currentTimeMillis()
        val it = seen.entries.iterator()
        while (it.hasNext()) if (now - it.next().value > DEDUPE_MS) it.remove()
        val key = (pkg + "|" + normalise(text).trim()).hashCode()   // sender left out: summaries use other titles
        if (seen.containsKey(key)) return true
        seen[key] = now
        return false
    }
}
