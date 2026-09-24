package com.fraudlens.shield

import android.os.Build
import android.telecom.Call
import android.telecom.CallScreeningService
import android.util.Log
import android.annotation.TargetApi
import java.util.concurrent.Executors

/**
 * Checks the caller's number while the phone is ringing (Android 10+).
 * Android only wakes this service during an incoming call from a number that isn't in your contacts; it
 * needs the "Caller ID & spam" role, NOT the READ_CALL_LOG permission. We never block the call.
 * Most unknown callers are genuine, so we only warn on real evidence (see Alerts.callWorthWarning).
 */
@TargetApi(Build.VERSION_CODES.Q)
class ShieldCallScreeningService : CallScreeningService() {

    private val worker = Executors.newSingleThreadExecutor()

    override fun onScreenCall(callDetails: Call.Details) {
        // 1) Answer Android immediately: let the call through untouched (must reply within ~5 s).
        respondToCall(callDetails, CallScreeningService.CallResponse.Builder().build())

        if (callDetails.callDirection != Call.Details.DIRECTION_INCOMING) return
        val prefs = Prefs(this)
        if (!prefs.protectionOn || !prefs.callCheckOn) return
        val number = callDetails.handle?.schemeSpecificPart ?: return
        val server = prefs.serverUrl

        // 2) Check the number in the background and warn while it is still ringing.
        worker.execute {
            try {
                val result = ApiClient(server).checkPhone(number)
                if (Alerts.callWorthWarning(result)) {
                    Alerts.showCallAlert(this, number, result)
                    prefs.log("Phone call", "Warned", "$number · ${result.optString("headline")}")
                } else {
                    prefs.log("Phone call", "Checked", "$number · no warning signs")
                }
            } catch (e: Exception) {
                prefs.log("Phone call", "Error", "Can't reach the FraudLens server at $server.")
                Log.w("FraudLensShield", "Call check failed: ${e.message}")
            }
        }
    }
}
