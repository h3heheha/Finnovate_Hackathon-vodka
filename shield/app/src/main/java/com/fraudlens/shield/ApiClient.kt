package com.fraudlens.shield

import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Talks to the FraudLens FastAPI backend. Blocking calls: always run them off the main thread.
 * Only the suspicious message (or the caller's number) is sent; the server redacts personal data.
 */
class ApiClient(private val baseUrl: String) {

    fun analyze(text: String, sender: String?, channel: String): JSONObject {
        val body = JSONObject()
            .put("text", text.take(5000))
            .put("channel", channel)
            .put("sender", sender?.take(120) ?: JSONObject.NULL)
        return request("POST", "/api/v1/analyze", body)
    }

    fun checkPhone(number: String): JSONObject =
        request("GET", "/api/v1/intel/phone?number=" + URLEncoder.encode(number, "UTF-8"), null)

    fun report(text: String, sender: String?, deviceId: String, label: String = "scam"): JSONObject {
        val body = JSONObject()
            .put("text", text.take(5000))
            .put("label", label)
            .put("reporter_id", deviceId)
            .put("sender", sender?.take(120) ?: JSONObject.NULL)
        return request("POST", "/api/v1/report", body)
    }

    fun health(): JSONObject = request("GET", "/health", null)

    private fun request(method: String, path: String, body: JSONObject?): JSONObject {
        val conn = URL(baseUrl + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 4000
            conn.readTimeout = 8000
            conn.setRequestProperty("Accept", "application/json")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.let { s ->
                BufferedReader(InputStreamReader(s, Charsets.UTF_8)).use { it.readText() }
            } ?: ""
            if (code !in 200..299) throw RuntimeException("Server error $code: ${text.take(200)}")
            return JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }
}
