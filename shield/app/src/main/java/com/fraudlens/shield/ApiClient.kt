package com.fraudlens.shield

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** The server answered with an error status (4xx/5xx). 429 means "too many requests from this device". */
class HttpException(val code: Int, message: String) : IOException(message)

/**
 * Talks to the FraudLens FastAPI backend. Blocking calls: always run them off the main thread (see Bg).
 * Only the message being checked (or the caller's number) is sent; the server redacts personal data.
 * Network problems throw IOException; error statuses throw HttpException (a subclass).
 */
class ApiClient(baseUrl: String) {
    private val base = baseUrl.trim().trimEnd('/')

    fun analyze(text: String, sender: String?, channel: String): JSONObject {
        val body = JSONObject()
            .put("text", text.take(5000))
            .put("channel", channel)
            .put("sender", sender?.trim()?.take(120)?.ifEmpty { null } ?: JSONObject.NULL)
        return JSONObject(request("POST", "/api/v1/analyze", body))
    }

    fun checkPhone(number: String): JSONObject =
        JSONObject(request("GET", "/api/v1/intel/phone?number=" + URLEncoder.encode(number, "UTF-8"), null))

    fun report(text: String, sender: String?, deviceId: String, label: String = "scam",
               category: String? = null): JSONObject {
        val body = JSONObject()
            .put("text", text.take(5000))
            .put("label", label)
            .put("reporter_id", deviceId)
            .put("sender", sender?.trim()?.take(120)?.ifEmpty { null } ?: JSONObject.NULL)
            .put("category", category ?: JSONObject.NULL)
        return JSONObject(request("POST", "/api/v1/report", body))
    }

    fun health(): JSONObject = JSONObject(request("GET", "/health", null))
    fun samples(): JSONArray = JSONArray(request("GET", "/api/v1/samples", null))
    fun tactics(): JSONArray = JSONArray(request("GET", "/api/v1/learn/tactics", null))
    fun quiz(): JSONArray = JSONArray(request("GET", "/api/v1/learn/quiz", null))
    fun directory(): JSONObject = JSONObject(request("GET", "/api/v1/directory", null))

    private fun request(method: String, path: String, body: JSONObject?): String {
        val conn = URL(base + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 4000
            conn.readTimeout = 10000
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
            if (code !in 200..299) throw HttpException(code, "Server error $code: ${text.take(200)}")
            return text
        } finally {
            conn.disconnect()
        }
    }
}
