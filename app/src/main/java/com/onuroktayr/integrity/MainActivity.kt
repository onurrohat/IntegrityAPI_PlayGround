package com.onuroktayr.integrity

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityToken
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom

/**
 * Play Integrity API - basic test screen for the Standard API.
 *
 * Flow:
 *  1) prepareIntegrityToken() - warms up the tokenProvider as soon as the app opens (or on button tap).
 *  2) provider.request() - requests the actual integrity token, returns with very low latency.
 *  3) The raw token received is meaningless as a "verdict" until it's sent server-side to Google's
 *     decodeIntegrityToken REST endpoint and decoded - see scripts/decode-token.ps1
 */
class MainActivity : AppCompatActivity() {

    private val tag = "IntegrityTest"

    // Production verification server on Google Cloud Run (always-on, fixed URL, independent of any local machine).
    // For local development against the server running on this machine use "http://10.0.2.2:8787" (emulator).
    private val serverBaseUrl = "https://integrity-server-271397153895.europe-west1.run.app"
    private val challengeServerUrl = "$serverBaseUrl/challenge"
    private val verifyServerUrl = "$serverBaseUrl/verify"

    private lateinit var tvStatus: TextView
    private lateinit var tvLog: TextView
    private lateinit var btnPrepare: Button
    private lateinit var btnRequest: Button
    private lateinit var btnCopy: Button
    private lateinit var btnLogin: Button
    private lateinit var btnAttestation: Button

    private lateinit var standardIntegrityManager: StandardIntegrityManager
    private var tokenProvider: StandardIntegrityTokenProvider? = null
    private var lastToken: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tvStatus)
        tvLog = findViewById(R.id.tvLog)
        btnPrepare = findViewById(R.id.btnPrepare)
        btnRequest = findViewById(R.id.btnRequest)
        btnCopy = findViewById(R.id.btnCopy)
        btnLogin = findViewById(R.id.btnLogin)
        btnAttestation = findViewById(R.id.btnAttestation)

        standardIntegrityManager = IntegrityManagerFactory.createStandard(applicationContext)

        val cloudProjectNumber = BuildConfig.CLOUD_PROJECT_NUMBER
        val warning = if (cloudProjectNumber == 0L) {
            "\n\nWARNING: cloudProjectNumber is not set.\n" +
                "Add integrity.cloudProjectNumber=<your-number> to local.properties\n" +
                "and Sync the project."
        } else {
            ""
        }
        tvStatus.text = "Package: $packageName\nCloud project number: $cloudProjectNumber$warning"

        btnRequest.isEnabled = false
        btnCopy.isEnabled = false

        btnPrepare.setOnClickListener { prepareToken(cloudProjectNumber) }
        btnRequest.setOnClickListener { requestToken() }
        btnCopy.setOnClickListener { copyTokenToClipboard() }
        btnLogin.setOnClickListener { loginWithIntegrity(cloudProjectNumber) }
        btnAttestation.setOnClickListener { startActivity(Intent(this, AttestationActivity::class.java)) }
    }

    /**
     * A real "login protected by Integrity" flow: fetches a one-time requestHash from the
     * backend's /challenge endpoint, produces a fresh token bound to that hash via
     * prepare + request, then sends the token to /verify. The decision (allowed or not) is
     * made ONLY on the backend - the client just reads the result and changes screens accordingly,
     * it never declares "I'm safe" on its own.
     *
     * The requestHash comes from the server (not randomRequestHash()) so the backend can confirm
     * the decoded token's requestDetails.requestHash matches a hash IT issued and hasn't already
     * consumed - that's what makes /verify's replay check meaningful.
     */
    private fun loginWithIntegrity(cloudProjectNumber: Long) {
        if (cloudProjectNumber == 0L) {
            log("ERROR: cloudProjectNumber = 0. Edit local.properties and Sync.")
            return
        }

        btnLogin.isEnabled = false
        log("Login flow started: challenge -> prepare -> request -> /verify")

        Thread {
            val requestHash = try {
                fetchChallenge()
            } catch (e: Exception) {
                runOnUiThread {
                    btnLogin.isEnabled = true
                    log("Login failed (challenge): ${e.message}")
                }
                return@Thread
            }

            runOnUiThread {
                val request = PrepareIntegrityTokenRequest.builder()
                    .setCloudProjectNumber(cloudProjectNumber)
                    .build()

                standardIntegrityManager.prepareIntegrityToken(request)
                    .addOnSuccessListener { provider ->
                        val tokenRequest = StandardIntegrityTokenRequest.builder()
                            .setRequestHash(requestHash)
                            .build()

                        provider.request(tokenRequest)
                            .addOnSuccessListener { response: StandardIntegrityToken ->
                                verifyWithServer(response.token())
                            }
                            .addOnFailureListener { exception ->
                                btnLogin.isEnabled = true
                                log("Login failed (request): ${describe(exception)}")
                            }
                    }
                    .addOnFailureListener { exception ->
                        btnLogin.isEnabled = true
                        log("Login failed (prepare): ${describe(exception)}")
                    }
            }
        }.start()
    }

    /** Blocking GET to /challenge - must be called off the main thread. */
    private fun fetchChallenge(): String {
        val connection = URL(challengeServerUrl).openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000

        val statusCode = connection.responseCode
        val stream = if (statusCode in 200..299) connection.inputStream else connection.errorStream
        val responseText = stream.bufferedReader().use { it.readText() }
        if (statusCode !in 200..299) {
            throw Exception("GET /challenge -> HTTP $statusCode: $responseText")
        }
        return JSONObject(responseText).getString("requestHash")
    }

    private fun verifyWithServer(token: String) {
        Thread {
            try {
                val connection = URL(verifyServerUrl).openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.connectTimeout = 10_000
                connection.readTimeout = 10_000

                val body = JSONObject().put("token", token).toString()
                connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

                val statusCode = connection.responseCode
                val stream = if (statusCode in 200..299) connection.inputStream else connection.errorStream
                val responseText = stream.bufferedReader().use { it.readText() }
                val json = JSONObject(responseText)
                val allowed = json.optBoolean("allowed", false)

                runOnUiThread {
                    btnLogin.isEnabled = true
                    log("/verify -> HTTP $statusCode, allowed=$allowed")
                    if (allowed) {
                        log("Login successful, opening the security dashboard.")
                        val verdict = json.optJSONObject("verdict")?.toString() ?: "{}"
                        val dashboardIntent = Intent(this, SecureDashboardActivity::class.java)
                            .putExtra(SecureDashboardActivity.EXTRA_VERDICT_JSON, verdict)
                            .putExtra(SecureDashboardActivity.EXTRA_RISK_LEVEL, json.optString("riskLevel"))
                            .putExtra(SecureDashboardActivity.EXTRA_TIERS_JSON, json.optJSONObject("tiers")?.toString() ?: "{}")
                            .putExtra(SecureDashboardActivity.EXTRA_REASONS_JSON, json.optJSONArray("reasons")?.toString() ?: "[]")
                        startActivity(dashboardIntent)
                    } else {
                        val reasons = json.optJSONArray("reasons")?.toString() ?: "-"
                        log("Login denied: $reasons")
                        Toast.makeText(this, "Login denied: device does not meet security requirements", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    btnLogin.isEnabled = true
                    log("/verify call failed: ${e.message}")
                }
            }
        }.start()
    }

    private fun log(message: String) {
        Log.d(tag, message)
        runOnUiThread { tvLog.append("\n$message") }
    }

    private fun prepareToken(cloudProjectNumber: Long) {
        if (cloudProjectNumber == 0L) {
            log("ERROR: cloudProjectNumber = 0. Edit local.properties and Sync.")
            return
        }

        log("Calling prepareIntegrityToken()...")
        btnPrepare.isEnabled = false

        val request = PrepareIntegrityTokenRequest.builder()
            .setCloudProjectNumber(cloudProjectNumber)
            .build()

        standardIntegrityManager.prepareIntegrityToken(request)
            .addOnSuccessListener { provider ->
                tokenProvider = provider
                btnPrepare.isEnabled = true
                btnRequest.isEnabled = true
                log("Ready (prepared). You can request a token now.")
            }
            .addOnFailureListener { exception ->
                btnPrepare.isEnabled = true
                log("prepare failed: ${describe(exception)}")
            }
    }

    private fun requestToken() {
        val provider = tokenProvider
        if (provider == null) {
            log("Tap 'Prepare' first.")
            return
        }

        val requestHash = randomRequestHash()
        log("Calling request()... requestHash=$requestHash")
        btnRequest.isEnabled = false

        val request = StandardIntegrityTokenRequest.builder()
            .setRequestHash(requestHash)
            .build()

        provider.request(request)
            .addOnSuccessListener { response: StandardIntegrityToken ->
                btnRequest.isEnabled = true
                lastToken = response.token()
                btnCopy.isEnabled = true
                log("Token received (${lastToken?.length ?: 0} characters):")
                log(lastToken ?: "")
            }
            .addOnFailureListener { exception ->
                btnRequest.isEnabled = true
                log("request failed: ${describe(exception)}")
            }
    }

    private fun describe(exception: Exception): String {
        val code = (exception as? StandardIntegrityException)?.errorCode
        return if (code != null) "${exception.message} (errorCode=$code)" else exception.message ?: exception.toString()
    }

    private fun randomRequestHash(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    private fun copyTokenToClipboard() {
        val token = lastToken ?: return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("integrity_token", token))
        Toast.makeText(this, "Token copied to clipboard", Toast.LENGTH_SHORT).show()
    }
}
