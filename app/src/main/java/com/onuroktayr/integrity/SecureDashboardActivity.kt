package com.onuroktayr.integrity

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject

/**
 * The "protected" screen shown after login. Shows the real Play Integrity verdict
 * (app/device/account/environment) returned by the backend's /verify call as text, and
 * colors each card using the backend's risk tiers - the client never re-evaluates the
 * verdict itself, so what's on screen always matches the decision /verify made.
 */
class SecureDashboardActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_VERDICT_JSON = "verdict_json"
        const val EXTRA_RISK_LEVEL = "risk_level"
        const val EXTRA_TIERS_JSON = "tiers_json"
        const val EXTRA_REASONS_JSON = "reasons_json"
    }

    private lateinit var cardBanner: CardView
    private lateinit var tvBannerIcon: TextView
    private lateinit var tvBannerTitle: TextView
    private lateinit var tvBannerSubtitle: TextView

    private lateinit var tvAppValue: TextView
    private lateinit var tvAppChip: TextView
    private lateinit var tvDeviceValue: TextView
    private lateinit var tvDeviceChip: TextView
    private lateinit var tvAccountValue: TextView
    private lateinit var tvAccountChip: TextView

    private lateinit var tvEnvValue: TextView
    private lateinit var tvEnvChip: TextView

    private lateinit var tvToggleJson: TextView
    private lateinit var tvRawJson: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_secure_dashboard)

        cardBanner = findViewById(R.id.cardBanner)
        tvBannerIcon = findViewById(R.id.tvBannerIcon)
        tvBannerTitle = findViewById(R.id.tvBannerTitle)
        tvBannerSubtitle = findViewById(R.id.tvBannerSubtitle)

        tvAppValue = findViewById(R.id.tvAppValue)
        tvAppChip = findViewById(R.id.tvAppChip)
        tvDeviceValue = findViewById(R.id.tvDeviceValue)
        tvDeviceChip = findViewById(R.id.tvDeviceChip)
        tvAccountValue = findViewById(R.id.tvAccountValue)
        tvAccountChip = findViewById(R.id.tvAccountChip)

        tvEnvValue = findViewById(R.id.tvEnvValue)
        tvEnvChip = findViewById(R.id.tvEnvChip)

        tvToggleJson = findViewById(R.id.tvToggleJson)
        tvRawJson = findViewById(R.id.tvRawJson)

        val rawJson = intent.getStringExtra(EXTRA_VERDICT_JSON)
        if (rawJson != null) {
            val riskLevel = intent.getStringExtra(EXTRA_RISK_LEVEL).orEmpty()
            val tiers = JSONObject(intent.getStringExtra(EXTRA_TIERS_JSON) ?: "{}")
            val reasons = JSONArray(intent.getStringExtra(EXTRA_REASONS_JSON) ?: "[]")
            renderVerdict(JSONObject(rawJson), riskLevel, tiers, reasons)
            tvRawJson.text = JSONObject(rawJson).toString(2)
        }

        tvToggleJson.setOnClickListener {
            val showing = tvRawJson.visibility == android.view.View.VISIBLE
            tvRawJson.visibility = if (showing) android.view.View.GONE else android.view.View.VISIBLE
            tvToggleJson.text = if (showing) "Technical details (raw JSON) ▾" else "Technical details (raw JSON) ▴"
        }

        findViewById<Button>(R.id.btnReverify).setOnClickListener { finish() }
        findViewById<Button>(R.id.btnLogout).setOnClickListener { finish() }
        findViewById<Button>(R.id.btnCompareAttestation).setOnClickListener {
            startActivity(
                Intent(this, ComparisonActivity::class.java)
                    .putExtra(ComparisonActivity.EXTRA_VERDICT_JSON, rawJson)
                    .putExtra(ComparisonActivity.EXTRA_TIERS_JSON, intent.getStringExtra(EXTRA_TIERS_JSON))
            )
        }
    }

    private fun renderVerdict(verdict: JSONObject, riskLevel: String, tiers: JSONObject, reasons: JSONArray) {
        val appIntegrity = verdict.optJSONObject("appIntegrity")
        val appVerdict = appIntegrity?.optString("appRecognitionVerdict", "UNKNOWN") ?: "UNKNOWN"
        val packageName = appIntegrity?.optString("packageName")
        val versionCode = appIntegrity?.optString("versionCode")

        val deviceIntegrity = verdict.optJSONObject("deviceIntegrity")
        val deviceVerdicts = deviceIntegrity?.optJSONArray("deviceRecognitionVerdict")
        val sdkVersion = deviceIntegrity?.optJSONObject("deviceAttributes")?.optInt("sdkVersion", -1) ?: -1
        val activityLevel = deviceIntegrity?.optJSONObject("recentDeviceActivity")
            ?.optString("deviceActivityLevel")

        val licensingVerdict = verdict.optJSONObject("accountDetails")
            ?.optString("appLicensingVerdict", "UNKNOWN") ?: "UNKNOWN"

        val environmentDetails = verdict.optJSONObject("environmentDetails")
        val playProtectVerdict = environmentDetails?.optString("playProtectVerdict")
        val appsDetected = environmentDetails?.optJSONObject("appAccessRiskVerdict")
            ?.optJSONArray("appsDetected")

        val deviceEvaluated = deviceVerdicts != null && deviceVerdicts.length() > 0
        var deviceText = if (deviceEvaluated) deviceVerdicts.toString() else "Not evaluated (may be an emulator)"
        if (sdkVersion >= 0) deviceText += " · SDK $sdkVersion"
        if (!activityLevel.isNullOrEmpty() && activityLevel != "UNEVALUATED") deviceText += " · activity $activityLevel"

        var appText = appVerdict
        if (!packageName.isNullOrEmpty()) appText += " · $packageName"
        if (!versionCode.isNullOrEmpty()) appText += " · v$versionCode"

        val envText = "Play Protect: ${playProtectVerdict ?: "not reported"}" +
            if (appsDetected != null && appsDetected.length() > 0) " · $appsDetected" else ""

        // Card colors come from the backend's per-area tiers (server.js evaluatePolicy).
        applyStatus(tvAppValue, tvAppChip, appText, statusOf(tiers.optString("app")))
        applyStatus(tvDeviceValue, tvDeviceChip, deviceText, statusOf(tiers.optString("device")))
        applyStatus(tvAccountValue, tvAccountChip, licensingVerdict, statusOf(tiers.optString("account")))
        applyStatus(tvEnvValue, tvEnvChip, envText, statusOf(tiers.optString("environment")))

        val (bannerColor, icon, title, subtitle) = when (statusOf(riskLevel)) {
            Status.GOOD -> Quad(R.color.trust_green, "✓", "Device Trusted", "Risk level: LOW - all Play Integrity checks passed")
            Status.BAD -> Quad(R.color.trust_red, "✕", "Risky Device", "Risk level: HIGH")
            Status.NEUTRAL -> Quad(R.color.trust_amber, "!", "Partially Verified", "Risk level: MEDIUM")
        }
        val reasonLines = (0 until reasons.length()).joinToString("\n") { "• ${reasons.optString(it)}" }
        cardBanner.setCardBackgroundColor(ContextCompat.getColor(this, bannerColor))
        tvBannerIcon.text = icon
        tvBannerTitle.text = title
        tvBannerSubtitle.text = if (reasonLines.isEmpty()) subtitle else "$subtitle\n\n$reasonLines"
    }

    private enum class Status { GOOD, NEUTRAL, BAD }

    /** Maps the backend's LOW/MEDIUM/HIGH tier to a card status; anything unexpected shows as UNCLEAR. */
    private fun statusOf(tier: String): Status = when (tier) {
        "LOW" -> Status.GOOD
        "HIGH" -> Status.BAD
        else -> Status.NEUTRAL
    }

    private data class Quad(val color: Int, val icon: String, val title: String, val subtitle: String)

    private fun applyStatus(valueView: TextView, chipView: TextView, value: String, status: Status) {
        valueView.text = value
        val (bg, fg, label) = when (status) {
            Status.GOOD -> Triple(R.color.trust_green_bg, R.color.trust_green, "GOOD")
            Status.NEUTRAL -> Triple(R.color.trust_amber_bg, R.color.trust_amber, "UNCLEAR")
            Status.BAD -> Triple(R.color.trust_red_bg, R.color.trust_red, "RISKY")
        }
        chipView.text = label
        chipView.setTextColor(ContextCompat.getColor(this, fg))
        chipView.background.setTint(ContextCompat.getColor(this, bg))
    }
}
