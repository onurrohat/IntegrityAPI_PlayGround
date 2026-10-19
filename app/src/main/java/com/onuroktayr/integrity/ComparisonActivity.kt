package com.onuroktayr.integrity

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import com.onuroktayr.integrity.attestation.AttestationReport
import com.onuroktayr.integrity.attestation.AttestationRunner
import com.onuroktayr.integrity.attestation.Severity
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Puts Play Integrity's *server-side* deviceIntegrity verdict for this login next to
 * a Key Attestation chain generated *on this device, right now*, and states whether
 * the two agree. The two are not mathematically linked - Google has never documented
 * computing the former from an app-generated chain like the latter - but both rest on
 * the same hardware root of trust (TEE/StrongBox), so agreement is still a meaningful
 * signal and disagreement is worth a closer look. This screen shows both sides at once
 * instead of trusting either one blindly.
 */
class ComparisonActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_VERDICT_JSON = SecureDashboardActivity.EXTRA_VERDICT_JSON
        const val EXTRA_TIERS_JSON = SecureDashboardActivity.EXTRA_TIERS_JSON
    }

    private lateinit var btnRun: Button
    private lateinit var pbLoading: ProgressBar
    private lateinit var cardBanner: CardView
    private lateinit var tvBannerIcon: TextView
    private lateinit var tvBannerTitle: TextView
    private lateinit var tvBannerSubtitle: TextView
    private lateinit var tvPiValue: TextView
    private lateinit var tvPiChip: TextView
    private lateinit var tvAttestValue: TextView
    private lateinit var tvAttestChip: TextView
    private lateinit var tvToggleTech: TextView
    private lateinit var tvTechDetails: TextView

    private var verdict: JSONObject? = null
    /** The backend's device risk tier (LOW/MEDIUM/HIGH) from /verify - the single source of truth for the Play Integrity side. */
    private var deviceTier: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_comparison)

        btnRun = findViewById(R.id.btnRun)
        pbLoading = findViewById(R.id.pbLoading)
        cardBanner = findViewById(R.id.cardBanner)
        tvBannerIcon = findViewById(R.id.tvBannerIcon)
        tvBannerTitle = findViewById(R.id.tvBannerTitle)
        tvBannerSubtitle = findViewById(R.id.tvBannerSubtitle)
        tvPiValue = findViewById(R.id.tvPiValue)
        tvPiChip = findViewById(R.id.tvPiChip)
        tvAttestValue = findViewById(R.id.tvAttestValue)
        tvAttestChip = findViewById(R.id.tvAttestChip)
        tvToggleTech = findViewById(R.id.tvToggleTech)
        tvTechDetails = findViewById(R.id.tvTechDetails)

        tvToggleTech.setOnClickListener {
            val showing = tvTechDetails.visibility == View.VISIBLE
            tvTechDetails.visibility = if (showing) View.GONE else View.VISIBLE
            tvToggleTech.text = if (showing) "Technical details (raw) ▾" else "Technical details (raw) ▴"
        }
        findViewById<Button>(R.id.btnBack).setOnClickListener { finish() }

        verdict = intent.getStringExtra(EXTRA_VERDICT_JSON)?.let { JSONObject(it) }
        deviceTier = intent.getStringExtra(EXTRA_TIERS_JSON)?.let { JSONObject(it).optString("device") }.orEmpty()
        renderPlayIntegritySide()

        btnRun.setOnClickListener { runAttestationAndCompare() }
    }

    private fun deviceRecognitionVerdicts(v: JSONObject?) =
        v?.optJSONObject("deviceIntegrity")?.optJSONArray("deviceRecognitionVerdict")

    private fun piStatus(): Status = when (deviceTier) {
        "LOW" -> Status.GOOD
        "HIGH" -> Status.BAD
        else -> Status.NEUTRAL
    }

    private fun renderPlayIntegritySide() {
        val deviceVerdicts = deviceRecognitionVerdicts(verdict)
        val evaluated = deviceVerdicts != null && deviceVerdicts.length() > 0
        val text = if (verdict == null) {
            "No login verdict available"
        } else if (evaluated) {
            "$deviceVerdicts · server device risk: ${deviceTier.ifEmpty { "?" }}"
        } else {
            "Not evaluated (empty deviceRecognitionVerdict - may be an emulator or too new to judge) · server device risk: ${deviceTier.ifEmpty { "?" }}"
        }
        applyChip(tvPiValue, tvPiChip, text, piStatus())
    }

    private fun runAttestationAndCompare() {
        btnRun.isEnabled = false
        pbLoading.visibility = View.VISIBLE
        setBanner(Severity.INFO, "⏳", "Working...", "Generating a hardware-backed key on this device")

        Thread {
            try {
                val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val report = AttestationRunner.run(AttestationRunner.KEY_ALIAS, challenge)
                runOnUiThread { renderComparison(report) }
            } catch (e: Exception) {
                runOnUiThread {
                    btnRun.isEnabled = true
                    pbLoading.visibility = View.GONE
                    setBanner(Severity.HIGH, "✕", "Could not generate attestation", e.message ?: e.toString())
                }
            }
        }.start()
    }

    private fun renderComparison(report: AttestationReport) {
        btnRun.isEnabled = true
        pbLoading.visibility = View.GONE

        val highCount = report.findings.count { it.severity == Severity.HIGH }
        val attestClean = highCount == 0
        applyChip(
            tvAttestValue, tvAttestChip,
            "$highCount high-severity finding(s), ${report.findings.size} total",
            if (attestClean) Status.GOOD else Status.BAD,
        )

        // The Play Integrity side uses the server's device tier, so this screen can never
        // disagree with the decision /verify made. MEDIUM (basic integrity only, or no device
        // verdict at all) is treated as "inconclusive", not as "bad" - collapsing it into BAD
        // would make an unevaluated device falsely read as "Signals Agree: Risky Device".
        val pi = piStatus()
        val result = when {
            pi == Status.GOOD && attestClean -> Quad(
                Severity.INFO, "✓", "Signals Agree: Genuine Device",
                "Play Integrity's device verdict and this device's own attestation chain both come back clean.",
            )
            pi == Status.BAD && !attestClean -> Quad(
                Severity.HIGH, "✕", "Signals Agree: Risky Device",
                "Both Play Integrity and the attestation chain found problems with this device.",
            )
            pi == Status.GOOD && !attestClean -> Quad(
                Severity.MEDIUM, "!", "Signals Disagree",
                "Play Integrity's device verdict looked fine, but the attestation chain found concrete evidence (see below) that Play Integrity's opaque verdict didn't surface.",
            )
            pi == Status.BAD && attestClean -> Quad(
                Severity.MEDIUM, "!", "Signals Disagree",
                "Play Integrity flagged this device, but the attestation chain generated just now came back clean - the device-level evidence here doesn't explain Play Integrity's concern, so check the app/account/environment signals on the dashboard instead.",
            )
            !attestClean -> Quad(
                Severity.HIGH, "!", "Attestation Found an Issue; Play Integrity Is Inconclusive",
                "The server rated this device MEDIUM (basic integrity only, or not evaluated - common for an emulator or a new app), so Play Integrity neither confirms nor denies anything here - but the attestation chain generated just now found concrete problems on its own.",
            )
            else -> Quad(
                Severity.MEDIUM, "!", "Signals Disagree",
                "The attestation chain is clean, but the server rated this device MEDIUM (basic integrity only, or not evaluated) - that's an absence of a good signal, not evidence of a bad one.",
            )
        }
        setBanner(result.severity, result.icon, result.title, result.subtitle)

        tvTechDetails.text = buildTechDetails(report)
    }

    private fun setBanner(severity: Severity, icon: String, title: String, subtitle: String) {
        val color = when (severity) {
            Severity.HIGH -> R.color.trust_red
            Severity.MEDIUM -> R.color.trust_amber
            Severity.LOW, Severity.INFO -> R.color.trust_green
        }
        cardBanner.setCardBackgroundColor(ContextCompat.getColor(this, color))
        tvBannerIcon.text = icon
        tvBannerTitle.text = title
        tvBannerSubtitle.text = subtitle
    }

    private enum class Status { GOOD, NEUTRAL, BAD }
    private data class Quad(val severity: Severity, val icon: String, val title: String, val subtitle: String)

    private fun applyChip(valueView: TextView, chipView: TextView, value: String, status: Status) {
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

    private fun buildTechDetails(report: AttestationReport): String {
        val sb = StringBuilder()
        sb.append("--- Play Integrity deviceIntegrity (from the server's /verify response) ---\n")
        sb.append(verdict?.optJSONObject("deviceIntegrity")?.toString(2) ?: "none")
        sb.append("\n\n--- Key Attestation chain (generated on this device just now) ---\n")
        report.findings.sortedByDescending { it.severity }.forEach {
            sb.append("[${it.severity}] ${it.title} - ${it.detail}\n")
        }
        return sb.toString()
    }
}
