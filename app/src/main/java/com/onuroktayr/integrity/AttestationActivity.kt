package com.onuroktayr.integrity

import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import com.onuroktayr.integrity.attestation.AttestationParser
import com.onuroktayr.integrity.attestation.AttestationReport
import com.onuroktayr.integrity.attestation.AttestationRunner
import com.onuroktayr.integrity.attestation.CertNode
import com.onuroktayr.integrity.attestation.Finding
import com.onuroktayr.integrity.attestation.Severity
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * Extracts and inspects the Android **Key Attestation certificate chain**
 * directly from the device's own Keystore - completely independent of the
 * Play Integrity API used elsewhere in this app.
 *
 * Where Play Integrity only ever returns an opaque verdict, this screen shows
 * the actual cryptographic evidence behind a device-integrity claim: the
 * leaf/intermediate/root certificate chain, whether it's signed correctly
 * link-by-link, whether the root is one Google actually publishes, whether
 * any certificate in it has been revoked, and what the leaf's attestation
 * extension says about Verified Boot state, bootloader lock state and patch
 * levels. See ARCHITECTURE.md for the full write-up of what each check means.
 */
class AttestationActivity : AppCompatActivity() {

    private lateinit var btnGenerate: Button
    private lateinit var pbLoading: ProgressBar
    private lateinit var cardBanner: CardView
    private lateinit var tvBannerIcon: TextView
    private lateinit var tvBannerTitle: TextView
    private lateinit var tvBannerSubtitle: TextView
    private lateinit var llFindings: LinearLayout
    private lateinit var llChain: LinearLayout
    private lateinit var tvToggleTech: TextView
    private lateinit var tvTechDetails: TextView

    private val dp get() = resources.displayMetrics.density
    private fun Int.dp() = (this * dp).toInt()

    private var lastReport: AttestationReport? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_attestation)

        btnGenerate = findViewById(R.id.btnGenerate)
        pbLoading = findViewById(R.id.pbLoading)
        cardBanner = findViewById(R.id.cardBanner)
        tvBannerIcon = findViewById(R.id.tvBannerIcon)
        tvBannerTitle = findViewById(R.id.tvBannerTitle)
        tvBannerSubtitle = findViewById(R.id.tvBannerSubtitle)
        llFindings = findViewById(R.id.llFindings)
        llChain = findViewById(R.id.llChain)
        tvToggleTech = findViewById(R.id.tvToggleTech)
        tvTechDetails = findViewById(R.id.tvTechDetails)

        tvToggleTech.setOnClickListener {
            val showing = tvTechDetails.visibility == View.VISIBLE
            tvTechDetails.visibility = if (showing) View.GONE else View.VISIBLE
            tvToggleTech.text = if (showing) "Technical details (raw) ▾" else "Technical details (raw) ▴"
        }

        findViewById<Button>(R.id.btnCopy).setOnClickListener { copyTechDetails() }
        findViewById<Button>(R.id.btnBack).setOnClickListener { finish() }

        btnGenerate.setOnClickListener { runInspection() }
    }

    private fun runInspection() {
        btnGenerate.isEnabled = false
        pbLoading.visibility = View.VISIBLE
        llFindings.removeAllViews()
        llChain.removeAllViews()
        tvTechDetails.text = ""
        setBanner(Severity.INFO, "⏳", "Working...", "Generating a hardware-backed key and fetching Google's trust data")

        Thread {
            try {
                val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val report = AttestationRunner.run(AttestationRunner.KEY_ALIAS, challenge)
                runOnUiThread { renderReport(report) }
            } catch (e: Exception) {
                runOnUiThread {
                    setBanner(Severity.HIGH, "✕", "Could not generate attestation", e.message ?: e.toString())
                    btnGenerate.isEnabled = true
                    pbLoading.visibility = View.GONE
                }
            }
        }.start()
    }

    private fun renderReport(report: AttestationReport) {
        lastReport = report
        btnGenerate.isEnabled = true
        pbLoading.visibility = View.GONE

        val highCount = report.findings.count { it.severity == Severity.HIGH }
        val mediumCount = report.findings.count { it.severity == Severity.MEDIUM }
        when {
            highCount > 0 -> setBanner(
                Severity.HIGH, "✕", "Issues Found",
                "$highCount high-severity finding(s) in the attestation chain",
            )
            mediumCount > 0 -> setBanner(
                Severity.MEDIUM, "!", "Partially Trusted",
                "$mediumCount medium-severity finding(s) - review before trusting this device",
            )
            else -> setBanner(
                Severity.INFO, "✓", "Chain Looks Clean",
                "No issues found in the attestation chain",
            )
        }

        report.findings
            .sortedByDescending { it.severity }
            .forEach { addFindingCard(it) }

        report.chain.forEachIndexed { index, node -> addChainNodeCard(node, index, report.chain.size) }

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

    private fun severityColors(severity: Severity): Triple<Int, Int, String> = when (severity) {
        Severity.HIGH -> Triple(R.color.trust_red_bg, R.color.trust_red, "HIGH")
        Severity.MEDIUM -> Triple(R.color.trust_amber_bg, R.color.trust_amber, "MEDIUM")
        Severity.LOW -> Triple(R.color.trust_amber_bg, R.color.trust_amber, "LOW")
        Severity.INFO -> Triple(R.color.trust_green_bg, R.color.trust_green, "OK")
    }

    private fun addFindingCard(finding: Finding) {
        val (bgColor, fgColor, label) = severityColors(finding.severity)

        val card = CardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = 8.dp()
            }
            radius = 14.dp().toFloat()
            cardElevation = 0f
            setCardBackgroundColor(ContextCompat.getColor(this@AttestationActivity, R.color.card_bg))
        }

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(14.dp(), 12.dp(), 14.dp(), 12.dp())
            gravity = android.view.Gravity.TOP
        }

        val chip = TextView(this).apply {
            text = label
            setTextColor(ContextCompat.getColor(this@AttestationActivity, fgColor))
            textSize = 10f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            background = ContextCompat.getDrawable(this@AttestationActivity, R.drawable.bg_chip)?.mutate()?.also {
                it.setTint(ContextCompat.getColor(this@AttestationActivity, bgColor))
            }
            setPadding(10.dp(), 4.dp(), 10.dp(), 4.dp())
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        }

        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = 12.dp() }
        }
        textCol.addView(TextView(this).apply {
            text = finding.title
            setTextColor(ContextCompat.getColor(this@AttestationActivity, R.color.text_primary))
            textSize = 13f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        textCol.addView(TextView(this).apply {
            text = finding.detail
            setTextColor(ContextCompat.getColor(this@AttestationActivity, R.color.text_secondary))
            textSize = 12f
            setPadding(0, 2.dp(), 0, 0)
        })

        row.addView(chip)
        row.addView(textCol)
        card.addView(row)
        llFindings.addView(card)
    }

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.US)

    private fun addChainNodeCard(node: CertNode, index: Int, total: Int) {
        val card = CardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = 8.dp()
            }
            radius = 14.dp().toFloat()
            cardElevation = 0f
            setCardBackgroundColor(ContextCompat.getColor(this@AttestationActivity, R.color.card_bg))
        }

        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(14.dp(), 12.dp(), 14.dp(), 12.dp())
        }

        val header = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL }
        header.addView(TextView(this).apply {
            text = "📜 ${node.level} (${index + 1}/$total)"
            setTextColor(ContextCompat.getColor(this@AttestationActivity, R.color.text_primary))
            textSize = 13f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        val validColor = if (node.currentlyValid) R.color.trust_green else R.color.trust_red
        header.addView(TextView(this).apply {
            text = if (node.currentlyValid) "VALID" else "INVALID"
            setTextColor(ContextCompat.getColor(this@AttestationActivity, validColor))
            textSize = 10f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        col.addView(header)

        col.addView(smallLine("Subject: ${node.subject}"))
        col.addView(smallLine("Issuer:  ${node.issuer}"))
        col.addView(smallLine("Serial:  ${node.serialHex}"))
        col.addView(smallLine("Valid:   ${dateFormat.format(node.notBefore)} → ${dateFormat.format(node.notAfter)}"))

        card.addView(col)
        llChain.addView(card)
    }

    private fun smallLine(text: String): TextView = TextView(this).apply {
        this.text = text
        setTextColor(ContextCompat.getColor(this@AttestationActivity, R.color.text_secondary))
        textSize = 11f
        typeface = android.graphics.Typeface.MONOSPACE
        setPadding(0, 2.dp(), 0, 0)
        setSingleLine(false)
    }

    private fun buildTechDetails(report: AttestationReport): String {
        val sb = StringBuilder()
        sb.append("=== Key Attestation Report ===\n")
        sb.append("Chain length: ${report.chain.size}\n")
        sb.append("Chain cryptographically valid: ${report.chainCryptoValid}\n")
        sb.append("Root trusted: ${report.rootTrusted} (checked against ${if (report.rootTrustCheckedAgainstLiveList) "LIVE" else "OFFLINE snapshot of"} Google root list)\n")
        sb.append("Revocation checked: ${report.revocationChecked}\n\n")

        report.info?.let { info ->
            sb.append("--- Attestation extension (leaf) ---\n")
            sb.append("attestationVersion: ${info.attestationVersion}\n")
            sb.append("attestationSecurityLevel: ${info.attestationSecurityLevel}\n")
            sb.append("keymasterVersion: ${info.keymasterVersion}\n")
            sb.append("keymasterSecurityLevel: ${info.keymasterSecurityLevel}\n")
            sb.append("attestationChallenge: ${info.attestationChallenge.toHex()}\n")
            appendAuthorizationList(sb, "teeEnforced (hardware-guaranteed)", info.teeEnforced)
            appendAuthorizationList(sb, "softwareEnforced (software-reported, not trusted)", info.softwareEnforced)
            sb.append("\n")
        }

        sb.append("--- Certificate chain ---\n")
        report.chain.forEach { node ->
            sb.append("[${node.level}] subject=${node.subject}\n")
            sb.append("            issuer=${node.issuer}\n")
            sb.append("            serial=${node.serialHex} valid=${node.currentlyValid} (${dateFormat.format(node.notBefore)} -> ${dateFormat.format(node.notAfter)})\n")
        }
        sb.append("\n--- Findings ---\n")
        report.findings.sortedByDescending { it.severity }.forEach {
            sb.append("[${it.severity}] ${it.title} - ${it.detail}\n")
        }
        return sb.toString()
    }

    private fun appendAuthorizationList(sb: StringBuilder, title: String, list: AttestationParser.AuthorizationList) {
        sb.append("[$title]\n")
        val before = sb.length
        list.rootOfTrust?.let { rot ->
            sb.append("  rootOfTrust.deviceLocked: ${rot.deviceLocked}\n")
            sb.append("  rootOfTrust.verifiedBootState: ${rot.verifiedBootState}\n")
            sb.append("  rootOfTrust.verifiedBootKey: ${rot.verifiedBootKey.toHex()}\n")
        }
        list.osPatchLevel?.let { sb.append("  osPatchLevel: ${AttestationParser.formatPatchLevel(it)}\n") }
        list.vendorPatchLevel?.let { sb.append("  vendorPatchLevel: ${AttestationParser.formatPatchLevel(it)}\n") }
        list.bootPatchLevel?.let { sb.append("  bootPatchLevel: ${AttestationParser.formatPatchLevel(it)}\n") }
        if (sb.length == before) sb.append("  (empty)\n")
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun copyTechDetails() {
        val text = tvTechDetails.text.toString()
        if (text.isBlank()) {
            Toast.makeText(this, "Nothing to copy yet - run the inspection first", Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = getSystemService(android.content.ClipboardManager::class.java)
        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("attestation_report", text))
        Toast.makeText(this, "Report copied to clipboard", Toast.LENGTH_SHORT).show()
    }
}
