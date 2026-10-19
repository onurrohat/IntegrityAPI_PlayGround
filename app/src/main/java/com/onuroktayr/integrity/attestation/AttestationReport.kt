package com.onuroktayr.integrity.attestation

import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

enum class Severity { INFO, LOW, MEDIUM, HIGH }

data class Finding(val severity: Severity, val title: String, val detail: String)

data class CertNode(
    val level: String,
    val subject: String,
    val issuer: String,
    val serialHex: String,
    val notBefore: Date,
    val notAfter: Date,
    val currentlyValid: Boolean,
)

data class AttestationReport(
    val chain: List<CertNode>,
    val chainCryptoValid: Boolean,
    val rootTrusted: Boolean?,
    val rootTrustCheckedAgainstLiveList: Boolean,
    val revocationChecked: Boolean,
    val info: AttestationParser.KeyAttestationInfo?,
    val findings: List<Finding>,
) {
    val overallSeverity: Severity
        get() = findings.maxOfOrNull { it.severity } ?: Severity.INFO
}

/**
 * Turns a raw certificate chain (as returned by `KeyStore.getCertificateChain`) into an
 * [AttestationReport]: parses the leaf's attestation extension, cryptographically links
 * the chain, checks the root against Google's published Hardware Attestation roots, checks
 * revocation status, and produces a flat list of human-readable findings.
 */
object AttestationChainValidator {

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)

    fun buildReport(
        chain: List<X509Certificate>,
        expectedChallenge: ByteArray,
        trustedRoots: List<X509Certificate>,
        rootsAreLive: Boolean,
        revocationList: Map<String, AttestationTrust.RevocationEntry>?,
    ): AttestationReport {
        val findings = mutableListOf<Finding>()
        val now = Date()

        // --- 1. Per-certificate bookkeeping (validity window, node labels) ---
        val nodes = chain.mapIndexed { index, cert ->
            val label = when {
                index == 0 -> "Leaf"
                index == chain.lastIndex -> "Root"
                else -> "Intermediate #$index"
            }
            val valid = !cert.notBefore.after(now) && !cert.notAfter.before(now)
            if (cert.notAfter.before(now)) {
                findings += Finding(Severity.HIGH, "$label certificate has expired", "notAfter=${dateFormat.format(cert.notAfter)}")
            }
            if (cert.notBefore.after(now)) {
                findings += Finding(Severity.MEDIUM, "$label certificate is not yet valid", "notBefore=${dateFormat.format(cert.notBefore)}")
            }
            CertNode(
                level = label,
                subject = cert.subjectX500Principal.name,
                issuer = cert.issuerX500Principal.name,
                serialHex = cert.serialNumber.toString(16),
                notBefore = cert.notBefore,
                notAfter = cert.notAfter,
                currentlyValid = valid,
            )
        }

        // --- 2. Cryptographic chain linking: each cert must verify with the next cert's key ---
        var chainCryptoValid = true
        for (i in 0 until chain.size - 1) {
            try {
                chain[i].verify(chain[i + 1].publicKey)
            } catch (e: Exception) {
                chainCryptoValid = false
                findings += Finding(
                    Severity.HIGH,
                    "Chain link broken between ${nodes[i].level} and ${nodes[i + 1].level}",
                    "Signature does not verify against the issuer's public key (${e.javaClass.simpleName}: ${e.message}). The chain may be forged or corrupted.",
                )
            }
        }

        // --- 3. Root trust: does the topmost cert match a known Google root? ---
        // Compare public keys, not whole certificates: Google has re-issued the same RSA
        // root key (subject serial f92009e853b6b045) several times with different validity
        // periods/serials, and devices may ship any of those re-issues while the live list
        // only carries the newest one. The key is what signs the chain, so it's what matters.
        val rootCert = chain.lastOrNull()
        val rootTrusted = rootCert?.let { root ->
            trustedRoots.any { it.publicKey.encoded.contentEquals(root.publicKey.encoded) }
        }
        when (rootTrusted) {
            true -> findings += Finding(
                Severity.INFO,
                "Root certificate matches a recognized Google Hardware Attestation root",
                if (rootsAreLive) "Checked against Google's live root list." else "Checked against an offline snapshot of Google's roots (no network at check time).",
            )
            false -> findings += Finding(
                Severity.HIGH,
                "Root certificate is NOT a recognized Google Hardware Attestation root",
                "The chain does not terminate at a certificate Google has published. This means the chain cannot be trusted - it may be self-signed, forged, or produced by a software/emulated Keystore pretending to have hardware backing.",
            )
            null -> {}
        }

        // --- 4. Leaf attestation extension: security level, verified boot, challenge, patch levels ---
        val leaf = chain.firstOrNull()
        val info = leaf?.let { AttestationParser.parse(it) }
        if (leaf != null && info == null) {
            findings += Finding(
                Severity.HIGH,
                "Leaf certificate has no attestation extension",
                "This key was not generated with a real attestation challenge, or the platform ignored it. There is nothing to attest.",
            )
        }

        if (info != null) {
            when (info.attestationSecurityLevel) {
                AttestationParser.SecurityLevel.SOFTWARE -> findings += Finding(
                    Severity.HIGH,
                    "Attestation security level is SOFTWARE",
                    "No real hardware/TEE backing was used to sign this certificate. Typical of an emulator, a rooted device with a software Keystore implementation, or a hooking framework faking the Keystore API.",
                )
                AttestationParser.SecurityLevel.TRUSTED_ENVIRONMENT -> findings += Finding(
                    Severity.INFO,
                    "Attestation is backed by a Trusted Execution Environment (TEE)",
                    "The key and its attestation were produced inside the device's TEE.",
                )
                AttestationParser.SecurityLevel.STRONG_BOX -> findings += Finding(
                    Severity.INFO,
                    "Attestation is backed by StrongBox",
                    "The highest hardware security level available on Android - a separate, tamper-resistant secure chip.",
                )
                AttestationParser.SecurityLevel.UNKNOWN -> findings += Finding(
                    Severity.LOW,
                    "Unrecognized attestation security level",
                    "code=${info.attestationSecurityLevel.code}",
                )
            }

            if (!info.attestationChallenge.contentEquals(expectedChallenge)) {
                findings += Finding(
                    Severity.HIGH,
                    "Attestation challenge mismatch",
                    "The challenge embedded in the certificate doesn't match the challenge this app just sent. Possible replay of a stale/cached certificate, or tampering between generation and inspection.",
                )
            }

            val rot = info.hardwareRootOfTrust
            val softwareRot = info.softwareEnforced.rootOfTrust
            if (rot == null && softwareRot != null) {
                findings += Finding(
                    Severity.MEDIUM,
                    "Root of trust is only software-reported",
                    "The bootloader/Verified Boot state is not in the hardware-enforced list, so nothing guarantees it. " +
                        "Software claims deviceLocked=${softwareRot.deviceLocked}, verifiedBootState=${softwareRot.verifiedBootState} - not used for any check.",
                )
            } else if (rot == null) {
                findings += Finding(
                    Severity.MEDIUM,
                    "No root-of-trust record in the attestation",
                    "Older devices/API levels may omit it; on a modern device this alone is suspicious.",
                )
            } else {
                if (!rot.deviceLocked) {
                    findings += Finding(
                        Severity.HIGH,
                        "Bootloader is unlocked",
                        "deviceLocked=false. Verified Boot cannot guarantee the OS partition wasn't modified.",
                    )
                }
                when (rot.verifiedBootState) {
                    AttestationParser.VerifiedBootState.VERIFIED -> findings += Finding(
                        Severity.INFO,
                        "Verified Boot state: VERIFIED",
                        "The boot image chain was verified against Google's or the OEM's trusted key.",
                    )
                    AttestationParser.VerifiedBootState.SELF_SIGNED -> findings += Finding(
                        Severity.MEDIUM,
                        "Verified Boot state: SELF_SIGNED",
                        "The boot image was verified against a user/OEM-unlock key, not Google's - typical of a custom ROM on a re-locked bootloader.",
                    )
                    AttestationParser.VerifiedBootState.UNVERIFIED -> findings += Finding(
                        Severity.HIGH,
                        "Verified Boot state: UNVERIFIED",
                        "Boot verification is turned off - usually an unlocked bootloader.",
                    )
                    AttestationParser.VerifiedBootState.FAILED -> findings += Finding(
                        Severity.HIGH,
                        "Verified Boot state: FAILED",
                        "The boot image failed verification. The device's OS may be compromised.",
                    )
                    AttestationParser.VerifiedBootState.UNKNOWN -> findings += Finding(
                        Severity.LOW,
                        "Unrecognized Verified Boot state",
                        "code=${rot.verifiedBootState.code}",
                    )
                }
            }

            info.hardwareOsPatchLevel?.let { checkPatchAge(findings, "OS security patch level", it) }
            info.hardwareVendorPatchLevel?.let { checkPatchAge(findings, "Vendor security patch level", it) }
            info.hardwareBootPatchLevel?.let { checkPatchAge(findings, "Boot security patch level", it) }
        }

        // --- 5. Revocation check across the whole chain ---
        if (revocationList != null) {
            for ((index, cert) in chain.withIndex()) {
                val serialHex = cert.serialNumber.toString(16).lowercase()
                val entry = revocationList[serialHex]
                if (entry != null) {
                    findings += Finding(
                        Severity.HIGH,
                        "${nodes[index].level} certificate is ${entry.status} by Google",
                        listOfNotNull(
                            entry.reason?.let { "reason=$it" },
                            entry.comment?.let { "comment=$it" },
                        ).joinToString(", ").ifEmpty { "serial=$serialHex" },
                    )
                }
            }
        } else {
            findings += Finding(
                Severity.LOW,
                "Revocation status could not be checked",
                "Could not reach ${AttestationTrust.REVOCATION_LIST_URL} (no network?). This chain has not been checked against Google's revoked-key list.",
            )
        }

        return AttestationReport(
            chain = nodes,
            chainCryptoValid = chainCryptoValid,
            rootTrusted = rootTrusted,
            rootTrustCheckedAgainstLiveList = rootsAreLive,
            revocationChecked = revocationList != null,
            info = info,
            findings = findings,
        )
    }

    private fun checkPatchAge(findings: MutableList<Finding>, label: String, patchLevel: Int) {
        val s = patchLevel.toString()
        if (s.length < 6) return
        val year = s.substring(0, 4).toIntOrNull() ?: return
        val month = s.substring(4, 6).toIntOrNull() ?: return
        val cal = java.util.Calendar.getInstance()
        cal.set(year, month - 1, 1)
        val ageMillis = System.currentTimeMillis() - cal.timeInMillis
        val ageMonths = TimeUnit.MILLISECONDS.toDays(ageMillis) / 30
        val formatted = AttestationParser.formatPatchLevel(patchLevel)
        when {
            ageMonths >= 24 -> findings += Finding(Severity.MEDIUM, "$label is very old", "$formatted (~$ageMonths months ago)")
            ageMonths >= 12 -> findings += Finding(Severity.LOW, "$label is stale", "$formatted (~$ageMonths months ago)")
            else -> findings += Finding(Severity.INFO, label, formatted)
        }
    }
}
