package com.onuroktayr.integrity.attestation

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import java.security.cert.X509Certificate

/**
 * Decodes the Android Key Attestation certificate extension (OID
 * 1.3.6.1.4.1.11129.2.1.17) out of a leaf certificate produced by
 * `KeyGenParameterSpec.Builder(...).setAttestationChallenge(...)`.
 *
 * Schema (stable, documented at
 * https://source.android.com/docs/security/features/keystore/attestation#schema):
 *
 * ```
 * KeyDescription ::= SEQUENCE {
 *     attestationVersion         INTEGER,
 *     attestationSecurityLevel   SecurityLevel,
 *     keymasterVersion           INTEGER,
 *     keymasterSecurityLevel     SecurityLevel,
 *     attestationChallenge       OCTET_STRING,
 *     uniqueId                   OCTET_STRING,
 *     softwareEnforced           AuthorizationList,
 *     teeEnforced                AuthorizationList,
 * }
 * ```
 *
 * Only the fields this app actually uses for problem-detection are extracted;
 * the many other AuthorizationList tags (padding, digests, auth timeouts, ...)
 * are ignored on purpose.
 */
object AttestationParser {

    const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

    enum class SecurityLevel(val code: Int) {
        SOFTWARE(0),
        TRUSTED_ENVIRONMENT(1),
        STRONG_BOX(2),
        UNKNOWN(-1);

        companion object {
            fun fromCode(code: Int) = entries.firstOrNull { it.code == code } ?: UNKNOWN
        }
    }

    enum class VerifiedBootState(val code: Int) {
        VERIFIED(0),
        SELF_SIGNED(1),
        UNVERIFIED(2),
        FAILED(3),
        UNKNOWN(-1);

        companion object {
            fun fromCode(code: Int) = entries.firstOrNull { it.code == code } ?: UNKNOWN
        }
    }

    data class RootOfTrust(
        val verifiedBootKey: ByteArray,
        val deviceLocked: Boolean,
        val verifiedBootState: VerifiedBootState,
        val verifiedBootHash: ByteArray?,
    )

    data class AuthorizationList(
        val origin: Int? = null,
        val rootOfTrust: RootOfTrust? = null,
        val osVersion: Int? = null,
        val osPatchLevel: Int? = null,
        val vendorPatchLevel: Int? = null,
        val bootPatchLevel: Int? = null,
    )

    data class KeyAttestationInfo(
        val attestationVersion: Int,
        val attestationSecurityLevel: SecurityLevel,
        val keymasterVersion: Int,
        val keymasterSecurityLevel: SecurityLevel,
        val attestationChallenge: ByteArray,
        val uniqueId: ByteArray,
        val softwareEnforced: AuthorizationList,
        val teeEnforced: AuthorizationList,
    ) {
        /**
         * Only teeEnforced values are guaranteed by the secure hardware. softwareEnforced is
         * written by Android itself, so on a rooted device or a fake Keystore it can claim
         * anything - it must never be used for a trust decision, only shown as "software-reported".
         */
        val hardwareRootOfTrust: RootOfTrust? get() = teeEnforced.rootOfTrust
        val hardwareOsPatchLevel: Int? get() = teeEnforced.osPatchLevel
        val hardwareVendorPatchLevel: Int? get() = teeEnforced.vendorPatchLevel
        val hardwareBootPatchLevel: Int? get() = teeEnforced.bootPatchLevel
    }

    // AuthorizationList explicit tag numbers we read (see the full list in the schema doc).
    private const val TAG_ORIGIN = 702
    private const val TAG_ROOT_OF_TRUST = 704
    private const val TAG_OS_VERSION = 705
    private const val TAG_OS_PATCH_LEVEL = 706
    private const val TAG_VENDOR_PATCH_LEVEL = 718
    private const val TAG_BOOT_PATCH_LEVEL = 719

    /** Returns null if the certificate has no attestation extension at all. */
    fun parse(cert: X509Certificate): KeyAttestationInfo? {
        val rawExtensionValue = cert.getExtensionValue(ATTESTATION_EXTENSION_OID) ?: return null
        // X.509 stores every extension value wrapped in an outer OCTET STRING;
        // unwrap it once to get the actual KeyDescription DER bytes.
        val keyDescriptionBytes = ASN1OctetString.getInstance(rawExtensionValue).octets
        val seq = ASN1Sequence.getInstance(keyDescriptionBytes)

        return KeyAttestationInfo(
            attestationVersion = intAt(seq, 0),
            attestationSecurityLevel = SecurityLevel.fromCode(enumAt(seq, 1)),
            keymasterVersion = intAt(seq, 2),
            keymasterSecurityLevel = SecurityLevel.fromCode(enumAt(seq, 3)),
            attestationChallenge = octetsAt(seq, 4),
            uniqueId = octetsAt(seq, 5),
            softwareEnforced = parseAuthorizationList(ASN1Sequence.getInstance(seq.getObjectAt(6))),
            teeEnforced = parseAuthorizationList(ASN1Sequence.getInstance(seq.getObjectAt(7))),
        )
    }

    private fun parseAuthorizationList(seq: ASN1Sequence): AuthorizationList {
        var origin: Int? = null
        var rootOfTrust: RootOfTrust? = null
        var osVersion: Int? = null
        var osPatchLevel: Int? = null
        var vendorPatchLevel: Int? = null
        var bootPatchLevel: Int? = null

        for (element in seq) {
            val tagged = element as? ASN1TaggedObject ?: continue
            // Every AuthorizationList field is [n] EXPLICIT - the tag wraps a fully
            // self-describing child TLV, so getExplicitBaseObject() always hands back that child.
            when (tagged.tagNo) {
                TAG_ORIGIN -> origin = ASN1Integer.getInstance(tagged.getExplicitBaseObject()).value.toInt()
                TAG_ROOT_OF_TRUST -> rootOfTrust = parseRootOfTrust(ASN1Sequence.getInstance(tagged.getExplicitBaseObject()))
                TAG_OS_VERSION -> osVersion = ASN1Integer.getInstance(tagged.getExplicitBaseObject()).value.toInt()
                TAG_OS_PATCH_LEVEL -> osPatchLevel = ASN1Integer.getInstance(tagged.getExplicitBaseObject()).value.toInt()
                TAG_VENDOR_PATCH_LEVEL -> vendorPatchLevel = ASN1Integer.getInstance(tagged.getExplicitBaseObject()).value.toInt()
                TAG_BOOT_PATCH_LEVEL -> bootPatchLevel = ASN1Integer.getInstance(tagged.getExplicitBaseObject()).value.toInt()
            }
        }
        return AuthorizationList(origin, rootOfTrust, osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel)
    }

    private fun parseRootOfTrust(seq: ASN1Sequence): RootOfTrust {
        val verifiedBootKey = (seq.getObjectAt(0) as ASN1OctetString).octets
        val deviceLocked = ASN1Boolean.getInstance(seq.getObjectAt(1)).isTrue
        val verifiedBootState = VerifiedBootState.fromCode((seq.getObjectAt(2) as ASN1Enumerated).value.toInt())
        val verifiedBootHash = if (seq.size() > 3) (seq.getObjectAt(3) as ASN1OctetString).octets else null
        return RootOfTrust(verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash)
    }

    private fun intAt(seq: ASN1Sequence, index: Int): Int =
        (seq.getObjectAt(index) as ASN1Integer).value.toInt()

    private fun enumAt(seq: ASN1Sequence, index: Int): Int =
        (seq.getObjectAt(index) as ASN1Enumerated).value.toInt()

    private fun octetsAt(seq: ASN1Sequence, index: Int): ByteArray =
        (seq.getObjectAt(index) as ASN1OctetString).octets

    /** Formats a Keymaster patch level int (YYYYMM or YYYYMMDD) as "YYYY-MM[-DD]". */
    fun formatPatchLevel(patchLevel: Int): String {
        val s = patchLevel.toString()
        return when (s.length) {
            8 -> "${s.substring(0, 4)}-${s.substring(4, 6)}-${s.substring(6, 8)}"
            6 -> "${s.substring(0, 4)}-${s.substring(4, 6)}"
            else -> s
        }
    }
}
