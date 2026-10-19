package com.onuroktayr.integrity.attestation

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * Key generation + chain fetch + report building, shared by every screen that needs a
 * fresh Key Attestation chain (AttestationActivity, ComparisonActivity). Kept as one
 * blocking function - callers run it off the main thread - so the two screens can't
 * drift apart on how the chain is produced.
 */
object AttestationRunner {

    const val KEY_ALIAS = "integritytest_attestation_key"

    fun run(alias: String, challenge: ByteArray): AttestationReport {
        generateAttestationKeyPair(alias, challenge)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        @Suppress("UNCHECKED_CAST")
        val chain = (keyStore.getCertificateChain(alias) ?: emptyArray())
            .map { it as X509Certificate }

        if (chain.isEmpty()) {
            throw IllegalStateException("Keystore returned no certificate chain for the generated key.")
        }

        val liveRoots = AttestationTrust.fetchTrustedRoots()
        val trustedRoots = liveRoots ?: AttestationTrust.embeddedTrustedRoots()
        val revocationList = AttestationTrust.fetchRevocationList()

        return AttestationChainValidator.buildReport(
            chain = chain,
            expectedChallenge = challenge,
            trustedRoots = trustedRoots,
            rootsAreLive = liveRoots != null,
            revocationList = revocationList,
        )
    }

    /** Returns once a fresh key exists under [alias] with [challenge] baked into its attestation. */
    private fun generateAttestationKeyPair(alias: String, challenge: ByteArray) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                val strongBoxSpec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .setIsStrongBoxBacked(true)
                    .build()
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                kpg.initialize(strongBoxSpec)
                kpg.generateKeyPair()
                return
            } catch (e: Exception) {
                // StrongBoxUnavailableException (or anything else) -> fall back to TEE below.
            }
        }

        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }
}
