package com.eltavine.duckdetector.features.tee.data.verification.keystore

import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.KeyStore
import java.security.SecureRandom

class OversizedChallengeProbe {

    fun inspect(
        keyStore: KeyStore = AndroidKeyStoreTools.loadKeyStore(),
        useStrongBox: Boolean = false,
    ): OversizedChallengeResult {
        val acceptedSizes = buildList {
            CHALLENGE_SIZES.forEach { size ->
                val alias = "duck_long_challenge_${size}_${System.nanoTime()}"
                val accepted = runCatching {
                    val challenge = ByteArray(size).also { SecureRandom().nextBytes(it) }
                    val chain = AndroidKeyStoreTools.generateAttestedEcChain(
                        keyStore = keyStore,
                        alias = alias,
                        challenge = challenge,
                        useStrongBox = useStrongBox,
                    )
                    chain.isNotEmpty()
                }.getOrDefault(false)
                AndroidKeyStoreTools.safeDelete(keyStore, alias)
                if (accepted) {
                    add(size)
                }
            }
        }
        return OversizedChallengeResult(
            acceptedOversizedChallenge = acceptedSizes.isNotEmpty(),
            acceptedSizes = acceptedSizes,
            attemptedSizes = CHALLENGE_SIZES,
            detail = if (acceptedSizes.isNotEmpty()) {
                "Attestation accepted oversized challenge sizes: ${
                    acceptedSizes.joinToString(
                        separator = ", "
                    ) { "${it}B" }
                }."
            } else {
                "Attestation rejected oversized challenge sizes: ${
                    CHALLENGE_SIZES.joinToString(
                        separator = ", "
                    ) { "${it}B" }
                }."
            },
        )
    }

    companion object {
        val CHALLENGE_SIZES: List<Int> = listOf(256, 512, 4096)
    }
}

data class OversizedChallengeResult(
    val acceptedOversizedChallenge: Boolean,
    val acceptedSizes: List<Int> = emptyList(),
    val attemptedSizes: List<Int> = OversizedChallengeProbe.CHALLENGE_SIZES,
    val detail: String,
) {
    val acceptedLargestSize: Int?
        get() = acceptedSizes.maxOrNull()

    fun acceptedSizesLabel(): String {
        return acceptedSizes.joinToString(separator = " • ") { "${it}B" }
    }

    fun attemptedSizesLabel(): String {
        return attemptedSizes.joinToString(separator = " • ") { "${it}B" }
    }
}
