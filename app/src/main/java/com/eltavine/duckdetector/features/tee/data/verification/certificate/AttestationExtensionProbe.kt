package com.eltavine.duckdetector.features.tee.data.verification.certificate

import java.security.cert.X509Certificate

class AttestationExtensionProbe {

    fun inspect(chain: List<X509Certificate>): AttestationExtensionResult {
        val attestationCount = chain.count { it.getExtensionValue(KEY_ATTESTATION_OID) != null }
        return AttestationExtensionResult(
            extensionCount = attestationCount,
            hasMultipleAttestationExtensions = attestationCount > 1,
            detail = if (attestationCount <= 1) {
                "Attestation extension appears exactly once in the chain."
            } else {
                "Attestation extension appears $attestationCount times in the chain."
            },
        )
    }

    companion object {
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    }
}

data class AttestationExtensionResult(
    val extensionCount: Int,
    val hasMultipleAttestationExtensions: Boolean,
    val detail: String,
)
