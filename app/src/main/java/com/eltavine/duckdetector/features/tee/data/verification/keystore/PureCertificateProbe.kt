package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore

class PureCertificateProbe {

    fun inspect(): PureCertificateResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val tempAlias = "duck_pure_cert_temp_${System.nanoTime()}"
        val certAlias = "duck_pure_cert_${System.nanoTime()}"
        return runCatching {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            )
            generator.initialize(
                KeyGenParameterSpec.Builder(
                    tempAlias,
                    KeyProperties.PURPOSE_SIGN,
                )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build(),
            )
            generator.generateKeyPair()
            val certificate = keyStore.getCertificate(tempAlias)
                ?: return PureCertificateResult(
                    pureCertificateReturnsNullKey = false,
                    detail = "Failed to create temporary certificate for pure certificate probe.",
                )
            keyStore.deleteEntry(tempAlias)
            keyStore.setCertificateEntry(certAlias, certificate)
            val keyResult = runCatching { keyStore.getKey(certAlias, null) }.getOrNull()
            PureCertificateResult(
                pureCertificateReturnsNullKey = keyResult == null,
                detail = if (keyResult == null) {
                    "Pure certificate entry returned null from getKey()."
                } else {
                    "Pure certificate entry unexpectedly returned a Key object."
                },
            )
        }.getOrElse { throwable ->
            PureCertificateResult(
                pureCertificateReturnsNullKey = false,
                detail = throwable.message ?: "Pure certificate probe failed.",
            )
        }.also {
            runCatching { keyStore.deleteEntry(tempAlias) }
            runCatching { keyStore.deleteEntry(certAlias) }
        }
    }
}

data class PureCertificateResult(
    val pureCertificateReturnsNullKey: Boolean,
    val detail: String,
)
