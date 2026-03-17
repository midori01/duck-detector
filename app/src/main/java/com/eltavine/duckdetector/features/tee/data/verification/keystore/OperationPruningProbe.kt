package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

class OperationPruningProbe {

    fun inspect(useStrongBox: Boolean = false): OperationPruningResult {
        val alias = "duck_prune_${System.nanoTime()}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return runCatching {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            )
            generator.initialize(builder.build())
            generator.generateKeyPair()
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: return OperationPruningResult(
                    suspicious = false,
                    operationsCreated = 0,
                    invalidatedOperations = 0,
                    detail = "Could not read private key for pruning probe.",
                )
            val signatures = buildList {
                repeat(18) { index ->
                    val signature = Signature.getInstance("SHA256withECDSA")
                    signature.initSign(privateKey)
                    signature.update("duck_prune_$index".encodeToByteArray())
                    add(signature)
                }
            }
            var invalidated = 0
            signatures.forEach { signature ->
                runCatching { signature.sign() }.onFailure { invalidated++ }
            }
            OperationPruningResult(
                suspicious = signatures.size >= 18 && invalidated == 0,
                operationsCreated = signatures.size,
                invalidatedOperations = invalidated,
                detail = if (invalidated == 0) {
                    "No operation invalidation was observed after creating 18 concurrent signers."
                } else {
                    "Observed $invalidated invalidated operations while saturating signer slots."
                },
            )
        }.getOrElse { throwable ->
            OperationPruningResult(
                suspicious = false,
                operationsCreated = 0,
                invalidatedOperations = 0,
                detail = throwable.message ?: "Operation pruning probe failed.",
            )
        }.also {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }
}

data class OperationPruningResult(
    val suspicious: Boolean,
    val operationsCreated: Int,
    val invalidatedOperations: Int,
    val detail: String,
)
