package com.eltavine.duckdetector.features.tee.data.verification.certificate

import android.content.Context
import com.eltavine.duckdetector.R
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class GoogleAttestationRootStore(
    context: Context,
) {

    private val appContext = context.applicationContext
    private val certificateFactory = CertificateFactory.getInstance("X.509")

    val certificates: List<X509Certificate> by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        listOf(
            R.raw.google_attestation_root_rsa,
            R.raw.google_attestation_root_ecdsa,
        ).map { resId ->
            appContext.resources.openRawResource(resId).use { stream ->
                certificateFactory.generateCertificate(stream) as X509Certificate
            }
        }
    }

    val publicKeyFingerprints: Set<String> by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        certificates.mapTo(linkedSetOf()) { cert ->
            cert.publicKey.encoded.sha256()
        }
    }

    fun contains(cert: X509Certificate): Boolean {
        val fingerprint = cert.publicKey.encoded.sha256()
        if (fingerprint in publicKeyFingerprints) {
            return true
        }
        return certificates.any { root ->
            root.encoded.contentEquals(cert.encoded)
        }
    }

    private fun ByteArray.sha256(): String {
        return MessageDigest.getInstance("SHA-256")
            .digest(this)
            .joinToString(separator = "") { byte -> "%02x".format(byte) }
    }
}
