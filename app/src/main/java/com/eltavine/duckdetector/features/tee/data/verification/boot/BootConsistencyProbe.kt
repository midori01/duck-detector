package com.eltavine.duckdetector.features.tee.data.verification.boot

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot

class BootConsistencyProbe(
    private val propertyReader: SystemPropertyReader = ReflectionSystemPropertyReader(),
) {

    fun inspect(snapshot: AttestationSnapshot): BootConsistencyResult {
        val property = propertyReader.read(VBMETA_DIGEST_PROP)
        val root = snapshot.rootOfTrust
        if (root == null) {
            return BootConsistencyResult(
                runtimePropsAvailable = property.available,
                runtimeVbmetaDigest = normalizeHex(property.value),
                detail = "Boot consistency check unavailable because attested root of trust was missing.",
            )
        }

        val attestedBootHash = normalizeHex(root.verifiedBootHashHex)
        val runtimeVbmetaDigest = normalizeHex(property.value)
        val verifiedBootHashAllZeros = isAllZeroHex(root.verifiedBootHashHex)
        val verifiedBootKeyAllZeros = isAllZeroHex(root.verifiedBootKeyHex)
        val verifiedStateUnlockedMismatch =
            root.verifiedBootState.equals(
                VERIFIED_BOOT_STATE,
                ignoreCase = true
            ) && root.deviceLocked == false
        val vbmetaDigestMissingWhileAttestedHashPresent =
            attestedBootHash != null && property.available && runtimeVbmetaDigest == null
        val vbmetaDigestMismatch =
            attestedBootHash != null &&
                    runtimeVbmetaDigest != null &&
                    attestedBootHash != runtimeVbmetaDigest

        return BootConsistencyResult(
            vbmetaDigestMismatch = vbmetaDigestMismatch,
            vbmetaDigestMissingWhileAttestedHashPresent = vbmetaDigestMissingWhileAttestedHashPresent,
            verifiedBootHashAllZeros = verifiedBootHashAllZeros,
            verifiedBootKeyAllZeros = verifiedBootKeyAllZeros,
            verifiedStateUnlockedMismatch = verifiedStateUnlockedMismatch,
            runtimePropsAvailable = property.available,
            runtimeVbmetaDigest = runtimeVbmetaDigest,
            detail = buildString {
                val issues = buildList {
                    if (vbmetaDigestMismatch) {
                        add("Attested verifiedBootHash did not match ro.boot.vbmeta.digest.")
                    }
                    if (vbmetaDigestMissingWhileAttestedHashPresent) {
                        add("Attested verifiedBootHash was present, but ro.boot.vbmeta.digest was empty.")
                    }
                    if (verifiedBootHashAllZeros) {
                        add("Attested verifiedBootHash was all zeros.")
                    }
                    if (verifiedBootKeyAllZeros) {
                        add("Attested verifiedBootKey was all zeros.")
                    }
                    if (verifiedStateUnlockedMismatch) {
                        add("Attestation reported Verified while deviceLocked=false.")
                    }
                }
                when {
                    issues.isNotEmpty() -> append(issues.joinToString(separator = " "))
                    !property.available -> append("Boot consistency check could not read ro.boot.vbmeta.digest.")
                    attestedBootHash == null -> append("Attestation did not expose verifiedBootHash for runtime comparison.")
                    runtimeVbmetaDigest == null -> append("Runtime vbmeta digest was unavailable for comparison.")
                    else -> append("Attested verifiedBootHash matched ro.boot.vbmeta.digest.")
                }
            },
        )
    }

    internal companion object {
        internal const val VBMETA_DIGEST_PROP = "ro.boot.vbmeta.digest"
        private const val VERIFIED_BOOT_STATE = "Verified"

        internal fun normalizeHex(raw: String?): String? {
            val cleaned = raw
                ?.filterNot { it.isWhitespace() || it == ':' }
                ?.lowercase()
                ?.takeIf { it.isNotBlank() }
            return cleaned?.takeIf { value ->
                value.all { it in '0'..'9' || it in 'a'..'f' }
            }
        }

        internal fun isAllZeroHex(raw: String?): Boolean {
            val normalized = normalizeHex(raw) ?: return false
            return normalized.isNotEmpty() && normalized.all { it == '0' }
        }
    }
}

data class BootConsistencyResult(
    val vbmetaDigestMismatch: Boolean = false,
    val vbmetaDigestMissingWhileAttestedHashPresent: Boolean = false,
    val verifiedBootHashAllZeros: Boolean = false,
    val verifiedBootKeyAllZeros: Boolean = false,
    val verifiedStateUnlockedMismatch: Boolean = false,
    val runtimePropsAvailable: Boolean = false,
    val runtimeVbmetaDigest: String? = null,
    val detail: String = "Boot consistency check unavailable.",
) {
    val hasHardAnomaly: Boolean
        get() = vbmetaDigestMismatch ||
                vbmetaDigestMissingWhileAttestedHashPresent ||
                verifiedBootHashAllZeros ||
                verifiedBootKeyAllZeros ||
                verifiedStateUnlockedMismatch
}

fun interface SystemPropertyReader {
    fun read(name: String): PropertyReadResult
}

data class PropertyReadResult(
    val available: Boolean,
    val value: String? = null,
)

private class ReflectionSystemPropertyReader : SystemPropertyReader {

    override fun read(name: String): PropertyReadResult {
        return runCatching {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            val value = method.invoke(null, name) as? String
            PropertyReadResult(available = true, value = value)
        }.getOrElse {
            PropertyReadResult(available = false)
        }
    }
}
