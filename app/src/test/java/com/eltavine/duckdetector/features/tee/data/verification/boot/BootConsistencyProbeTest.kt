package com.eltavine.duckdetector.features.tee.data.verification.boot

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedApplicationInfo
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedAuthState
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedDeviceInfo
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedKeyProperties
import com.eltavine.duckdetector.features.tee.data.attestation.RootOfTrustSnapshot
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootConsistencyProbeTest {

    @Test
    fun `normalizes attested and runtime hex before comparing`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "AA:BB CC")
            },
        )

        val result = probe.inspect(snapshot(rootOfTrust = rootOfTrust(hash = "aabbcc")))

        assertFalse(result.vbmetaDigestMismatch)
        assertTrue(result.detail.contains("matched", ignoreCase = true))
    }

    @Test
    fun `attested hash with empty runtime digest becomes anomaly`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "")
            },
        )

        val result = probe.inspect(snapshot(rootOfTrust = rootOfTrust(hash = "aabb")))

        assertTrue(result.vbmetaDigestMissingWhileAttestedHashPresent)
    }

    @Test
    fun `missing root of trust stays unavailable`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "aabb")
            },
        )

        val result = probe.inspect(snapshot(rootOfTrust = null))

        assertFalse(result.hasHardAnomaly)
        assertTrue(result.detail.contains("missing", ignoreCase = true))
    }

    @Test
    fun `verified plus unlocked becomes anomaly`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "aabb")
            },
        )

        val result = probe.inspect(
            snapshot(
                rootOfTrust = RootOfTrustSnapshot(
                    verifiedBootKeyHex = "11",
                    deviceLocked = false,
                    verifiedBootState = "Verified",
                    verifiedBootHashHex = "aabb",
                ),
            ),
        )

        assertTrue(result.verifiedStateUnlockedMismatch)
    }

    @Test
    fun `all zero key and hash become anomalies`() {
        val probe = BootConsistencyProbe(
            propertyReader = SystemPropertyReader {
                PropertyReadResult(available = true, value = "00")
            },
        )

        val result = probe.inspect(
            snapshot(
                rootOfTrust = RootOfTrustSnapshot(
                    verifiedBootKeyHex = "00:00",
                    deviceLocked = true,
                    verifiedBootState = "Verified",
                    verifiedBootHashHex = "0000",
                ),
            ),
        )

        assertTrue(result.verifiedBootKeyAllZeros)
        assertTrue(result.verifiedBootHashAllZeros)
    }

    private fun rootOfTrust(hash: String): RootOfTrustSnapshot {
        return RootOfTrustSnapshot(
            verifiedBootKeyHex = "112233",
            deviceLocked = true,
            verifiedBootState = "Verified",
            verifiedBootHashHex = hash,
        )
    }

    private fun snapshot(rootOfTrust: RootOfTrustSnapshot?): AttestationSnapshot {
        return AttestationSnapshot(
            tier = TeeTier.TEE,
            attestationVersion = 4,
            keymasterVersion = 4,
            attestationTier = TeeTier.TEE,
            keymasterTier = TeeTier.TEE,
            challengeVerified = true,
            challengeSummary = "len=32",
            rootOfTrust = rootOfTrust,
            osVersion = "14.0.0",
            osPatchLevel = "2026-03",
            vendorPatchLevel = null,
            bootPatchLevel = null,
            keyProperties = AttestedKeyProperties(),
            authState = AttestedAuthState(),
            applicationInfo = AttestedApplicationInfo(),
            deviceInfo = AttestedDeviceInfo(),
            deviceUniqueAttestation = false,
            trustedAttestationIndex = 0,
            rawCertificates = emptyList(),
            displayCertificates = emptyList(),
        )
    }
}
