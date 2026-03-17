package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedApplicationInfo
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedAuthState
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedDeviceInfo
import com.eltavine.duckdetector.features.tee.data.attestation.AttestedKeyProperties
import com.eltavine.duckdetector.features.tee.data.attestation.RootOfTrustSnapshot
import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult
import com.eltavine.duckdetector.features.tee.data.verification.crl.CrlStatusResult
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkState
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `java hook becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                keystore2Hook = Keystore2HookResult(
                    available = true,
                    javaHookDetected = true,
                    detail = "hooked",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.summary.contains("Java-hook", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Keystore2" && it.body.contains(
                "Java-style"
            )
        })
    }

    @Test
    fun `soft extension anomaly becomes suspicious verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                chainStructure = ChainStructureResult(
                    chainLength = 4,
                    attestationExtensionCount = 2,
                    trustedAttestationIndex = 2,
                    hasMultipleAttestationExtensions = true,
                    detail = "multi",
                ),
            ),
        )

        assertEquals(TeeVerdict.SUSPICIOUS, report.verdict)
        assertTrue(report.sections.single { it.title == "Trust" }.items.any { it.title == "Chain layout" })
        assertTrue(report.summary.contains("nearest the root", ignoreCase = true))
    }

    @Test
    fun `vbmeta digest mismatch becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                bootConsistency = BootConsistencyResult(
                    vbmetaDigestMismatch = true,
                    runtimePropsAvailable = true,
                    runtimeVbmetaDigest = "ffee",
                    detail = "Attested verifiedBootHash did not match ro.boot.vbmeta.digest.",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.signals.any { it.label == "Boot" && it.value == "Mismatch" })
        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Boot consistency" && it.body.contains("Mismatch")
        })
    }

    @Test
    fun `verified state unlocked mismatch becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                bootConsistency = BootConsistencyResult(
                    verifiedStateUnlockedMismatch = true,
                    runtimePropsAvailable = true,
                    detail = "Attestation reported Verified while deviceLocked=false.",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.summary.contains("deviceLocked=false"))
    }

    @Test
    fun `zeroed verified boot hash becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                bootConsistency = BootConsistencyResult(
                    verifiedBootHashAllZeros = true,
                    runtimePropsAvailable = true,
                    detail = "Attested verifiedBootHash was all zeros.",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any { it.title == "Indicators" })
    }

    @Test
    fun `native got hook becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    trickyStoreDetected = true,
                    gotHookDetected = true,
                    trickyStoreMethods = listOf("GOT_HOOK"),
                    trickyStoreDetails = "got hook",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.summary.contains("GOT", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" && it.body.contains("GOT hook")
        })
    }

    @Test
    fun `native syscall mismatch only stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    syscallMismatchDetected = true,
                    trickyStoreMethods = listOf("SYSCALL_MISMATCH"),
                    trickyStoreDetails = "sys mismatch",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Indicators" && it.body == "0 hard • 0 soft"
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" &&
                    it.body.contains("Syscall mismatch") &&
                    it.body.contains("vendor binder/libc", ignoreCase = true) &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `device ids omitted from attestation are not shown as unavailable`() {
        val report = reducer.reduce(
            baseArtifacts(
                deviceInfo = AttestedDeviceInfo(),
                idAttestation = IdAttestationResult(
                    mismatches = emptyList(),
                    unavailableFields = listOf(
                        "brand",
                        "device",
                        "product",
                        "manufacturer",
                        "model"
                    ),
                    detail = "Attestation did not expose any comparable device identifiers.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Device IDs" && it.body == "Not included in attestation"
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ID attestation" && it.body == "No comparable IDs exposed"
        })
    }

    @Test
    fun `graded oversized challenge lists accepted sizes`() {
        val report = reducer.reduce(
            baseArtifacts(
                oversizedChallenge = OversizedChallengeResult(
                    acceptedOversizedChallenge = true,
                    acceptedSizes = listOf(256, 512, 4096),
                    attemptedSizes = listOf(256, 512, 4096),
                    detail = "Attestation accepted oversized challenge sizes: 256B, 512B, 4096B.",
                ),
            ),
        )

        assertEquals(TeeVerdict.SUSPICIOUS, report.verdict)
        assertTrue(report.summary.contains("256B"))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Oversized challenge" && it.body.contains("256B") && it.body.contains("4096B")
        })
    }

    @Test
    fun `disabled crl state uses settings wording`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Online CRL disabled in Settings.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" && it.body.contains("Disabled in Settings")
        })
        assertTrue(report.signals.any { it.label == "CRL" && it.value == "Disabled" })
    }

    @Test
    fun `refresh failed crl state is surfaced as degraded`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ERROR,
                    summary = "CRL refresh timed out.",
                    detail = "CRL refresh timed out.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" &&
                    it.body.contains("Refresh failed") &&
                    it.body.contains("timed out")
        })
        assertTrue(report.signals.any { it.label == "CRL" && it.value == "Error" && it.level == TeeSignalLevel.WARN })
    }

    private fun baseArtifacts(
        tier: TeeTier = TeeTier.TEE,
        chainStructure: ChainStructureResult = ChainStructureResult(
            chainLength = 3,
            attestationExtensionCount = 1,
            trustedAttestationIndex = 1,
            detail = "base",
        ),
        keystore2Hook: Keystore2HookResult = Keystore2HookResult(
            available = true,
            nativeStyleResponse = true,
            detail = "native",
        ),
        deviceInfo: AttestedDeviceInfo = AttestedDeviceInfo(brand = "duck", device = "duck"),
        idAttestation: IdAttestationResult = IdAttestationResult(
            mismatches = emptyList(),
            unavailableFields = emptyList(),
            detail = "ok",
        ),
        oversizedChallenge: OversizedChallengeResult = OversizedChallengeResult(
            acceptedOversizedChallenge = false,
            acceptedSizes = emptyList(),
            attemptedSizes = listOf(256, 512, 4096),
            detail = "ok",
        ),
        native: NativeTeeSnapshot = NativeTeeSnapshot(
            trickyStoreDetails = "clean",
        ),
        bootConsistency: BootConsistencyResult = BootConsistencyResult(
            runtimePropsAvailable = true,
            runtimeVbmetaDigest = "12345678",
            detail = "Attested verifiedBootHash matched ro.boot.vbmeta.digest.",
        ),
        networkState: TeeNetworkState = TeeNetworkState(
            mode = TeeNetworkMode.INACTIVE,
            summary = "Offline-only verification",
        ),
    ): TeeScanArtifacts {
        return TeeScanArtifacts(
            snapshot = AttestationSnapshot(
                tier = tier,
                attestationVersion = 4,
                keymasterVersion = 4,
                attestationTier = tier,
                keymasterTier = tier,
                challengeVerified = true,
                challengeSummary = "len=32",
                rootOfTrust = RootOfTrustSnapshot(
                    verifiedBootKeyHex = "abcd",
                    deviceLocked = true,
                    verifiedBootState = "Verified",
                    verifiedBootHashHex = "12345678",
                ),
                osVersion = "14.0.0",
                osPatchLevel = "2026-03",
                vendorPatchLevel = "2026-03-05",
                bootPatchLevel = "2026-03-05",
                keyProperties = AttestedKeyProperties(
                    algorithm = "EC",
                    keySize = 256,
                    ecCurve = "P-256",
                    origin = "Generated",
                    rollbackResistant = true,
                ),
                authState = AttestedAuthState(noAuthRequired = true),
                applicationInfo = AttestedApplicationInfo(packageNames = listOf("com.eltavine.duckdetector")),
                deviceInfo = deviceInfo,
                deviceUniqueAttestation = false,
                trustedAttestationIndex = 1,
                rawCertificates = emptyList(),
                displayCertificates = emptyList(),
            ),
            trust = CertificateTrustResult(
                trustRoot = TeeTrustRoot.GOOGLE,
                chainLength = 3,
                chainSignatureValid = true,
                googleRootMatched = true,
            ),
            chainStructure = chainStructure,
            rkp = TeeRkpState(),
            crl = CrlStatusResult(
                networkState = networkState,
            ),
            pairConsistency = KeyPairConsistencyResult(
                keyMatchesCertificate = true,
                medianSignMicros = 1800,
                detail = "ok",
            ),
            lifecycle = KeyLifecycleResult(
                created = true,
                deleteRemovedAlias = true,
                regeneratedFreshMaterial = true,
                detail = "ok",
            ),
            timing = TimingAnomalyResult(
                suspicious = false,
                medianMicros = 1800,
                detail = "ok",
            ),
            oversizedChallenge = oversizedChallenge,
            keyboxImport = KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = KeyboxImportProbe.FIXTURE_MARKER,
                detail = "skipped",
            ),
            keystore2Hook = keystore2Hook,
            pureCertificate = PureCertificateResult(
                pureCertificateReturnsNullKey = true,
                detail = "ok",
            ),
            updateSubcomponent = UpdateSubcomponentResult(
                updateSucceeded = true,
                keyNotFoundStyleFailure = false,
                detail = "ok",
            ),
            pruning = OperationPruningResult(
                suspicious = false,
                operationsCreated = 18,
                invalidatedOperations = 2,
                detail = "ok",
            ),
            dualAlgorithm = DualAlgorithmChainResult(
                mismatchDetected = false,
                detail = "ok",
            ),
            idAttestation = idAttestation,
            strongBox = StrongBoxBehaviorResult(
                requested = false,
                advertised = false,
                available = false,
                detail = "skipped",
            ),
            native = native,
            soter = TeeSoterState(),
            bootConsistency = bootConsistency,
        )
    }
}
