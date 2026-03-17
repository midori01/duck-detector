package com.eltavine.duckdetector.features.tee.domain

data class TeeReport(
    val stage: TeeScanStage,
    val verdict: TeeVerdict,
    val tier: TeeTier,
    val headline: String,
    val summary: String,
    val collapsedSummary: String,
    val trustRoot: TeeTrustRoot,
    val trustSummary: String,
    val tamperScore: Int,
    val evidenceCount: Int,
    val signals: List<TeeSignal>,
    val sections: List<TeeEvidenceSection>,
    val certificates: List<TeeCertificateItem>,
    val rkpState: TeeRkpState = TeeRkpState(),
    val patchState: TeePatchState = TeePatchState(),
    val soterState: TeeSoterState = TeeSoterState(),
    val networkState: TeeNetworkState = TeeNetworkState(),
    val exportText: String = "",
    val failureMessage: String? = null,
) {
    companion object {
        fun loading(): TeeReport = TeeReport(
            stage = TeeScanStage.LOADING,
            verdict = TeeVerdict.LOADING,
            tier = TeeTier.UNKNOWN,
            headline = "TEE",
            summary = "Collecting local attestation and keystore evidence.",
            collapsedSummary = "Scanning",
            trustRoot = TeeTrustRoot.UNKNOWN,
            trustSummary = "Local trust path pending",
            tamperScore = 0,
            evidenceCount = 0,
            signals = emptyList(),
            sections = emptyList(),
            certificates = emptyList(),
        )

        fun failed(message: String): TeeReport = TeeReport(
            stage = TeeScanStage.FAILED,
            verdict = TeeVerdict.INCONCLUSIVE,
            tier = TeeTier.UNKNOWN,
            headline = "Local TEE verification failed",
            summary = message,
            collapsedSummary = "Scan failed",
            trustRoot = TeeTrustRoot.UNKNOWN,
            trustSummary = "Local trust path unavailable",
            tamperScore = 0,
            evidenceCount = 0,
            signals = emptyList(),
            sections = listOf(
                TeeEvidenceSection(
                    title = "Checks",
                    items = listOf(
                        TeeEvidenceItem(
                            title = "Collection failure",
                            body = message,
                            level = TeeSignalLevel.FAIL,
                        ),
                    ),
                ),
            ),
            certificates = emptyList(),
            failureMessage = message,
        )
    }
}
