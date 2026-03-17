package com.eltavine.duckdetector.features.tee.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.features.tee.domain.TeeCertificateItem

enum class TeeFactIcon {
    TRUST,
    CERTIFICATE,
    NETWORK,
    RKP,
    KEY,
    BOOT,
    PATCH,
    DEVICE,
    APP,
    AUTH,
    KEYSTORE,
    TIMING,
    STRONGBOX,
    NATIVE,
    SOTER,
    WARNING,
}

data class TeeHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class TeeHighlightSignalModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class TeeFactRowModel(
    val icon: TeeFactIcon,
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class TeeFactGroupModel(
    val title: String,
    val rows: List<TeeFactRowModel>,
)

data class TeeCertificateSummaryModel(
    val label: String,
    val count: String,
    val certificates: List<TeeCertificateItem>,
)

enum class TeeFooterActionId {
    RESCAN,
    DETAILS,
    CERTIFICATES,
}

data class TeeFooterActionModel(
    val id: TeeFooterActionId,
    val label: String,
    val counter: String? = null,
    val enabled: Boolean = true,
)

data class TeeNetworkStateModel(
    val label: String,
    val summary: String,
    val status: DetectorStatus,
)

data class TeeCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val isExpanded: Boolean,
    val headerFacts: List<TeeHeaderFactModel>,
    val highlightSignals: List<TeeHighlightSignalModel>,
    val factGroups: List<TeeFactGroupModel>,
    val certificateSummary: TeeCertificateSummaryModel,
    val actions: List<TeeFooterActionModel>,
    val networkState: TeeNetworkStateModel,
    val exportText: String,
    val rkpBadgeLabel: String? = null,
)
