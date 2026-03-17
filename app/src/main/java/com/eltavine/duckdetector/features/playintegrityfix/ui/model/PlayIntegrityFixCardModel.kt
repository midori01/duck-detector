package com.eltavine.duckdetector.features.playintegrityfix.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class PlayIntegrityFixCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<PlayIntegrityFixHeaderFactModel>,
    val propertyRows: List<PlayIntegrityFixDetailRowModel>,
    val consistencyRows: List<PlayIntegrityFixDetailRowModel>,
    val nativeRows: List<PlayIntegrityFixDetailRowModel>,
    val impactItems: List<PlayIntegrityFixImpactItemModel>,
    val methodRows: List<PlayIntegrityFixDetailRowModel>,
    val scanRows: List<PlayIntegrityFixDetailRowModel>,
)

data class PlayIntegrityFixHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class PlayIntegrityFixDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class PlayIntegrityFixImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
