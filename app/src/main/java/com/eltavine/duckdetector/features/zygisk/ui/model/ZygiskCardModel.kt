package com.eltavine.duckdetector.features.zygisk.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class ZygiskCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<ZygiskHeaderFactModel>,
    val stateRows: List<ZygiskDetailRowModel>,
    val impactItems: List<ZygiskImpactItemModel>,
    val methodRows: List<ZygiskDetailRowModel>,
    val signalRows: List<ZygiskDetailRowModel>,
    val references: List<String>,
)

data class ZygiskHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class ZygiskDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class ZygiskImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
