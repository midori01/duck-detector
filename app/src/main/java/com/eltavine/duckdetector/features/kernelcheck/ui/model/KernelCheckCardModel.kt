package com.eltavine.duckdetector.features.kernelcheck.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class KernelCheckCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<KernelCheckHeaderFactModel>,
    val identityRows: List<KernelCheckDetailRowModel>,
    val anomalyRows: List<KernelCheckDetailRowModel>,
    val behaviorRows: List<KernelCheckDetailRowModel>,
    val impactItems: List<KernelCheckImpactItemModel>,
    val methodRows: List<KernelCheckDetailRowModel>,
    val scanRows: List<KernelCheckDetailRowModel>,
)

data class KernelCheckHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class KernelCheckDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class KernelCheckImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
