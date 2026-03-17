package com.eltavine.duckdetector.features.su.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class SuCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<SuHeaderFactModel>,
    val artifactRows: List<SuDetailRowModel>,
    val contextRows: List<SuDetailRowModel>,
    val impactItems: List<SuImpactItemModel>,
    val methodRows: List<SuDetailRowModel>,
    val scanRows: List<SuDetailRowModel>,
)

data class SuHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class SuDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class SuImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
