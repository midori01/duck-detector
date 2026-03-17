package com.eltavine.duckdetector.features.customrom.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class CustomRomCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<CustomRomHeaderFactModel>,
    val buildRows: List<CustomRomDetailRowModel>,
    val runtimeRows: List<CustomRomDetailRowModel>,
    val frameworkRows: List<CustomRomDetailRowModel>,
    val impactItems: List<CustomRomImpactItemModel>,
    val methodRows: List<CustomRomDetailRowModel>,
    val scanRows: List<CustomRomDetailRowModel>,
)

data class CustomRomHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class CustomRomDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class CustomRomImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
