package com.eltavine.duckdetector.features.nativeroot.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class NativeRootCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<NativeRootHeaderFactModel>,
    val nativeRows: List<NativeRootDetailRowModel>,
    val runtimeRows: List<NativeRootDetailRowModel>,
    val kernelRows: List<NativeRootDetailRowModel>,
    val propertyRows: List<NativeRootDetailRowModel>,
    val impactItems: List<NativeRootImpactItemModel>,
    val methodRows: List<NativeRootDetailRowModel>,
    val scanRows: List<NativeRootDetailRowModel>,
)

data class NativeRootHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class NativeRootDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class NativeRootImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
