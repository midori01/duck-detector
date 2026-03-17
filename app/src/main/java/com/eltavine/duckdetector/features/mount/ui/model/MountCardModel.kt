package com.eltavine.duckdetector.features.mount.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class MountCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<MountHeaderFactModel>,
    val artifactRows: List<MountDetailRowModel>,
    val runtimeRows: List<MountDetailRowModel>,
    val filesystemRows: List<MountDetailRowModel>,
    val consistencyRows: List<MountDetailRowModel>,
    val impactItems: List<MountImpactItemModel>,
    val methodRows: List<MountDetailRowModel>,
    val scanRows: List<MountDetailRowModel>,
)

data class MountHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class MountDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class MountImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
