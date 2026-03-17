package com.eltavine.duckdetector.features.memory.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class MemoryCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<MemoryHeaderFactModel>,
    val hookRows: List<MemoryDetailRowModel>,
    val mappingRows: List<MemoryDetailRowModel>,
    val loaderRows: List<MemoryDetailRowModel>,
    val impactItems: List<MemoryImpactItemModel>,
    val methodRows: List<MemoryDetailRowModel>,
    val scanRows: List<MemoryDetailRowModel>,
)

data class MemoryHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class MemoryDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class MemoryImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
