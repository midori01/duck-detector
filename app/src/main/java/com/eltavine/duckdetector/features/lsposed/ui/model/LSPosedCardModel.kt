package com.eltavine.duckdetector.features.lsposed.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class LSPosedCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<LSPosedHeaderFactModel>,
    val runtimeRows: List<LSPosedDetailRowModel>,
    val binderRows: List<LSPosedDetailRowModel>,
    val packageRows: List<LSPosedDetailRowModel>,
    val nativeRows: List<LSPosedDetailRowModel>,
    val impactItems: List<LSPosedImpactItemModel>,
    val methodRows: List<LSPosedDetailRowModel>,
    val scanRows: List<LSPosedDetailRowModel>,
)

data class LSPosedHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class LSPosedDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class LSPosedImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
