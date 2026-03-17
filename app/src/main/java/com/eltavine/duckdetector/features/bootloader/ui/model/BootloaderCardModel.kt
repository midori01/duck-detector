package com.eltavine.duckdetector.features.bootloader.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class BootloaderCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<BootloaderHeaderFactModel>,
    val stateRows: List<BootloaderDetailRowModel>,
    val attestationRows: List<BootloaderDetailRowModel>,
    val propertyRows: List<BootloaderDetailRowModel>,
    val consistencyRows: List<BootloaderDetailRowModel>,
    val impactItems: List<BootloaderImpactItemModel>,
    val methodRows: List<BootloaderDetailRowModel>,
    val scanRows: List<BootloaderDetailRowModel>,
)

data class BootloaderHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class BootloaderDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class BootloaderImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
