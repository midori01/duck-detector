package com.eltavine.duckdetector.features.systemproperties.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class SystemPropertiesCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<SystemPropertiesHeaderFactModel>,
    val coreRows: List<SystemPropertiesDetailRowModel>,
    val bootRows: List<SystemPropertiesDetailRowModel>,
    val buildRows: List<SystemPropertiesDetailRowModel>,
    val sourceRows: List<SystemPropertiesDetailRowModel>,
    val consistencyRows: List<SystemPropertiesDetailRowModel>,
    val infoRows: List<SystemPropertiesDetailRowModel>,
    val impactItems: List<SystemPropertiesImpactItemModel>,
    val methodRows: List<SystemPropertiesDetailRowModel>,
    val scanRows: List<SystemPropertiesDetailRowModel>,
)

data class SystemPropertiesHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class SystemPropertiesDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class SystemPropertiesImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
