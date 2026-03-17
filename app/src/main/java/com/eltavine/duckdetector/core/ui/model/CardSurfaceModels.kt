package com.eltavine.duckdetector.core.ui.model

data class MetricChipModel(
    val label: String,
    val value: String,
    val status: DetectorStatus = DetectorStatus.allClear(),
)

data class HighlightItemModel(
    val title: String,
    val detail: String,
    val status: DetectorStatus,
)

data class ContextItemModel(
    val label: String,
    val value: String,
)

data class ActionItemModel(
    val label: String,
    val counter: String? = null,
)
