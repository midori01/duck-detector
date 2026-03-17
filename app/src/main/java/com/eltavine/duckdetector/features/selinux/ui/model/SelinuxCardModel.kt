package com.eltavine.duckdetector.features.selinux.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class SelinuxCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<SelinuxHeaderFactModel>,
    val stateRows: List<SelinuxDetailRowModel>,
    val impactItems: List<SelinuxImpactItemModel>,
    val methodRows: List<SelinuxDetailRowModel>,
    val policyRows: List<SelinuxDetailRowModel>,
    val policyNotes: List<SelinuxImpactItemModel>,
    val auditRows: List<SelinuxDetailRowModel>,
    val auditNotes: List<SelinuxImpactItemModel>,
    val deviceRows: List<SelinuxDetailRowModel>,
    val references: List<String>,
)

data class SelinuxHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class SelinuxDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
)

data class SelinuxImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
