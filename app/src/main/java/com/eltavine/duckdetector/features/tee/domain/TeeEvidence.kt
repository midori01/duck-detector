package com.eltavine.duckdetector.features.tee.domain

data class TeeEvidenceItem(
    val title: String,
    val body: String,
    val level: TeeSignalLevel,
)

data class TeeEvidenceSection(
    val title: String,
    val items: List<TeeEvidenceItem>,
)
