package com.eltavine.duckdetector.features.tee.presentation

import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.ui.model.TeeCardModel

enum class TeeUiStage {
    LOADING,
    READY,
    FAILED,
}

data class TeeUiState(
    val stage: TeeUiStage,
    val report: TeeReport,
    val cardModel: TeeCardModel,
    val showDetailsDialog: Boolean = false,
    val showCertificatesDialog: Boolean = false,
)
