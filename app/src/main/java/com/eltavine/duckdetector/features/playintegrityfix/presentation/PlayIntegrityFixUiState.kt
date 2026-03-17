package com.eltavine.duckdetector.features.playintegrityfix.presentation

import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixReport
import com.eltavine.duckdetector.features.playintegrityfix.ui.model.PlayIntegrityFixCardModel

enum class PlayIntegrityFixUiStage {
    LOADING,
    READY,
    FAILED,
}

data class PlayIntegrityFixUiState(
    val stage: PlayIntegrityFixUiStage,
    val report: PlayIntegrityFixReport,
    val cardModel: PlayIntegrityFixCardModel,
)
