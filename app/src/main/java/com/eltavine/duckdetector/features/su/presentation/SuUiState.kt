package com.eltavine.duckdetector.features.su.presentation

import com.eltavine.duckdetector.features.su.domain.SuReport
import com.eltavine.duckdetector.features.su.ui.model.SuCardModel

enum class SuUiStage {
    LOADING,
    READY,
    FAILED,
}

data class SuUiState(
    val stage: SuUiStage,
    val report: SuReport,
    val cardModel: SuCardModel,
)
