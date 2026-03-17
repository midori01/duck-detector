package com.eltavine.duckdetector.features.customrom.presentation

import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomCardModel

enum class CustomRomUiStage {
    LOADING,
    READY,
    FAILED,
}

data class CustomRomUiState(
    val stage: CustomRomUiStage,
    val report: CustomRomReport,
    val cardModel: CustomRomCardModel,
)
