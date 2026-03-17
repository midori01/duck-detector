package com.eltavine.duckdetector.features.lsposed.presentation

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedCardModel

enum class LSPosedUiStage {
    LOADING,
    READY,
    FAILED,
}

data class LSPosedUiState(
    val stage: LSPosedUiStage,
    val report: LSPosedReport,
    val cardModel: LSPosedCardModel,
)
