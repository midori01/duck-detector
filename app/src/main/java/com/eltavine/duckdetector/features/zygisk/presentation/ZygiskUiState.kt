package com.eltavine.duckdetector.features.zygisk.presentation

import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskCardModel

enum class ZygiskUiStage {
    LOADING,
    READY,
    FAILED,
}

data class ZygiskUiState(
    val stage: ZygiskUiStage,
    val report: ZygiskReport,
    val cardModel: ZygiskCardModel,
)
