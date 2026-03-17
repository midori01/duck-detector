package com.eltavine.duckdetector.features.kernelcheck.presentation

import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckCardModel

enum class KernelCheckUiStage {
    LOADING,
    READY,
    FAILED,
}

data class KernelCheckUiState(
    val stage: KernelCheckUiStage,
    val report: KernelCheckReport,
    val cardModel: KernelCheckCardModel,
)
