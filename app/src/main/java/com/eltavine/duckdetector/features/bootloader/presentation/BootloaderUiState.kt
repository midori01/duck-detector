package com.eltavine.duckdetector.features.bootloader.presentation

import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderCardModel

enum class BootloaderUiStage {
    LOADING,
    READY,
    FAILED,
}

data class BootloaderUiState(
    val stage: BootloaderUiStage,
    val report: BootloaderReport,
    val cardModel: BootloaderCardModel,
)
