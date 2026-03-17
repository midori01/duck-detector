package com.eltavine.duckdetector.features.memory.presentation

import com.eltavine.duckdetector.features.memory.domain.MemoryReport
import com.eltavine.duckdetector.features.memory.ui.model.MemoryCardModel

enum class MemoryUiStage {
    LOADING,
    READY,
    FAILED,
}

data class MemoryUiState(
    val stage: MemoryUiStage,
    val report: MemoryReport,
    val cardModel: MemoryCardModel,
)
