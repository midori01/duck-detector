package com.eltavine.duckdetector.features.mount.presentation

import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.ui.model.MountCardModel

enum class MountUiStage {
    LOADING,
    READY,
    FAILED,
}

data class MountUiState(
    val stage: MountUiStage,
    val report: MountReport,
    val cardModel: MountCardModel,
)
