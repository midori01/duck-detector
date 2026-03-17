package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsCardModel

enum class DangerousAppsUiStage {
    LOADING,
    READY,
    FAILED,
}

data class DangerousAppsUiState(
    val stage: DangerousAppsUiStage,
    val report: DangerousAppsReport,
    val cardModel: DangerousAppsCardModel,
)
