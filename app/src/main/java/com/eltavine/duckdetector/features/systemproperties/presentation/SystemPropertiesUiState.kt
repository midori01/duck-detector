package com.eltavine.duckdetector.features.systemproperties.presentation

import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesCardModel

enum class SystemPropertiesUiStage {
    LOADING,
    READY,
    FAILED,
}

data class SystemPropertiesUiState(
    val stage: SystemPropertiesUiStage,
    val report: SystemPropertiesReport,
    val cardModel: SystemPropertiesCardModel,
)
