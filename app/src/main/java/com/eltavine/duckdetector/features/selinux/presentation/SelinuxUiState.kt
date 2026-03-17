package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxCardModel

enum class SelinuxUiStage {
    LOADING,
    READY,
    FAILED,
}

data class SelinuxUiState(
    val stage: SelinuxUiStage,
    val report: SelinuxReport,
    val cardModel: SelinuxCardModel,
)
