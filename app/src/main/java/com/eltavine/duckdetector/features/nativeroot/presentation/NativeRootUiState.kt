package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootCardModel

enum class NativeRootUiStage {
    LOADING,
    READY,
    FAILED,
}

data class NativeRootUiState(
    val stage: NativeRootUiStage,
    val report: NativeRootReport,
    val cardModel: NativeRootCardModel,
)
