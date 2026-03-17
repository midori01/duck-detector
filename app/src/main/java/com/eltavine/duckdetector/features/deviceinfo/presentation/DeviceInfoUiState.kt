package com.eltavine.duckdetector.features.deviceinfo.presentation

import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoReport
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel

enum class DeviceInfoUiStage {
    LOADING,
    READY,
    FAILED,
}

data class DeviceInfoUiState(
    val stage: DeviceInfoUiStage,
    val report: DeviceInfoReport,
    val cardModel: DeviceInfoCardModel,
)
