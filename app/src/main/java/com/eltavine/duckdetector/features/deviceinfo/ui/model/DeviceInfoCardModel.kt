package com.eltavine.duckdetector.features.deviceinfo.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class DeviceInfoCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<DeviceInfoHeaderFactModel>,
    val sections: List<DeviceInfoSectionModel>,
)

data class DeviceInfoHeaderFactModel(
    val label: String,
    val value: String,
)

data class DeviceInfoSectionModel(
    val title: String,
    val rows: List<DeviceInfoRowModel>,
)

data class DeviceInfoRowModel(
    val label: String,
    val value: String,
    val detailMonospace: Boolean = false,
)
