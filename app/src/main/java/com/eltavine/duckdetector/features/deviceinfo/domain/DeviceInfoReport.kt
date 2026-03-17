package com.eltavine.duckdetector.features.deviceinfo.domain

enum class DeviceInfoStage {
    LOADING,
    READY,
    FAILED,
}

data class DeviceInfoEntry(
    val label: String,
    val value: String,
    val detailMonospace: Boolean = false,
)

data class DeviceInfoSection(
    val title: String,
    val entries: List<DeviceInfoEntry>,
)

data class DeviceInfoReport(
    val stage: DeviceInfoStage,
    val sections: List<DeviceInfoSection>,
    val errorMessage: String? = null,
) {
    val totalCount: Int
        get() = sections.sumOf { it.entries.size }

    companion object {
        fun loading(): DeviceInfoReport {
            return DeviceInfoReport(
                stage = DeviceInfoStage.LOADING,
                sections = emptyList(),
            )
        }

        fun failed(message: String): DeviceInfoReport {
            return DeviceInfoReport(
                stage = DeviceInfoStage.FAILED,
                sections = emptyList(),
                errorMessage = message,
            )
        }
    }
}
