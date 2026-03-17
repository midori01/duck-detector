package com.eltavine.duckdetector.features.su.domain

enum class SuStage {
    LOADING,
    READY,
    FAILED,
}

enum class SuMethodOutcome {
    CLEAN,
    DETECTED,
    SUPPORT,
}

data class SuDaemonFinding(
    val name: String,
    val path: String,
)

data class SuMethodResult(
    val label: String,
    val summary: String,
    val outcome: SuMethodOutcome,
    val detail: String? = null,
)

data class SuReport(
    val stage: SuStage,
    val suBinaries: List<String>,
    val daemons: List<SuDaemonFinding>,
    val selfContext: String,
    val selfContextAbnormal: Boolean,
    val suspiciousProcesses: List<String>,
    val nativeAvailable: Boolean,
    val checkedSuPathCount: Int,
    val checkedDaemonPathCount: Int,
    val checkedProcessCount: Int,
    val deniedProcessCount: Int,
    val methods: List<SuMethodResult>,
    val errorMessage: String? = null,
) {
    val hasRootIndicators: Boolean
        get() = suBinaries.isNotEmpty() || daemons.isNotEmpty() || selfContextAbnormal || suspiciousProcesses.isNotEmpty()

    companion object {
        fun loading(): SuReport {
            return SuReport(
                stage = SuStage.LOADING,
                suBinaries = emptyList(),
                daemons = emptyList(),
                selfContext = "",
                selfContextAbnormal = false,
                suspiciousProcesses = emptyList(),
                nativeAvailable = true,
                checkedSuPathCount = 0,
                checkedDaemonPathCount = 0,
                checkedProcessCount = 0,
                deniedProcessCount = 0,
                methods = emptyList(),
            )
        }

        fun failed(message: String): SuReport {
            return SuReport(
                stage = SuStage.FAILED,
                suBinaries = emptyList(),
                daemons = emptyList(),
                selfContext = "",
                selfContextAbnormal = false,
                suspiciousProcesses = emptyList(),
                nativeAvailable = false,
                checkedSuPathCount = 0,
                checkedDaemonPathCount = 0,
                checkedProcessCount = 0,
                deniedProcessCount = 0,
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
