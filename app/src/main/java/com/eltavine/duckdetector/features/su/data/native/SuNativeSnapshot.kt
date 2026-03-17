package com.eltavine.duckdetector.features.su.data.native

data class SuNativeSnapshot(
    val available: Boolean = false,
    val selfContext: String = "",
    val selfContextAbnormal: Boolean = false,
    val suspiciousProcesses: List<String> = emptyList(),
    val checkedProcesses: Int = 0,
    val deniedProcesses: Int = 0,
)
