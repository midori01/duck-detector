package com.eltavine.duckdetector.features.lsposed.data.native

data class LSPosedNativeTrace(
    val group: String,
    val severity: String,
    val label: String,
    val detail: String,
)

data class LSPosedNativeSnapshot(
    val available: Boolean = false,
    val heapAvailable: Boolean = false,
    val mapsHitCount: Int = 0,
    val mapsScannedLines: Int = 0,
    val heapHitCount: Int = 0,
    val heapScannedRegions: Int = 0,
    val traces: List<LSPosedNativeTrace> = emptyList(),
)
