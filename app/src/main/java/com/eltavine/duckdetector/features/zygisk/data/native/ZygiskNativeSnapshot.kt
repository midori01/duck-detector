package com.eltavine.duckdetector.features.zygisk.data.native

data class ZygiskNativeTrace(
    val group: String,
    val severity: String,
    val label: String,
    val detail: String,
)

data class ZygiskNativeSnapshot(
    val available: Boolean = false,
    val heapAvailable: Boolean = false,
    val seccompSupported: Boolean = false,
    val tracerPid: Int = 0,
    val strongHitCount: Int = 0,
    val heuristicHitCount: Int = 0,
    val solistHitCount: Int = 0,
    val vmapHitCount: Int = 0,
    val atexitHitCount: Int = 0,
    val smapsHitCount: Int = 0,
    val namespaceHitCount: Int = 0,
    val linkerHookHitCount: Int = 0,
    val stackLeakHitCount: Int = 0,
    val seccompHitCount: Int = 0,
    val heapHitCount: Int = 0,
    val threadHitCount: Int = 0,
    val fdHitCount: Int = 0,
    val traces: List<ZygiskNativeTrace> = emptyList(),
)
