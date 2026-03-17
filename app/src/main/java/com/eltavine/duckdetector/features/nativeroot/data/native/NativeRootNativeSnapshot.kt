package com.eltavine.duckdetector.features.nativeroot.data.native

data class NativeRootNativeFinding(
    val group: String,
    val severity: String,
    val label: String,
    val value: String,
    val detail: String,
)

data class NativeRootNativeSnapshot(
    val available: Boolean = false,
    val kernelSuDetected: Boolean = false,
    val aPatchDetected: Boolean = false,
    val magiskDetected: Boolean = false,
    val susfsDetected: Boolean = false,
    val kernelSuVersion: Long = 0L,
    val prctlProbeHit: Boolean = false,
    val susfsProbeHit: Boolean = false,
    val pathHitCount: Int = 0,
    val pathCheckCount: Int = 0,
    val processHitCount: Int = 0,
    val processCheckedCount: Int = 0,
    val processDeniedCount: Int = 0,
    val kernelHitCount: Int = 0,
    val kernelSourceCount: Int = 0,
    val propertyHitCount: Int = 0,
    val propertyCheckCount: Int = 0,
    val findings: List<NativeRootNativeFinding> = emptyList(),
)
