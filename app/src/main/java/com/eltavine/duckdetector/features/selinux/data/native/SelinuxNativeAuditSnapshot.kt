package com.eltavine.duckdetector.features.selinux.data.native

data class SelinuxNativeAuditSnapshot(
    val available: Boolean = false,
    val callbackInstalled: Boolean = false,
    val probeRan: Boolean = false,
    val denialObserved: Boolean = false,
    val allowObserved: Boolean = false,
    val probeMarker: String? = null,
    val failureReason: String? = null,
    val callbackLines: List<String> = emptyList(),
)
