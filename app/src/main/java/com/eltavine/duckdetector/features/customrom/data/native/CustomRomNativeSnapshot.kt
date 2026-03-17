package com.eltavine.duckdetector.features.customrom.data.native

import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding

data class CustomRomNativeSnapshot(
    val available: Boolean = false,
    val platformFiles: List<CustomRomFinding> = emptyList(),
    val resourceInjectionFindings: List<CustomRomFinding> = emptyList(),
    val recoveryScripts: List<String> = emptyList(),
    val policyFindings: List<CustomRomFinding> = emptyList(),
    val overlayFindings: List<CustomRomFinding> = emptyList(),
)
