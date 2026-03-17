package com.eltavine.duckdetector.features.playintegrityfix.data.native

data class PlayIntegrityFixNativeTrace(
    val severity: String,
    val label: String,
    val detail: String,
)

data class PlayIntegrityFixNativeSnapshot(
    val available: Boolean = false,
    val nativeProperties: Map<String, String> = emptyMap(),
    val runtimeTraces: List<PlayIntegrityFixNativeTrace> = emptyList(),
) {
    val nativePropertyHitCount: Int
        get() = nativeProperties.values.count { it.isNotBlank() }
}
