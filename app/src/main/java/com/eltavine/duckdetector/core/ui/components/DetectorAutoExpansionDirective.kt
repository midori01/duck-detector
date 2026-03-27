package com.eltavine.duckdetector.core.ui.components

import androidx.compose.runtime.compositionLocalOf

data class DetectorAutoExpansionDirective(
    val titles: Set<String> = emptySet(),
    val onConsumed: (String) -> Unit = {},
) {
    fun shouldExpand(title: String): Boolean {
        return title in titles
    }
}

val LocalDetectorAutoExpansionDirective =
    compositionLocalOf { DetectorAutoExpansionDirective() }
