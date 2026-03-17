package com.eltavine.duckdetector.core.startup.preload

import android.content.Intent

object EarlyMountPreloadStore {

    @Volatile
    private var intentResult: EarlyMountPreloadResult = EarlyMountPreloadResult.empty()

    @Volatile
    private var bridge: EarlyMountPreloadBridge = EarlyMountPreloadBridge()

    fun capture(intent: Intent?) {
        val captured = EarlyMountPreloadResult.fromIntent(intent)
        if (captured.hasRun) {
            intentResult = captured
        }
    }

    fun currentResult(): EarlyMountPreloadResult {
        return selectPreferred(
            nativeResult = bridge.getStoredResult(),
            intentOnlyResult = intentResult,
        )
    }

    internal fun capture(values: Map<String, Any?>) {
        val captured = EarlyMountPreloadResult.fromCapturedValues(values)
        if (captured.hasRun) {
            intentResult = captured
        }
    }

    internal fun selectPreferred(
        nativeResult: EarlyMountPreloadResult,
        intentOnlyResult: EarlyMountPreloadResult,
    ): EarlyMountPreloadResult {
        return when {
            nativeResult.hasRun -> nativeResult
            intentOnlyResult.hasRun -> intentOnlyResult
            else -> EarlyMountPreloadResult.empty()
        }
    }

    internal fun replaceBridgeForTesting(testBridge: EarlyMountPreloadBridge) {
        bridge = testBridge
    }

    internal fun resetForTesting() {
        intentResult = EarlyMountPreloadResult.empty()
        bridge = EarlyMountPreloadBridge()
    }
}
