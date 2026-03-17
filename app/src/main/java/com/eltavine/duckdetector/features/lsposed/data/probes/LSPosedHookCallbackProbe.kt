package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

data class LSPosedHookCallbackProbeResult(
    val signals: List<LSPosedSignal>,
    val hitCount: Int,
)

class LSPosedHookCallbackProbe {

    fun run(): LSPosedHookCallbackProbeResult {
        return evaluate(Thread.getDefaultUncaughtExceptionHandler())
    }

    internal fun evaluate(
        handler: Thread.UncaughtExceptionHandler?,
    ): LSPosedHookCallbackProbeResult {
        val handlerClassName = handler?.javaClass?.name
            ?.takeIf(::containsFrameworkToken)
            ?: return LSPosedHookCallbackProbeResult(
                signals = emptyList(),
                hitCount = 0,
            )

        val signal = LSPosedSignal(
            id = "hook_callback_handler",
            label = "Default exception handler",
            value = "Injected",
            group = LSPosedSignalGroup.RUNTIME,
            severity = LSPosedSignalSeverity.DANGER,
            detail = handlerClassName,
            detailMonospace = true,
        )

        return LSPosedHookCallbackProbeResult(
            signals = listOf(signal),
            hitCount = 1,
        )
    }
}
