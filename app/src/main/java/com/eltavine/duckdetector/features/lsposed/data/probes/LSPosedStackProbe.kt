package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

data class LSPosedStackProbeResult(
    val signals: List<LSPosedSignal>,
    val hitCount: Int,
)

class LSPosedStackProbe {

    fun run(): LSPosedStackProbeResult {
        val signals = buildList {
            addAll(
                analyzeStack(
                    id = "current",
                    label = "Current thread stack",
                    frames = Thread.currentThread().stackTrace,
                ),
            )
            addAll(
                analyzeStack(
                    id = "throwable",
                    label = "Synthetic throwable stack",
                    frames = Throwable().stackTrace,
                ),
            )
        }
        return LSPosedStackProbeResult(
            signals = signals,
            hitCount = signals.size,
        )
    }

    private fun analyzeStack(
        id: String,
        label: String,
        frames: Array<StackTraceElement>,
    ): List<LSPosedSignal> {
        val filteredFrames = frames.filterNot { frame ->
            frame.className.startsWith("java.lang.Thread") ||
                    frame.className.startsWith("java.lang.Throwable") ||
                    frame.className.startsWith(javaClass.name)
        }
        val rendered = filteredFrames.joinToString(separator = "\n") { it.toString() }
        val token = STACK_SIGNATURES.firstOrNull { signature ->
            rendered.contains(signature, ignoreCase = true)
        } ?: return emptyList()

        return listOf(
            LSPosedSignal(
                id = "stack_$id",
                label = label,
                value = "Matched",
                group = LSPosedSignalGroup.RUNTIME,
                severity = LSPosedSignalSeverity.DANGER,
                detail = buildString {
                    appendLine("Matched: $token")
                    filteredFrames.take(8).forEach { frame ->
                        appendLine(frame.toString())
                    }
                }.trim(),
                detailMonospace = true,
            ),
        )
    }

    private companion object {
        private val STACK_SIGNATURES = listOf(
            "de.robv.android.xposed.XposedBridge.main",
            "de.robv.android.xposed.XposedBridge.handleHookedMethod",
            "de.robv.android.xposed.XposedBridge.invokeOriginalMethodNative",
            "LSPosedBridge",
            "EdXposedBridge",
            "XC_MethodHook",
            "LSPHooker_",
            "callBeforeHookedMethod",
            "callAfterHookedMethod",
            "invokeOriginalMethod",
            "(LSP)",
        )
    }
}
