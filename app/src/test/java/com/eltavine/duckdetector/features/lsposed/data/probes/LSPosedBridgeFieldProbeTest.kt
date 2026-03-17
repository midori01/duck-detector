package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedBridgeFieldProbeTest {

    private val probe = LSPosedBridgeFieldProbe()

    @Test
    fun `bridge fields surface as runtime evidence`() {
        val result = probe.evaluate("de.robv.android.xposed.XposedBridge")

        assertEquals(2, result.hitCount)
        assertTrue(result.signals.all { it.severity == LSPosedSignalSeverity.DANGER })
        assertTrue(result.signals.any { it.value == "disableHooks" })
        assertTrue(result.signals.any { it.value == "sHookedMethodCallbacks" })
    }

    @Test
    fun `missing bridge class stays clear`() {
        val result = probe.evaluate("de.robv.android.xposed.MissingBridge")

        assertTrue(result.signals.isEmpty())
        assertEquals(0, result.hitCount)
    }
}
