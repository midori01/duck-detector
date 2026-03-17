package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedLogcatProbeTest {

    @Test
    fun `explicit tags and daemon process report danger`() {
        val probe = LSPosedLogcatProbe()
        val result = probe.evaluate(
            mapOf(
                "overview" to LSPosedLogcatCommandOutput(
                    output = """
                        I/LSPosed( 123): bridge attached to target process
                    """.trimIndent(),
                ),
                "tag:LSPosed" to LSPosedLogcatCommandOutput(output = "I/LSPosed( 123): hello"),
                "tag:LSPosed-Bridge" to LSPosedLogcatCommandOutput(),
                "tag:LSPosedService" to LSPosedLogcatCommandOutput(),
                "process" to LSPosedLogcatCommandOutput(
                    output = "I/org.lsposed.daemon( 321): daemon ready",
                ),
            ),
        )

        assertTrue(result.available)
        assertTrue(result.dangerHitCount >= 2)
        assertTrue(result.signals.any { it.id == "logcat_tag_lsposed" })
        assertTrue(result.signals.any { it.id == "logcat_process_lsposed_daemon" })
    }

    @Test
    fun `pattern only hit stays warning`() {
        val probe = LSPosedLogcatProbe()
        val result = probe.evaluate(
            mapOf(
                "overview" to LSPosedLogcatCommandOutput(
                    output = "I/OtherTag( 123): Loading module from cache",
                ),
                "tag:LSPosed" to LSPosedLogcatCommandOutput(),
                "tag:LSPosed-Bridge" to LSPosedLogcatCommandOutput(),
                "tag:LSPosedService" to LSPosedLogcatCommandOutput(),
                "process" to LSPosedLogcatCommandOutput(),
            ),
        )

        assertTrue(result.available)
        assertEquals(1, result.hitCount)
        assertEquals(0, result.dangerHitCount)
        assertEquals(1, result.warningHitCount)
        assertEquals(LSPosedSignalSeverity.WARNING, result.signals.single().severity)
    }

    @Test
    fun `log access denied downgrades to unavailable`() {
        val probe = LSPosedLogcatProbe(
            commandRunner = LSPosedLogcatCommandRunner { _, _ ->
                LSPosedLogcatCommandOutput(errorMessage = "Permission denied: not allowed to read logs")
            },
        )

        val result = probe.run()

        assertFalse(result.available)
        assertTrue(result.signals.isEmpty())
        assertTrue(result.failureReason?.contains("not readable") == true)
    }
}
