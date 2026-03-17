package com.eltavine.duckdetector.features.memory.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MemoryNativeBridgeTest {

    private val bridge = MemoryNativeBridge()

    @Test
    fun `parse decodes escaped detail and booleans`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                GOT_PLT_HOOK=1
                MODIFIED_FUNCTION_COUNT=2
                HIGH_COUNT=1
                MEDIUM_COUNT=1
                FINDING=HOOK	GOT_PLT	Resolved address escaped expected module	HIGH	open resolved to /data/adb/modules/zygisk.so @ 0x1234
                FINDING=MAPS	SMAPS	Swapped executable pages	MEDIUM	/system/lib64/libc.so has 4 kB swapped executable pages\nVmFlags: rd ex mr mw me
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.gotPltHook)
        assertEquals(2, snapshot.modifiedFunctionCount)
        assertEquals(2, snapshot.findings.size)
        assertEquals("HOOK", snapshot.findings[0].section)
        assertTrue(snapshot.findings[1].detail.contains('\n'))
    }

    @Test
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertTrue(snapshot.findings.isEmpty())
        assertEquals(0, snapshot.modifiedFunctionCount)
    }
}
