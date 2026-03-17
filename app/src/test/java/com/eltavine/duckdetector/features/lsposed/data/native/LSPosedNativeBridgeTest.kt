package com.eltavine.duckdetector.features.lsposed.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedNativeBridgeTest {

    private val bridge = LSPosedNativeBridge()

    @Test
    fun `parse decodes snapshot entries and traces`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                HEAP_AVAILABLE=1
                MAPS_HITS=2
                MAPS_SCANNED=412
                HEAP_HITS=1
                HEAP_SCANNED=4
                TRACE=MAPS	DANGER	LSPosed runtime mapping	/system/framework/lsposed.dex
                TRACE=HEAP	DANGER	Heap residual	MAPS\nKeyword sample matched in dalvik-main space
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.heapAvailable)
        assertEquals(2, snapshot.mapsHitCount)
        assertEquals(4, snapshot.heapScannedRegions)
        assertEquals(2, snapshot.traces.size)
        assertEquals("HEAP", snapshot.traces.last().group)
        assertTrue(snapshot.traces.last().detail.contains('\n'))
    }

    @Test
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertFalse(snapshot.heapAvailable)
        assertTrue(snapshot.traces.isEmpty())
        assertEquals(0, snapshot.mapsHitCount)
    }
}
