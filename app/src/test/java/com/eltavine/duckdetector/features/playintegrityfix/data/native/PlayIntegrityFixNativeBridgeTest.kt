package com.eltavine.duckdetector.features.playintegrityfix.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PlayIntegrityFixNativeBridgeTest {

    private val bridge = PlayIntegrityFixNativeBridge()

    @Test
    fun `parse decodes native properties and runtime traces`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                PROP=persist.sys.pihooks_FINGERPRINT|google/husky/husky:14/AP1A.240305.019/1234567:user/release-keys
                TRACE=WARNING	pixelprops runtime	pixelprops injected into current process\nmaps: /system/lib64/libpixelprops.so
                TRACE=DANGER	keystore deleted trace	keystore hook artifact (deleted)
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertEquals(
            "google/husky/husky:14/AP1A.240305.019/1234567:user/release-keys",
            snapshot.nativeProperties["persist.sys.pihooks_FINGERPRINT"],
        )
        assertEquals(2, snapshot.runtimeTraces.size)
        assertEquals("WARNING", snapshot.runtimeTraces[0].severity)
        assertTrue(snapshot.runtimeTraces[0].detail.contains('\n'))
        assertEquals("keystore deleted trace", snapshot.runtimeTraces[1].label)
    }

    @Test
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertTrue(snapshot.nativeProperties.isEmpty())
        assertTrue(snapshot.runtimeTraces.isEmpty())
    }
}
