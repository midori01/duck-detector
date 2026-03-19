package com.eltavine.duckdetector.features.selinux.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxNativeAuditBridgeTest {

    private val bridge = SelinuxNativeAuditBridge()

    @Test
    fun `parse decodes callback lines and flags`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                CALLBACK_INSTALLED=1
                PROBE_RAN=1
                DENIAL_OBSERVED=1
                ALLOW_OBSERVED=0
                PROBE_MARKER=ddprobe_1_1
                FAILURE_REASON=Direct\ncallback
                LINE=type=1400 audit(0.0:123): avc: denied { write } for scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:object_r:system_file:s0 tclass=file
                LINE=second\tline
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.callbackInstalled)
        assertTrue(snapshot.probeRan)
        assertTrue(snapshot.denialObserved)
        assertEquals("ddprobe_1_1", snapshot.probeMarker)
        assertEquals("Direct\ncallback", snapshot.failureReason)
        assertEquals(2, snapshot.callbackLines.size)
        assertTrue(snapshot.callbackLines.first().contains("avc: denied"))
        assertEquals("second\tline", snapshot.callbackLines.last())
    }
}
