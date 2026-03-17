package com.eltavine.duckdetector.features.zygisk.data.fdtrap

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ZygiskFdTrapDetectionResultTest {

    @Test
    fun `maps clean result`() {
        val result = ZygiskFdTrapDetectionResult.fromResultCode(
            ZygiskFdTrapNativeBridge.RESULT_CLEAN,
            "descriptor survived cleanly",
        )

        assertTrue(result.available)
        assertFalse(result.detected)
        assertEquals("Clean", result.methodName)
    }

    @Test
    fun `maps ebadf and corruption variants as detected`() {
        val ebadf = ZygiskFdTrapDetectionResult.fromResultCode(
            ZygiskFdTrapNativeBridge.RESULT_EBADF,
            "closed",
        )
        val corruption = ZygiskFdTrapDetectionResult.fromResultCode(
            ZygiskFdTrapNativeBridge.RESULT_CORRUPTION,
            "mismatch",
        )
        val procfs = ZygiskFdTrapDetectionResult.fromResultCode(
            ZygiskFdTrapNativeBridge.RESULT_PROCFS_ANOMALY,
            "procfs drift",
        )

        assertTrue(ebadf.detected)
        assertTrue(corruption.detected)
        assertTrue(procfs.detected)
        assertEquals("EBADF", ebadf.methodName)
        assertEquals("Corruption", corruption.methodName)
        assertEquals("Procfs anomaly", procfs.methodName)
    }

    @Test
    fun `maps bind and native failures as unavailable support`() {
        val bindFailure = ZygiskFdTrapDetectionResult.fromResultCode(
            ZygiskFdTrapNativeBridge.RESULT_BIND_FAILED,
            "bind failed",
        )
        val nativeUnavailable = ZygiskFdTrapDetectionResult.fromResultCode(
            ZygiskFdTrapNativeBridge.RESULT_NATIVE_UNAVAILABLE,
            "native unavailable",
        )

        assertFalse(bindFailure.available)
        assertFalse(bindFailure.detected)
        assertEquals("Service bind failed", bindFailure.summary)
        assertFalse(nativeUnavailable.available)
        assertEquals("Native helper unavailable", nativeUnavailable.summary)
    }
}
