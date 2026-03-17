package com.eltavine.duckdetector.features.tee.data.verification.strongbox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StrongBoxProbeTest {

    @Test
    fun `pixel profile uses 128 concurrent signing handle threshold`() {
        assertEquals(
            128,
            expectedConcurrentSigningHandleLimit(
                brand = "google",
                manufacturer = "Google",
                model = "Pixel 9 Pro",
            ),
        )
    }

    @Test
    fun `non pixel profile keeps 16 concurrent signing handle threshold`() {
        assertEquals(
            16,
            expectedConcurrentSigningHandleLimit(
                brand = "samsung",
                manufacturer = "samsung",
                model = "SM-S9280",
            ),
        )
    }

    @Test
    fun `pixel device profile requires pixel model plus google brand or manufacturer`() {
        assertTrue(isPixelDeviceProfile("google", "Google", "Pixel 8"))
        assertTrue(isPixelDeviceProfile("android", "Google", "Pixel Fold"))
        assertFalse(isPixelDeviceProfile("google", "Google", "PixelExperience"))
        assertFalse(isPixelDeviceProfile("google", "xiaomi", "MIX 4"))
    }
}
