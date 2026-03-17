package com.eltavine.duckdetector.features.customrom.data.repository

import com.eltavine.duckdetector.features.customrom.data.native.CustomRomNativeSnapshot
import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CustomRomPlatformFileResolverTest {

    @Test
    fun `native unavailable falls back to Java file scan`() {
        val findings = CustomRomPlatformFileResolver.resolve(
            nativeSnapshot = CustomRomNativeSnapshot(available = false),
            isPixel = false,
            shouldSkip = ::shouldSkip,
            fileExists = { path -> path == "/system/framework/crdroid-res.apk" },
        )

        assertEquals(
            listOf(
                CustomRomFinding(
                    romName = "crDroid",
                    signal = "crdroid-res.apk",
                    detail = "/system/framework/crdroid-res.apk",
                ),
            ),
            findings,
        )
    }

    @Test
    fun `pixel experience fallback is skipped on Pixel devices`() {
        val findings = CustomRomPlatformFileResolver.resolve(
            nativeSnapshot = CustomRomNativeSnapshot(available = false),
            isPixel = true,
            shouldSkip = ::shouldSkip,
            fileExists = { path -> path == "/system/framework/org.pixelexperience.platform-res.apk" },
        )

        assertTrue(findings.isEmpty())
    }

    @Test
    fun `native findings are preserved when native scan is available`() {
        val nativeFinding = CustomRomFinding(
            romName = "LineageOS",
            signal = "org.lineageos.platform-res.apk",
            detail = "/system/framework/org.lineageos.platform-res.apk",
        )

        val findings = CustomRomPlatformFileResolver.resolve(
            nativeSnapshot = CustomRomNativeSnapshot(
                available = true,
                platformFiles = listOf(nativeFinding),
            ),
            isPixel = false,
            shouldSkip = ::shouldSkip,
            fileExists = { false },
        )

        assertEquals(listOf(nativeFinding), findings)
    }

    private fun shouldSkip(romName: String, isPixel: Boolean): Boolean {
        return isPixel && romName == "PixelExperience"
    }
}
