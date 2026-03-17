package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppShellStateTest {

    @Test
    fun `null prefs stay in loading gate`() {
        val gateState = resolveStartupGateState(null)

        assertEquals(StartupGateState.LOADING, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `unanswered prefs require startup decision`() {
        val gateState = resolveStartupGateState(
            TeeNetworkPrefs(
                consentAsked = false,
                consentGranted = false,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )

        assertEquals(StartupGateState.REQUIRES_DECISION, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `answered prefs unlock detector creation`() {
        val gateState = resolveStartupGateState(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )

        assertEquals(StartupGateState.READY, gateState)
        assertTrue(shouldCreateDetectorViewModels(gateState))
    }
}
