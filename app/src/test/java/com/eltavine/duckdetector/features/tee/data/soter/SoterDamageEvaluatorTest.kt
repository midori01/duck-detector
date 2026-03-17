package com.eltavine.duckdetector.features.tee.data.soter

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SoterDamageEvaluatorTest {

    private val evaluator = SoterDamageEvaluator()

    @Test
    fun `expected support without capability becomes damaged`() {
        val state = evaluator.evaluate(
            expectedSupport = true,
            servicePackagePresent = true,
            initialized = true,
            supported = false,
            errorMessage = null,
        )

        assertTrue(state.expectedSupport)
        assertTrue(state.damaged)
        assertTrue(state.summary.contains("expected", ignoreCase = true))
    }

    @Test
    fun `supported device stays available`() {
        val state = evaluator.evaluate(
            expectedSupport = true,
            servicePackagePresent = true,
            initialized = true,
            supported = true,
            errorMessage = null,
        )

        assertTrue(state.available)
        assertFalse(state.damaged)
    }
}
