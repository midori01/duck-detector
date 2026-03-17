package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.testhelpers.clean.NeutralLoader
import com.eltavine.duckdetector.testhelpers.suspicious.LsposedRuntimeClassLoader
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedClassLoaderProbeTest {

    private val probe = LSPosedClassLoaderProbe()

    @Test
    fun `loader token reports danger`() {
        val loader = LsposedRuntimeClassLoader(parent = NeutralLoader(null))

        val result = probe.evaluate(startingLoaders = listOf(loader))

        assertEquals(1, result.hitCount)
        assertEquals(LSPosedSignalSeverity.DANGER, result.signals.single().severity)
        assertTrue(result.signals.single().detail.contains("LsposedRuntimeClassLoader"))
    }

    @Test
    fun `deep clean chain reports warning`() {
        val loader = NeutralLoader(
            parent = NeutralLoader(
                parent = NeutralLoader(
                    parent = NeutralLoader(
                        parent = NeutralLoader(
                            parent = NeutralLoader(null),
                        ),
                    ),
                ),
            ),
        )

        val result = probe.evaluate(startingLoaders = listOf(loader))

        assertEquals(1, result.hitCount)
        assertEquals(LSPosedSignalSeverity.WARNING, result.signals.single().severity)
        assertTrue(result.signals.single().detail.contains("6 levels"))
    }

    @Test
    fun `short clean chain stays clear`() {
        val loader = NeutralLoader(parent = NeutralLoader(parent = NeutralLoader(null)))

        val result = probe.evaluate(startingLoaders = listOf(loader))

        assertTrue(result.signals.isEmpty())
        assertEquals(0, result.hitCount)
    }
}
