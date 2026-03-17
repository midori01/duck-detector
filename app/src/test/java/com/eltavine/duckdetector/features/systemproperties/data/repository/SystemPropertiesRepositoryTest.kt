package com.eltavine.duckdetector.features.systemproperties.data.repository

import com.eltavine.duckdetector.features.systemproperties.data.native.PropAreaFinding
import com.eltavine.duckdetector.features.systemproperties.data.native.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertiesRepositoryTest {

    private val repository = SystemPropertiesRepository()

    @Test
    fun `adbd config prop hole maps to danger`() {
        val snapshot = SystemPropertiesNativeSnapshot(
            propAreaAvailable = true,
            propAreaContextCount = 3,
            propAreaHoleCount = 2,
            propAreaFindings = listOf(
                PropAreaFinding(
                    context = "u:object_r:adbd_config_prop:s0",
                    holeCount = 2,
                    detail = "Found hole in prop area: u:object_r:adbd_config_prop:s0",
                ),
            ),
        )

        val signals = repository.buildPropAreaSignals(snapshot)
        val method = repository.buildPropAreaMethod(
            propAreaAvailable = snapshot.propAreaAvailable,
            propAreaContextCount = snapshot.propAreaContextCount,
            propAreaHoleCount = snapshot.propAreaHoleCount,
            propAreaSignals = signals,
        )

        assertEquals(1, signals.size)
        assertEquals(SystemPropertySeverity.DANGER, signals.single().severity)
        assertTrue(signals.single().property.contains("adbd_config_prop"))
        assertEquals("2 hole(s)", method.summary)
        assertEquals(SystemPropertiesMethodOutcome.DANGER, method.outcome)
    }

    @Test
    fun `regular prop area hole maps to warning`() {
        val snapshot = SystemPropertiesNativeSnapshot(
            propAreaAvailable = true,
            propAreaContextCount = 5,
            propAreaHoleCount = 1,
            propAreaFindings = listOf(
                PropAreaFinding(
                    context = "u:object_r:vendor_prop:s0",
                    holeCount = 1,
                    detail = "Found hole in prop area: u:object_r:vendor_prop:s0",
                ),
            ),
        )

        val signals = repository.buildPropAreaSignals(snapshot)
        val method = repository.buildPropAreaMethod(
            propAreaAvailable = snapshot.propAreaAvailable,
            propAreaContextCount = snapshot.propAreaContextCount,
            propAreaHoleCount = snapshot.propAreaHoleCount,
            propAreaSignals = signals,
        )

        assertEquals(SystemPropertySeverity.WARNING, signals.single().severity)
        assertEquals(SystemPropertiesMethodOutcome.WARNING, method.outcome)
    }

    @Test
    fun `unavailable prop area scan yields support without findings`() {
        val snapshot = SystemPropertiesNativeSnapshot()

        val signals = repository.buildPropAreaSignals(snapshot)
        val method = repository.buildPropAreaMethod(
            propAreaAvailable = snapshot.propAreaAvailable,
            propAreaContextCount = snapshot.propAreaContextCount,
            propAreaHoleCount = snapshot.propAreaHoleCount,
            propAreaSignals = signals,
        )

        assertTrue(signals.isEmpty())
        assertEquals("Unavailable", method.summary)
        assertEquals(SystemPropertiesMethodOutcome.SUPPORT, method.outcome)
    }
}
