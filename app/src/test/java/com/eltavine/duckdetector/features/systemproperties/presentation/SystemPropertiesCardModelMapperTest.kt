package com.eltavine.duckdetector.features.systemproperties.presentation

import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodResult
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertiesCardModelMapperTest {

    private val mapper = SystemPropertiesCardModelMapper()

    @Test
    fun `prop area method and scan rows are rendered`() {
        val report = SystemPropertiesReport(
            stage = SystemPropertiesStage.READY,
            signals = listOf(
                SystemPropertySignal(
                    property = "prop_area hole: u:object_r:shell_prop:s0",
                    description = "Raw property area layout residue",
                    value = "2 hole(s)",
                    category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                    severity = SystemPropertySeverity.DANGER,
                    source = SystemPropertySource.NATIVE_LIBC,
                    detail = "Found hole in prop area: u:object_r:shell_prop:s0",
                ),
            ),
            infoSignals = emptyList(),
            checkedRuleCount = 12,
            observedRuleCount = 4,
            infoPropertyCount = 0,
            reflectionHitCount = 4,
            getpropHitCount = 4,
            jvmHitCount = 0,
            nativeHitCount = 4,
            bootParamHitCount = 2,
            buildSignalCount = 1,
            propAreaAvailable = true,
            propAreaContextCount = 6,
            propAreaHoleCount = 2,
            methods = listOf(
                SystemPropertiesMethodResult(
                    label = "Prop area layout",
                    summary = "2 hole(s)",
                    outcome = SystemPropertiesMethodOutcome.DANGER,
                    detail = "Raw /dev/__properties__ layout scan across 6 area(s).",
                ),
            ),
        )

        val model = mapper.map(report)

        assertTrue(model.subtitle.contains("prop-area hole", ignoreCase = true))
        assertTrue(model.methodRows.any { it.label == "Prop area layout" && it.value == "2 hole(s)" })
        assertTrue(model.consistencyRows.any { it.label.contains("prop_area hole:") })
        assertEquals("6", model.scanRows.single { it.label == "Prop areas scanned" }.value)
        assertEquals("2", model.scanRows.single { it.label == "Prop area holes" }.value)
    }
}
