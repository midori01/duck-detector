/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.lsposed.presentation

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedCardModelMapperTest {

    private val mapper = LSPosedCardModelMapper()

    @Test
    fun `zygote permission unavailable keeps clean signal report at support`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            zygotePermissionAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertTrue(model.verdict.contains("reduced coverage", ignoreCase = true))
    }

    @Test
    fun `native heap unavailable keeps clean signal report at support`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            nativeHeapAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("N/A", model.scanRows.single { it.label == "Native heap" }.value)
    }
}
