package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardDetectorContribution
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectorResultNoticeDialogTest {

    @Test
    fun `does not show while dashboard is loading`() {
        assertFalse(
            shouldShowDetectorResultNotice(
                isLoading = true,
                overviewStatus = DetectorStatus.danger(),
            ),
        )
    }

    @Test
    fun `does not show when overall result is ok`() {
        assertFalse(
            shouldShowDetectorResultNotice(
                isLoading = false,
                overviewStatus = DetectorStatus.allClear(),
            ),
        )
    }

    @Test
    fun `does not show for info only result`() {
        assertFalse(
            shouldShowDetectorResultNotice(
                isLoading = false,
                overviewStatus = DetectorStatus.info(
                    com.eltavine.duckdetector.core.ui.model.InfoKind.ERROR
                ),
            ),
        )
    }

    @Test
    fun `shows when scan is complete and result is warning`() {
        assertTrue(
            shouldShowDetectorResultNotice(
                isLoading = false,
                overviewStatus = DetectorStatus.warning(),
            ),
        )
    }

    @Test
    fun `returns titles for ready danger and warning detectors only`() {
        val titles = attentionDetectorTitles(
            listOf(
                DashboardDetectorContribution(
                    id = "bootloader",
                    title = "Bootloader",
                    status = DetectorStatus.danger(),
                    headline = "Danger",
                    summary = "summary",
                    ready = true,
                ),
                DashboardDetectorContribution(
                    id = "tee",
                    title = "TEE",
                    status = DetectorStatus.warning(),
                    headline = "Warning",
                    summary = "summary",
                    ready = true,
                ),
                DashboardDetectorContribution(
                    id = "memory",
                    title = "Memory",
                    status = DetectorStatus.allClear(),
                    headline = "OK",
                    summary = "summary",
                    ready = true,
                ),
                DashboardDetectorContribution(
                    id = "virtualization",
                    title = "Virtualization",
                    status = DetectorStatus.danger(),
                    headline = "Danger",
                    summary = "summary",
                    ready = false,
                ),
            ),
        )

        assertEquals(linkedSetOf("Bootloader", "TEE"), titles)
    }
}
