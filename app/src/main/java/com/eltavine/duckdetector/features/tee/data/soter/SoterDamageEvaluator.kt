package com.eltavine.duckdetector.features.tee.data.soter

import com.eltavine.duckdetector.features.tee.domain.TeeSoterState

class SoterDamageEvaluator {

    fun evaluate(
        expectedSupport: Boolean,
        servicePackagePresent: Boolean,
        initialized: Boolean,
        supported: Boolean,
        errorMessage: String?,
    ): TeeSoterState {
        val damaged = expectedSupport && initialized && !supported
        val summary = when {
            supported -> "Soter initialized and reports device support."
            damaged -> "Soter support was expected, but initialization completed without capability."
            expectedSupport && !servicePackagePresent -> "Soter support looks expected for this vendor, but the service package is absent."
            errorMessage != null -> errorMessage
            expectedSupport -> "Soter support could not be confirmed."
            else -> "Soter is not expected on this device family."
        }
        return TeeSoterState(
            expectedSupport = expectedSupport,
            available = supported,
            damaged = damaged,
            summary = summary,
        )
    }
}
