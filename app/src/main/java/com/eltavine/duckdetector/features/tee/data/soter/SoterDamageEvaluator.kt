package com.eltavine.duckdetector.features.tee.data.soter

import com.eltavine.duckdetector.features.tee.domain.TeeSoterState

class SoterDamageEvaluator {

    fun evaluate(
        serviceReachable: Boolean,
        keyPrepared: Boolean,
        signSessionAvailable: Boolean,
        errorMessage: String?,
    ): TeeSoterState {
        val available = serviceReachable && keyPrepared && signSessionAvailable
        val damaged = serviceReachable && !available
        val summary = when {
            available -> "Soter checks succeeded: Treble service was reachable and ASK/AuthKey/initSigh all succeeded."
            !serviceReachable -> "Soter check skipped because the Treble service was not reachable."
            errorMessage != null -> withSoterHint(errorMessage)
            !keyPrepared -> "Soter key preparation failed after the Treble service became reachable."
            else -> "Soter signing session initialization failed after the Treble service became reachable."
        }
        return TeeSoterState(
            serviceReachable = serviceReachable,
            keyPrepared = keyPrepared,
            signSessionAvailable = signSessionAvailable,
            available = available,
            damaged = damaged,
            summary = summary,
        )
    }

    private fun withSoterHint(message: String): String {
        return if (message.contains("soter", ignoreCase = true)) {
            message
        } else {
            "Soter check: $message"
        }
    }
}
