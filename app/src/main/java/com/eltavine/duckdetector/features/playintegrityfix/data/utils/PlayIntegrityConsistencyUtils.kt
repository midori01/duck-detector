package com.eltavine.duckdetector.features.playintegrityfix.data.utils

import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixGroup
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignal
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignalSeverity
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSource

class PlayIntegrityConsistencyUtils {

    fun buildSourceMismatchSignals(
        reads: Collection<PlayIntegrityMultiSourceRead>,
    ): List<PlayIntegrityFixSignal> {
        return reads.mapNotNull { read ->
            val nonBlankValues = read.sourceValues.filterValues { it.isNotBlank() }
            if (nonBlankValues.size < 2) {
                return@mapNotNull null
            }
            val distinctValues = nonBlankValues.values.map { it.trim() }.distinct()
            if (distinctValues.size < 2) {
                return@mapNotNull null
            }

            PlayIntegrityFixSignal(
                id = "mismatch_${read.rule.property}",
                label = "${read.rule.label} source mismatch",
                value = "Mismatch",
                group = PlayIntegrityFixGroup.CONSISTENCY,
                category = read.rule.category,
                severity = PlayIntegrityFixSignalSeverity.WARNING,
                source = PlayIntegrityFixSource.NATIVE_LIBC,
                detail = buildString {
                    append(read.rule.property)
                    append('\n')
                    nonBlankValues.forEach { (source, value) ->
                        append(source.label)
                        append(": ")
                        append(value)
                        append('\n')
                    }
                }.trim(),
                detailMonospace = true,
            )
        }
    }
}
