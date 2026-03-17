package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.domain.TeeReport

class TeeExportFormatter {

    fun format(report: TeeReport): String {
        return buildString {
            appendLine(report.headline)
            appendLine(report.summary)
            appendLine()
            appendLine("Verdict: ${report.verdict}")
            appendLine("Tier: ${report.tier}")
            appendLine("Trust root: ${report.trustRoot}")
            appendLine("Trust summary: ${report.trustSummary}")
            appendLine("Tamper score: ${report.tamperScore}")
            appendLine("Evidence count: ${report.evidenceCount}")
            appendLine("Network: ${report.networkState.summary}")
            appendLine("Soter: ${report.soterState.summary}")
            appendLine()
            report.sections.forEach { section ->
                appendLine(section.title)
                section.items.forEach { item ->
                    append("- ")
                    append(item.title)
                    append(": ")
                    appendLine(item.body)
                }
                appendLine()
            }
            if (report.certificates.isNotEmpty()) {
                appendLine("Certificates")
                report.certificates.forEach { cert ->
                    append("- ")
                    append(cert.slotLabel)
                    append(": ")
                    append(cert.subject)
                    append(" -> ")
                    appendLine(cert.issuer)
                }
            }
        }.trim()
    }
}
