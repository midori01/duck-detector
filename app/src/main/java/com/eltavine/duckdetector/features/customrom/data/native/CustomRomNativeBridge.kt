package com.eltavine.duckdetector.features.customrom.data.native

import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding

class CustomRomNativeBridge {

    fun collectSnapshot(): CustomRomNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot())
        }.getOrDefault(CustomRomNativeSnapshot())
    }

    internal fun parse(raw: String): CustomRomNativeSnapshot {
        if (raw.isBlank()) {
            return CustomRomNativeSnapshot()
        }

        var available = false
        val platformFiles = mutableListOf<CustomRomFinding>()
        val resourceInjectionFindings = mutableListOf<CustomRomFinding>()
        val recoveryScripts = mutableListOf<String>()
        val policyFindings = mutableListOf<CustomRomFinding>()
        val overlayFindings = mutableListOf<CustomRomFinding>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .forEach { line ->
                val key = line.substringBefore('=')
                val value = line.substringAfter('=')
                when (key) {
                    "AVAILABLE" -> available = value != "0"
                    "PLATFORM" -> parseFinding(value)?.let(platformFiles::add)
                    "MAP" -> parseMapFinding(value)?.let(resourceInjectionFindings::add)
                    "SCRIPT" -> if (value.isNotBlank()) recoveryScripts += value
                    "POLICY" -> parsePolicyFinding(value)?.let(policyFindings::add)
                    "OVERLAY" -> parseFinding(value)?.let(overlayFindings::add)
                }
            }

        return CustomRomNativeSnapshot(
            available = available,
            platformFiles = platformFiles,
            resourceInjectionFindings = resourceInjectionFindings,
            recoveryScripts = recoveryScripts,
            policyFindings = policyFindings,
            overlayFindings = overlayFindings,
        )
    }

    private fun parseFinding(raw: String): CustomRomFinding? {
        val parts = raw.split('|')
        if (parts.size < 2) {
            return null
        }
        return CustomRomFinding(
            romName = parts[0],
            signal = parts[1].substringAfterLast('/'),
            detail = parts[1],
        )
    }

    private fun parsePolicyFinding(raw: String): CustomRomFinding? {
        val parts = raw.split('|')
        if (parts.size < 3) {
            return null
        }
        return CustomRomFinding(
            romName = parts[0],
            signal = parts[1].substringAfterLast('/'),
            detail = "${parts[1]} (${parts[2]} hits)",
        )
    }

    private fun parseMapFinding(raw: String): CustomRomFinding? {
        val parts = raw.split('|', limit = 3)
        if (parts.size < 3) {
            return null
        }
        return CustomRomFinding(
            romName = parts[0],
            signal = parts[1],
            detail = parts[2].replace("\\n", "\n"),
        )
    }

    private external fun nativeCollectSnapshot(): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
