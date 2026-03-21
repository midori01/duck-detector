package com.eltavine.duckdetector.features.tee.data.native

class TeeNativeBridge {

    fun collectSnapshot(leafDer: ByteArray?): NativeTeeSnapshot {
        return runCatching {
            decodeSnapshot(
                environmentRaw = nativeCollectEnvironment(),
                trickyRaw = nativeInspectTrickyStore(),
                derRaw = leafDer?.let(::nativeInspectLeafDer).orEmpty(),
            )
        }.getOrDefault(NativeTeeSnapshot())
    }

    internal fun decodeSnapshot(
        environmentRaw: String,
        trickyRaw: String,
        derRaw: String,
    ): NativeTeeSnapshot {
        val env = parseKeyValueLines(environmentRaw)
        val tricky = parseKeyValueLines(trickyRaw)
        val der = parseKeyValueLines(derRaw)
        return NativeTeeSnapshot(
            tracingDetected = env["TRACING"] == "1",
            suspiciousMappings = env.filterKeys { it == "MAPPING" || it.startsWith("MAPPING_") }.values.toList(),
            trickyStoreDetected = tricky["DETECTED"] == "1",
            gotHookDetected = tricky["GOT_HOOK"] == "1",
            syscallMismatchDetected = tricky["SYSCALL_MISMATCH"] == "1",
            inlineHookDetected = tricky["INLINE_HOOK"] == "1",
            honeypotDetected = tricky["HONEYPOT"] == "1",
            trickyStoreTimerSource = tricky["TIMER_SOURCE"] ?: "unknown",
            trickyStoreTimerFallbackReason = tricky["TIMER_FALLBACK"]?.takeIf { it.isNotBlank() },
            trickyStoreAffinityStatus = tricky["AFFINITY"] ?: "not_requested",
            trickyStoreMethods = tricky.filterKeys { it == "METHOD" || it.startsWith("METHOD_") }.values.toList(),
            trickyStoreDetails = tricky["DETAILS"] ?: "Native trickystore probe unavailable",
            leafDerPrimaryDetected = der["PRIMARY"] == "1",
            leafDerSecondaryDetected = der["SECONDARY"] == "1",
            leafDerFindings = der.filterKeys { it == "FINDING" || it.startsWith("FINDING_") }.values.toList(),
            pageSize = env["PAGE_SIZE"]?.toIntOrNull(),
            timingSummary = env["TIMING"],
        )
    }

    private fun parseKeyValueLines(raw: String): Map<String, String> {
        val indexedKeys = hashMapOf<String, Int>()
        return buildMap {
            raw.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && it.contains('=') }
                .forEach { line ->
                    val key = line.substringBefore('=')
                    val value = line.substringAfter('=')
                    val index = indexedKeys.getOrDefault(key, 0)
                    indexedKeys[key] = index + 1
                    if (index == 0) {
                        put(key, value)
                    } else {
                        put("${key}_$index", value)
                    }
                }
        }
    }

    private external fun nativeCollectEnvironment(): String

    private external fun nativeInspectTrickyStore(): String

    private external fun nativeInspectLeafDer(leafDer: ByteArray): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
