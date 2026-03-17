package com.eltavine.duckdetector.features.lsposed.data.probes

internal object LSPosedProbeSupport {
    val frameworkTokens = listOf(
        "lsposed",
        "xposed",
        "edxposed",
        "lspd",
        "libxposed",
        "lspatch",
        "lsplant",
    )

    val runtimeExcludePatterns = listOf(
        "duckdetector",
        "accessing hidden",
        "using reflection",
        "hiddenapi",
    )

    val logcatTags = listOf(
        "LSPosed",
        "LSPosed-Bridge",
        "LSPosedService",
        "LSPosedContext",
        "LSPosedHelper",
        "LSPosedLogcat",
        "XposedBridge",
        "XposedInit",
        "XSharedPreferences",
        "Dobby",
        "LSPlant",
        "EdXposed",
        "EdXposedManager",
    )

    val logcatTagPrefixes = listOf(
        "zygisk",
        "LSPosed",
    )

    val logcatPatterns = listOf(
        "Loading module",
        "Loading legacy module",
        "Loading class",
        "Crash unexpectedly",
        "Cannot hook",
        "Cannot load module",
        "Xposed API classes are compiled",
        "Failed to load class",
        "hookMethod",
        "deoptimizeMethod",
        "!!start_verbose!!",
        "!!stop_verbose!!",
        "!!refresh_modules!!",
        "!!refresh_verbose!!",
        "getSystemClassLoader failed",
        "InMemoryDexClassLoader creation failed",
        "ObfuscationManager init",
        "startBootstrapHook starts",
        "LoadedApk#",
    )
}

internal fun containsFrameworkToken(text: String): Boolean {
    val lower = text.lowercase()
    return LSPosedProbeSupport.frameworkTokens.any { token -> lower.contains(token) }
}

internal fun String.toSignalIdSegment(): String {
    return lowercase()
        .replace(Regex("[^a-z0-9]+"), "_")
        .trim('_')
        .ifBlank { "entry" }
}

internal fun String.trimToPreview(
    maxLength: Int = 180,
): String {
    val normalized = replace(Regex("\\s+"), " ").trim()
    return if (normalized.length <= maxLength) {
        normalized
    } else {
        normalized.take(maxLength - 3).trimEnd() + "..."
    }
}
