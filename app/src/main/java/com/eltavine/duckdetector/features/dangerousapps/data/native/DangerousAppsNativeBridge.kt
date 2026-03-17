package com.eltavine.duckdetector.features.dangerousapps.data.native

class DangerousAppsNativeBridge {

    fun statPackages(packageNames: List<String>): Set<String> {
        if (packageNames.isEmpty()) {
            return emptySet()
        }
        return runCatching {
            nativeStatPackages(packageNames.toTypedArray())
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toSet()
        }.getOrDefault(emptySet())
    }

    private external fun nativeStatPackages(packageNames: Array<String>): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
