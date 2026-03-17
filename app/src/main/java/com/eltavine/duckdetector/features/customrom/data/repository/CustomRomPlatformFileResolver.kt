package com.eltavine.duckdetector.features.customrom.data.repository

import com.eltavine.duckdetector.features.customrom.data.native.CustomRomNativeSnapshot
import com.eltavine.duckdetector.features.customrom.data.rules.CustomRomCatalog
import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding

internal object CustomRomPlatformFileResolver {

    fun resolve(
        nativeSnapshot: CustomRomNativeSnapshot,
        isPixel: Boolean,
        shouldSkip: (String, Boolean) -> Boolean,
        fileExists: (String) -> Boolean,
    ): List<CustomRomFinding> {
        if (nativeSnapshot.available) {
            return nativeSnapshot.platformFiles.filterNot { shouldSkip(it.romName, isPixel) }
        }

        return CustomRomCatalog.platformFileSignatures.mapNotNull { signature ->
            if (shouldSkip(signature.romName, isPixel) || !fileExists(signature.path)) {
                return@mapNotNull null
            }
            CustomRomFinding(
                romName = signature.romName,
                signal = signature.path.substringAfterLast('/'),
                detail = signature.path,
            )
        }.distinct()
    }
}
