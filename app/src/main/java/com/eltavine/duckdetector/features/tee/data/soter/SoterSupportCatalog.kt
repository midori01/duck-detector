package com.eltavine.duckdetector.features.tee.data.soter

import android.os.Build

class SoterSupportCatalog {

    fun expectsSupport(
        manufacturer: String = Build.MANUFACTURER,
        brand: String = Build.BRAND,
    ): Boolean {
        val haystack = "${manufacturer.lowercase()} ${brand.lowercase()}"
        return KNOWN_SOTER_BRANDS.any { haystack.contains(it) }
    }

    companion object {
        private val KNOWN_SOTER_BRANDS = setOf(
            "huawei",
            "honor",
            "oppo",
            "realme",
            "vivo",
            "xiaomi",
            "redmi",
            "poco",
            "samsung",
            "oneplus",
            "meizu",
            "lenovo",
            "iqoo"
        )
    }
}
