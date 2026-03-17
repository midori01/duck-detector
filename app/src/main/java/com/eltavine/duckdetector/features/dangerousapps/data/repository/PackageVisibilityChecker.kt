package com.eltavine.duckdetector.features.dangerousapps.data.repository

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility

object PackageVisibilityChecker {

    fun detect(
        context: Context,
        installedPackageCount: Int,
    ): DangerousPackageVisibility {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return DangerousPackageVisibility.FULL
        }
        return if (installedPackageCount > 10) {
            DangerousPackageVisibility.FULL
        } else {
            DangerousPackageVisibility.RESTRICTED
        }
    }

    @Suppress("DEPRECATION")
    fun getInstalledPackages(context: Context): Set<String> {
        return runCatching {
            val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()),
                )
            } else {
                context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            }
            applications.mapTo(linkedSetOf()) { it.packageName }
        }.getOrDefault(emptySet())
    }
}
