package com.eltavine.duckdetector.features.dangerousapps.ui.model

import com.eltavine.duckdetector.core.ui.model.ContextItemModel
import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class DangerousAppsCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<DangerousAppsHeaderFactModel>,
    val hmaAlert: DangerousAppsHmaAlertModel? = null,
    val packageItems: List<DangerousAppsPackageItemModel>,
    val context: List<ContextItemModel>,
    val targetApps: List<DangerousAppsTargetAppModel>,
)

data class DangerousAppsHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class DangerousAppsHmaAlertModel(
    val title: String,
    val summary: String,
    val hiddenPackages: List<DangerousAppsHiddenPackageItemModel>,
)

data class DangerousAppsHiddenPackageItemModel(
    val appName: String,
    val packageName: String,
    val methods: List<String>,
)

data class DangerousAppsPackageItemModel(
    val appName: String,
    val packageName: String,
    val methods: List<String>,
)

data class DangerousAppsTargetAppModel(
    val appName: String,
    val packageName: String,
    val category: String,
)
