package com.eltavine.duckdetector.core.ui.model

data class DetectorStatus(
    val severity: DetectionSeverity,
    val infoKind: InfoKind? = null,
) {
    init {
        require(severity == DetectionSeverity.INFO || infoKind == null) {
            "Only INFO status can carry an InfoKind"
        }
    }

    companion object {
        fun info(kind: InfoKind) = DetectorStatus(DetectionSeverity.INFO, kind)
        fun allClear() = DetectorStatus(DetectionSeverity.ALL_CLEAR)
        fun warning() = DetectorStatus(DetectionSeverity.WARNING)
        fun danger() = DetectorStatus(DetectionSeverity.DANGER)
    }
}
