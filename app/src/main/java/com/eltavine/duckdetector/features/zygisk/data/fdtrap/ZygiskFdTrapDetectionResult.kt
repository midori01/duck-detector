package com.eltavine.duckdetector.features.zygisk.data.fdtrap

data class ZygiskFdTrapDetectionResult(
    val available: Boolean,
    val detected: Boolean,
    val resultCode: Int,
    val methodName: String,
    val summary: String,
    val detail: String,
    val error: String? = null,
) {
    companion object {
        fun fromResultCode(
            resultCode: Int,
            detail: String,
            error: String? = null,
        ): ZygiskFdTrapDetectionResult {
            return when (resultCode) {
                ZygiskFdTrapNativeBridge.RESULT_CLEAN -> ZygiskFdTrapDetectionResult(
                    available = true,
                    detected = false,
                    resultCode = resultCode,
                    methodName = "Clean",
                    summary = "Clean",
                    detail = detail,
                    error = error,
                )

                ZygiskFdTrapNativeBridge.RESULT_EBADF -> ZygiskFdTrapDetectionResult(
                    available = true,
                    detected = true,
                    resultCode = resultCode,
                    methodName = "EBADF",
                    summary = "Closed during specialization",
                    detail = detail,
                    error = error,
                )

                ZygiskFdTrapNativeBridge.RESULT_CORRUPTION -> ZygiskFdTrapDetectionResult(
                    available = true,
                    detected = true,
                    resultCode = resultCode,
                    methodName = "Corruption",
                    summary = "Trap signature mismatch",
                    detail = detail,
                    error = error,
                )

                ZygiskFdTrapNativeBridge.RESULT_PROCFS_ANOMALY -> ZygiskFdTrapDetectionResult(
                    available = true,
                    detected = true,
                    resultCode = resultCode,
                    methodName = "Procfs anomaly",
                    summary = "Descriptor state drift",
                    detail = detail,
                    error = error,
                )

                else -> ZygiskFdTrapDetectionResult(
                    available = false,
                    detected = false,
                    resultCode = resultCode,
                    methodName = "Unavailable",
                    summary = when (resultCode) {
                        ZygiskFdTrapNativeBridge.RESULT_BIND_FAILED -> "Service bind failed"
                        ZygiskFdTrapNativeBridge.RESULT_TIMEOUT -> "Service timeout"
                        ZygiskFdTrapNativeBridge.RESULT_NATIVE_UNAVAILABLE -> "Native helper unavailable"
                        ZygiskFdTrapNativeBridge.RESULT_SKIPPED -> "Skipped"
                        else -> "Unavailable"
                    },
                    detail = detail,
                    error = error,
                )
            }
        }
    }
}
