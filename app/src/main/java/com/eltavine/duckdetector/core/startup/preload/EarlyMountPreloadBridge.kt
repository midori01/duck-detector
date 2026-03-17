package com.eltavine.duckdetector.core.startup.preload

open class EarlyMountPreloadBridge {

    open fun isNativeAvailable(): Boolean = isLoaded

    open fun getStoredResult(): EarlyMountPreloadResult {
        if (!isLoaded) {
            return EarlyMountPreloadResult.empty()
        }

        return runCatching {
            if (!nativeHasEarlyDetectionRun()) {
                return EarlyMountPreloadResult.empty()
            }

            EarlyMountPreloadResult(
                hasRun = true,
                detected = nativeWasDetected(),
                detectionMethod = nativeGetDetectionMethod(),
                details = nativeGetDetails(),
                futileHideDetected = nativeWasFutileHideDetected(),
                mntStringsDetected = nativeWasMntStringsDetected(),
                mountIdGapDetected = nativeWasMountIdGapDetected(),
                minorDevGapDetected = nativeWasMinorDevGapDetected(),
                peerGroupGapDetected = nativeWasPeerGroupGapDetected(),
                nsMntCtimeDeltaNs = nativeGetNsMntCtimeDeltaNs(),
                mountInfoCtimeDeltaNs = nativeGetMountInfoCtimeDeltaNs(),
                mntStringsSource = nativeGetMntStringsSource(),
                mntStringsTarget = nativeGetMntStringsTarget(),
                mntStringsFs = nativeGetMntStringsFs(),
                findings = nativeGetFindings().toList(),
                isContextValid = nativeIsPreloadContextValid(),
                source = EarlyMountPreloadSource.NATIVE,
            ).normalize()
        }.getOrElse {
            EarlyMountPreloadResult.empty()
        }
    }

    @Suppress("unused")
    open fun resetForTesting() {
        if (isLoaded) {
            runCatching { nativeReset() }
        }
    }

    private external fun nativeHasEarlyDetectionRun(): Boolean

    private external fun nativeIsPreloadContextValid(): Boolean

    private external fun nativeWasDetected(): Boolean

    private external fun nativeWasFutileHideDetected(): Boolean

    private external fun nativeWasMinorDevGapDetected(): Boolean

    private external fun nativeWasMountIdGapDetected(): Boolean

    private external fun nativeWasMntStringsDetected(): Boolean

    private external fun nativeWasPeerGroupGapDetected(): Boolean

    private external fun nativeGetDetectionMethod(): String

    private external fun nativeGetDetails(): String

    private external fun nativeGetFindings(): Array<String>

    private external fun nativeGetNsMntCtimeDeltaNs(): Long

    private external fun nativeGetMountInfoCtimeDeltaNs(): Long

    private external fun nativeGetMntStringsSource(): String

    private external fun nativeGetMntStringsTarget(): String

    private external fun nativeGetMntStringsFs(): String

    private external fun nativeReset()

    companion object {
        private val isLoaded: Boolean = runCatching {
            System.loadLibrary("duckdetector")
            true
        }.getOrDefault(false)
    }
}
