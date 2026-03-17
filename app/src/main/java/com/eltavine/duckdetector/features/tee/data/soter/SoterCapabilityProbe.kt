package com.eltavine.duckdetector.features.tee.data.soter

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.tencent.soter.wrapper.SoterWrapperApi
import com.tencent.soter.wrapper.wrap_callback.SoterProcessCallback
import com.tencent.soter.wrapper.wrap_callback.SoterProcessNoExtResult
import com.tencent.soter.wrapper.wrap_task.InitializeParam
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class SoterCapabilityProbe(
    private val context: Context,
    private val supportCatalog: SoterSupportCatalog = SoterSupportCatalog(),
    private val damageEvaluator: SoterDamageEvaluator = SoterDamageEvaluator(),
) {

    fun inspect(): TeeSoterState {
        val expectedSupport = supportCatalog.expectsSupport()
        val packagePresent = hasSoterServicePackage()
        var initialized = runCatching { SoterWrapperApi.isInitialized() }.getOrDefault(false)
        var supported = false
        var error: String? = null

        if (!initialized) {
            val latch = CountDownLatch(1)
            val callbackError = AtomicReference<String?>(null)
            runCatching {
                SoterWrapperApi.init(
                    context.applicationContext,
                    object : SoterProcessCallback<SoterProcessNoExtResult> {
                        override fun onResult(result: SoterProcessNoExtResult) {
                            callbackError.set(result.errMsg)
                            latch.countDown()
                        }
                    },
                    InitializeParam.InitializeParamBuilder()
                        .setScenes(0)
                        .build(),
                )
            }.onFailure { throwable ->
                error = throwable.message ?: "Soter init threw ${throwable.javaClass.simpleName}."
                latch.countDown()
            }
            latch.await(3, TimeUnit.SECONDS)
            initialized = runCatching { SoterWrapperApi.isInitialized() }.getOrDefault(false)
            if (error == null) {
                error = callbackError.get()
            }
        }

        supported = runCatching { SoterWrapperApi.isSupportSoter() }
            .getOrElse { throwable ->
                error = error ?: throwable.message ?: "Soter support query failed."
                false
            }

        return damageEvaluator.evaluate(
            expectedSupport = expectedSupport,
            servicePackagePresent = packagePresent,
            initialized = initialized,
            supported = supported,
            errorMessage = error,
        )
    }

    private fun hasSoterServicePackage(): Boolean {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(
                    SOTER_SERVER_PACKAGE,
                    PackageManager.PackageInfoFlags.of(0)
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    SOTER_SERVER_PACKAGE,
                    0
                )
            }
            true
        }.getOrDefault(false)
    }

    companion object {
        private const val SOTER_SERVER_PACKAGE = "com.tencent.soter.soterserver"
    }
}
