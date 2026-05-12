/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.selinux.data.service

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.system.Os
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge

class AppZygotePreload : ZygotePreload {

    override fun doPreload(appInfo: ApplicationInfo) {
        val result = runCatching {
            val currentUid = Os.getuid()
            if (currentUid != appInfo.uid) {
                fallbackPayload("UID mismatch: $currentUid != app uid ${appInfo.uid}.")
            } else if (!SelinuxContextValidityBridge.isNativeLibraryLoaded) {
                fallbackPayload("SELinux native library unavailable.")
            } else {
                SelinuxContextValidityBridge.nativeCollectContextValiditySnapshot()
                    .ifBlank { fallbackPayload("SELinux native snapshot payload was empty.") }
            }
        }.getOrElse { throwable ->
            fallbackPayload(throwable.message ?: "SELinux app zygote preload failed.")
        }
        SelinuxContextValidityBridge.setPreloadedRawData(result)
    }

    private fun fallbackPayload(reason: String): String {
        val escapedReason = reason.escapePayloadValue()
        return buildString {
            append("AVAILABLE=0\n")
            append("PROBE_ATTEMPTED=0\n")
            append("CARRIER_MATCHES_EXPECTED=0\n")
            append("ORACLE_CONTROLS_PASSED=0\n")
            append("KSU_RESULTS_STABLE=0\n")
            append("DIRTY_POLICY_AVAILABLE=0\n")
            append("DIRTY_POLICY_PROBE_ATTEMPTED=0\n")
            append("DIRTY_POLICY_CARRIER_MATCHES_EXPECTED=0\n")
            append("DIRTY_POLICY_CONTROLS_PASSED=0\n")
            append("DIRTY_POLICY_STABLE=0\n")
            append("DIRTY_POLICY_QUERY_METHOD=android.os.SELinux.checkSELinuxAccess\n")
            append("DIRTY_POLICY_FAILURE_REASON=").append(escapedReason).append('\n')
            append("DIRTY_POLICY_NOTE=Kotlin preload fallback produced a parseable SELinux snapshot.\n")
            append("FAILURE_REASON=").append(escapedReason).append('\n')
            append("NOTE=Kotlin preload fallback produced a parseable SELinux snapshot.\n")
        }
    }

    private fun String.escapePayloadValue(): String {
        return buildString(length) {
            this@escapePayloadValue.forEach { ch ->
                when (ch) {
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
        }
    }
}
