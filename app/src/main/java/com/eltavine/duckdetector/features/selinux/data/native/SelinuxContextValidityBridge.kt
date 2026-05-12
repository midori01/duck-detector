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
package com.eltavine.duckdetector.features.selinux.data.native

open class SelinuxContextValidityBridge {

    open fun collectSnapshot(): SelinuxContextValiditySnapshot {
        val rawData = preloadedRawData
            ?: return parseFailureSnapshot("No preloaded data available. Check AppZygotePreload status.")

        return runCatching {
            parse(rawData)
        }.getOrElse {
            parseFailureSnapshot("Parse error: ${it.message}")
        }
    }

    internal fun parse(raw: String): SelinuxContextValiditySnapshot {
        if (raw.isBlank()) {
            return parseFailureSnapshot("SELinux context validity payload was empty.")
        }

        var snapshot = SelinuxContextValiditySnapshot()
        val notes = mutableListOf<String>()
        val dirtyPolicyNotes = mutableListOf<String>()
        var recognizedEntryCount = 0

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("NOTE=") -> notes += line.removePrefix("NOTE=")
                        .decodeValue()

                    line.startsWith("DIRTY_POLICY_NOTE=") -> dirtyPolicyNotes += line.removePrefix(
                        "DIRTY_POLICY_NOTE="
                    ).decodeValue()

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        val (updatedSnapshot, recognized) = snapshot.applyEntry(key, value)
                        if (recognized) {
                            recognizedEntryCount += 1
                            snapshot = updatedSnapshot
                        }
                    }
                }
            }

        if (recognizedEntryCount == 0) {
            return parseFailureSnapshot("SELinux context validity payload was unrecognized.")
        }

        if (
            snapshot.available &&
            (snapshot.carrierContext.isNullOrBlank() || snapshot.queryMethod.isBlank() ||
                (snapshot.carrierMatchesExpected && !snapshot.probeAttempted))
        ) {
            return parseFailureSnapshot("SELinux context validity payload was incomplete.")
        }

        if (
            snapshot.dirtyPolicyAvailable &&
            (snapshot.dirtyPolicyQueryMethod.isBlank() ||
                (snapshot.dirtyPolicyCarrierMatchesExpected && !snapshot.dirtyPolicyProbeAttempted))
        ) {
            return parseFailureSnapshot("SELinux context validity payload was incomplete.")
        }

        return snapshot.copy(
            notes = notes,
            dirtyPolicyNotes = dirtyPolicyNotes,
        )
    }

    private fun parseFailureSnapshot(reason: String): SelinuxContextValiditySnapshot {
        return SelinuxContextValiditySnapshot(
            failureReason = reason,
            dirtyPolicyFailureReason = reason,
            dirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess",
            notes = listOf("SELinux context validity parser rejected the preloaded payload."),
            dirtyPolicyNotes = listOf("SELinux context validity parser rejected the preloaded payload."),
        )
    }

    private fun SelinuxContextValiditySnapshot.applyEntry(
        key: String,
        value: String,
    ): Pair<SelinuxContextValiditySnapshot, Boolean> {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool()) to true
            "PROBE_ATTEMPTED" -> copy(probeAttempted = value.asBool()) to true
            "CARRIER_CONTEXT" -> copy(carrierContext = value.decodeValue()) to true
            "CARRIER_MATCHES_EXPECTED" -> copy(carrierMatchesExpected = value.asBool()) to true
            "CARRIER_CONTROL_VALID" -> copy(carrierControlValid = value.asNullableBool()) to true
            "NEGATIVE_CONTROL_REJECTED" -> copy(negativeControlRejected = value.asNullableBool()) to true
            "FILE_CONTROL_VALID" -> copy(fileControlValid = value.asNullableBool()) to true
            "FILE_NEGATIVE_CONTROL_REJECTED" -> copy(fileNegativeControlRejected = value.asNullableBool()) to true
            "ORACLE_CONTROLS_PASSED" -> copy(oracleControlsPassed = value.asBool()) to true
            "KSU_RESULTS_STABLE" -> copy(ksuResultsStable = value.asBool()) to true
            "QUERY_METHOD" -> copy(queryMethod = value.decodeValue()) to true
            "KSU_DOMAIN_VALID" -> copy(ksuDomainValid = value.asNullableBool()) to true
            "KSU_FILE_VALID" -> copy(ksuFileValid = value.asNullableBool()) to true
            "MAGISK_FILE_VALID" -> copy(magiskFileValid = value.asNullableBool()) to true
            "DIRTY_POLICY_AVAILABLE" -> copy(dirtyPolicyAvailable = value.asBool()) to true
            "DIRTY_POLICY_PROBE_ATTEMPTED" -> copy(dirtyPolicyProbeAttempted = value.asBool()) to true
            "DIRTY_POLICY_CARRIER_CONTEXT" -> copy(dirtyPolicyCarrierContext = value.decodeValue()) to true
            "DIRTY_POLICY_CARRIER_MATCHES_EXPECTED" ->
                copy(dirtyPolicyCarrierMatchesExpected = value.asBool()) to true

            "DIRTY_POLICY_CONTROLS_PASSED" -> copy(dirtyPolicyControlsPassed = value.asBool()) to true
            "DIRTY_POLICY_STABLE" -> copy(dirtyPolicyStable = value.asBool()) to true
            "DIRTY_POLICY_QUERY_METHOD" -> copy(dirtyPolicyQueryMethod = value.decodeValue()) to true
            "DIRTY_POLICY_ACCESS_CONTROL_ALLOWED" ->
                copy(dirtyPolicyAccessControlAllowed = value.asNullableBool()) to true

            "DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED" ->
                copy(dirtyPolicyNegativeControlRejected = value.asNullableBool()) to true

            "DIRTY_POLICY_SYSTEM_SERVER_EXECMEM_ALLOWED" ->
                copy(dirtyPolicySystemServerExecmemAllowed = value.asNullableBool()) to true

            "DIRTY_POLICY_MAGISK_BINDER_CALL_ALLOWED" ->
                copy(dirtyPolicyMagiskBinderCallAllowed = value.asNullableBool()) to true

            "DIRTY_POLICY_KSU_BINDER_CALL_ALLOWED" ->
                copy(dirtyPolicyKsuBinderCallAllowed = value.asNullableBool()) to true

            "DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED" ->
                copy(dirtyPolicyLsposedFileReadAllowed = value.asNullableBool()) to true

            "DIRTY_POLICY_FAILURE_REASON" -> copy(dirtyPolicyFailureReason = value.decodeValue()) to true
            "FAILURE_REASON" -> copy(failureReason = value.decodeValue()) to true
            else -> this to false
        }
    }

    private fun String.asBool(): Boolean = this == "1" || equals("true", ignoreCase = true)

    private fun String.asNullableBool(): Boolean? {
        if (isBlank() || equals("unknown", ignoreCase = true)) return null
        return asBool()
    }

    private fun String.decodeValue(): String {
        return buildString(length) {
            var index = 0
            while (index < this@decodeValue.length) {
                val current = this@decodeValue[index]
                if (current == '\\' && index + 1 < this@decodeValue.length) {
                    when (this@decodeValue[index + 1]) {
                        'n' -> { append('\n'); index += 2; continue }
                        'r' -> { append('\r'); index += 2; continue }
                        't' -> { append('\t'); index += 2; continue }
                        '\\' -> { append('\\'); index += 2; continue }
                    }
                }
                append(current)
                index += 1
            }
        }
    }

    companion object {
        @Volatile
        private var preloadedRawData: String? = null

        @JvmStatic
        fun setPreloadedRawData(data: String) {
            preloadedRawData = data
        }

        val isNativeLibraryLoaded: Boolean by lazy {
            runCatching { System.loadLibrary("duckdetector") }.isSuccess
        }

        @JvmStatic
        external fun nativeCollectContextValiditySnapshot(): String
    }
}
