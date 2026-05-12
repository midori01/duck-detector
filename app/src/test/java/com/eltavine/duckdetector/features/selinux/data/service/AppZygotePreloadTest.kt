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

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AppZygotePreloadTest {

    @Test
    fun `fallback payload stays parseable`() {
        val preload = AppZygotePreload()
        val method = AppZygotePreload::class.java.getDeclaredMethod(
            "fallbackPayload",
            String::class.java,
        )
        method.isAccessible = true

        val payload = method.invoke(preload, "boom\n\"quoted\"") as String
        val snapshot = SelinuxContextValidityBridge().parse(payload)

        assertFalse(snapshot.available)
        assertEquals("boom\n\"quoted\"", snapshot.failureReason)
        assertFalse(snapshot.dirtyPolicyAvailable)
        assertEquals("android.os.SELinux.checkSELinuxAccess", snapshot.dirtyPolicyQueryMethod)
        assertEquals("boom\n\"quoted\"", snapshot.dirtyPolicyFailureReason)
        assertEquals(
            listOf("Kotlin preload fallback produced a parseable SELinux snapshot."),
            snapshot.dirtyPolicyNotes,
        )
        assertEquals(
            listOf("Kotlin preload fallback produced a parseable SELinux snapshot."),
            snapshot.notes,
        )
    }
}
