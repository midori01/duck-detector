package com.eltavine.duckdetector.features.tee.ui

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import com.eltavine.duckdetector.core.ui.components.WrapSafeText

@Composable
fun CrlNetworkConsentDialog(
    onAllowNetwork: () -> Unit,
    onLocalOnly: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = {},
        title = {
            WrapSafeText(
                text = "Use network for CRL checks?",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        },
        text = {
            WrapSafeText(
                text = "Duck Detector can query Google's attestation revocation feed during TEE validation. Startup scanning waits for this choice.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        confirmButton = {
            TextButton(onClick = onAllowNetwork) {
                WrapSafeText(
                    text = "Allow network",
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onLocalOnly) {
                WrapSafeText(
                    text = "Local only",
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
    )
}
