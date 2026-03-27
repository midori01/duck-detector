package com.eltavine.duckdetector.ui.shell

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardDetectorContribution
import kotlinx.coroutines.delay

internal const val HELP_REQUEST_NOTICE =
    "Provide complete information to get help."

internal const val NON_OK_RESULT_NOTICE =
    "Danger and warning cards were expanded automatically for full review."

internal const val RESULT_NOTICE_LOCK_SECONDS = 5

internal fun shouldShowDetectorResultNotice(
    isLoading: Boolean,
    overviewStatus: DetectorStatus,
): Boolean {
    return !isLoading && when (overviewStatus.severity) {
        DetectionSeverity.DANGER,
        DetectionSeverity.WARNING -> true

        DetectionSeverity.INFO,
        DetectionSeverity.ALL_CLEAR -> false
    }
}

internal fun attentionDetectorTitles(
    contributions: List<DashboardDetectorContribution>,
): Set<String> {
    return contributions
        .filter { contribution ->
            contribution.ready && when (contribution.status.severity) {
                DetectionSeverity.DANGER,
                DetectionSeverity.WARNING -> true

                DetectionSeverity.INFO,
                DetectionSeverity.ALL_CLEAR -> false
            }
        }
        .mapTo(linkedSetOf()) { contribution -> contribution.title }
}

@Composable
fun DetectorResultNoticeDialog(
    onDismiss: () -> Unit,
) {
    var secondsRemaining by rememberSaveable { mutableIntStateOf(RESULT_NOTICE_LOCK_SECONDS) }
    val canDismiss = secondsRemaining == 0

    LaunchedEffect(Unit) {
        while (secondsRemaining > 0) {
            delay(1_000)
            secondsRemaining -= 1
        }
    }

    AlertDialog(
        onDismissRequest = {
            if (canDismiss) {
                onDismiss()
            }
        },
        properties = DialogProperties(
            dismissOnBackPress = canDismiss,
            dismissOnClickOutside = canDismiss,
        ),
        title = {
            WrapSafeText(
                text = "Before asking for help",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                WrapSafeText(
                    text = HELP_REQUEST_NOTICE,
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                )
                WrapSafeText(
                    text = NON_OK_RESULT_NOTICE,
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDismiss,
                enabled = canDismiss,
            ) {
                WrapSafeText(
                    text = if (canDismiss) {
                        "Continue"
                    } else {
                        "Continue (${secondsRemaining}s)"
                    },
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
    )
}
