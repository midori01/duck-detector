package com.eltavine.duckdetector.features.zygisk.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.MenuBook
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.FolderZip
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.SyncAlt
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskCardModel
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskDetailRowModel
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskHeaderFactModel
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun ZygiskDetectorCard(
    model: ZygiskCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.BugReport,
        modifier = modifier,
        headerFacts = {
            ZygiskCollapsedOverview(model)
        },
    ) {
        if (model.stateRows.isNotEmpty()) {
            ZygiskDetailSection("Security state", Icons.Rounded.Info, model.stateRows)
        }
        if (model.impactItems.isNotEmpty()) {
            ZygiskImpactSection("Impact", Icons.Rounded.CrisisAlert, model.impactItems)
        }
        if (model.methodRows.isNotEmpty()) {
            ZygiskDetailSection("Detection methods", Icons.Rounded.Search, model.methodRows)
        }
        if (model.signalRows.isNotEmpty()) {
            ZygiskDetailSection("Signals", Icons.Rounded.Memory, model.signalRows)
        }
        if (model.references.isNotEmpty()) {
            DetectorSectionFrame(
                title = "References",
                icon = Icons.AutoMirrored.Rounded.MenuBook,
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    model.references.forEach { reference ->
                        WrapSafeText(
                            text = reference,
                            modifier = Modifier.fillMaxWidth(),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ZygiskCollapsedOverview(
    model: ZygiskCardModel,
) {
    val state = model.headerFacts.firstOrNull { it.label == "State" } ?: return
    val confidence = model.headerFacts.firstOrNull { it.label == "Confidence" } ?: return
    val fdTrap = model.headerFacts.firstOrNull { it.label == "FD trap" } ?: return
    val native = model.headerFacts.firstOrNull { it.label == "Native" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        ZygiskFactPairCard(
            primary = state,
            secondary = confidence,
            modifier = Modifier.weight(1f),
        )
        ZygiskFactPairCard(
            primary = fdTrap,
            secondary = native,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun ZygiskFactPairCard(
    primary: ZygiskHeaderFactModel,
    secondary: ZygiskHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            ZygiskFactPairRow(primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            ZygiskFactPairRow(secondary)
        }
    }
}

@Composable
private fun ZygiskFactPairRow(
    fact: ZygiskHeaderFactModel,
) {
    val appearance = rememberStatusAppearance(fact.status)
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(15.dp),
            )
            WrapSafeText(
                text = fact.label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        WrapSafeText(
            text = fact.value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun ZygiskDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<ZygiskDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                ZygiskDetailRow(row)
                if (index < rows.lastIndex) {
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.18f),
                        thickness = 1.dp,
                    )
                }
            }
        }
    }
}

@Composable
private fun ZygiskDetailRow(
    row: ZygiskDetailRowModel,
) {
    val appearance = rememberStatusAppearance(row.status)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = rowIcon(row, appearance.icon),
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(17.dp),
            )
            WrapSafeText(
                text = row.label,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Surface(
                color = appearance.iconTint.copy(alpha = 0.12f),
                shape = ShapeTokens.CornerFull,
            ) {
                WrapSafeText(
                    text = row.value,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                    style = MaterialTheme.typography.labelMedium,
                    color = appearance.iconTint,
                )
            }
        }
        row.detail?.takeIf { it.isNotBlank() }?.let { detail ->
            WrapSafeText(
                text = detail,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 27.dp),
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = if (row.detailMonospace) FontFamily.Monospace else FontFamily.Default,
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ZygiskImpactSection(
    title: String,
    icon: ImageVector,
    items: List<ZygiskImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                ZygiskImpactRow(item)
            }
        }
    }
}

@Composable
private fun ZygiskImpactRow(
    item: ZygiskImpactItemModel,
) {
    val appearance = rememberStatusAppearance(item.status)
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(
            imageVector = appearance.icon,
            contentDescription = null,
            tint = appearance.iconTint,
            modifier = Modifier.size(16.dp),
        )
        WrapSafeText(
            text = item.text,
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun rowIcon(
    row: ZygiskDetailRowModel,
    fallback: ImageVector,
): ImageVector {
    return when {
        row.label.contains("fd trap", ignoreCase = true) ||
                row.label.contains("cross-process", ignoreCase = true) -> Icons.Rounded.SyncAlt

        row.label.contains("linker", ignoreCase = true) ||
                row.label.contains("namespace", ignoreCase = true) -> Icons.Rounded.FolderZip

        row.label.contains("heap", ignoreCase = true) ||
                row.label.contains("maps", ignoreCase = true) ||
                row.label.contains("smaps", ignoreCase = true) -> Icons.Rounded.Memory

        else -> fallback
    }
}
