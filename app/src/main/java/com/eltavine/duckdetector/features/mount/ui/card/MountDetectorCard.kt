package com.eltavine.duckdetector.features.mount.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountTree
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Storage
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
import com.eltavine.duckdetector.features.mount.ui.model.MountCardModel
import com.eltavine.duckdetector.features.mount.ui.model.MountDetailRowModel
import com.eltavine.duckdetector.features.mount.ui.model.MountHeaderFactModel
import com.eltavine.duckdetector.features.mount.ui.model.MountImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun MountDetectorCard(
    model: MountCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Storage,
        modifier = modifier,
        headerFacts = {
            MountCollapsedOverview(model = model)
        },
    ) {
        if (model.artifactRows.isNotEmpty()) {
            MountDetailSection(
                title = "Root artifacts",
                icon = Icons.Rounded.FolderOpen,
                rows = model.artifactRows,
            )
        }

        if (model.runtimeRows.isNotEmpty()) {
            MountDetailSection(
                title = "Runtime mounts",
                icon = Icons.Rounded.Storage,
                rows = model.runtimeRows,
            )
        }

        if (model.filesystemRows.isNotEmpty()) {
            MountDetailSection(
                title = "Filesystem",
                icon = Icons.Rounded.Memory,
                rows = model.filesystemRows,
            )
        }

        if (model.consistencyRows.isNotEmpty()) {
            MountDetailSection(
                title = "Namespace and consistency",
                icon = Icons.Rounded.AccountTree,
                rows = model.consistencyRows,
            )
        }

        if (model.impactItems.isNotEmpty()) {
            MountImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }

        if (model.methodRows.isNotEmpty()) {
            MountDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }

        if (model.scanRows.isNotEmpty()) {
            MountDetailSection(
                title = "Scan summary",
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
            )
        }
    }
}

@Composable
private fun MountCollapsedOverview(
    model: MountCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.label == "Critical" } ?: return
    val review = model.headerFacts.firstOrNull { it.label == "Review" } ?: return
    val coverage = model.headerFacts.firstOrNull { it.label == "Coverage" } ?: return
    val native = model.headerFacts.firstOrNull { it.label == "Native" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        MountFactPairCard(
            primary = critical,
            secondary = review,
            modifier = Modifier.weight(1f),
        )
        MountFactPairCard(
            primary = coverage,
            secondary = native,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun MountFactPairCard(
    primary: MountHeaderFactModel,
    secondary: MountHeaderFactModel,
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
            MountFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            MountFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun MountFactPairRow(
    fact: MountHeaderFactModel,
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
private fun MountDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<MountDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                MountDetailRow(row = row)
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
private fun MountDetailRow(
    row: MountDetailRowModel,
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
                imageVector = appearance.icon,
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
private fun MountImpactSection(
    title: String,
    icon: ImageVector,
    items: List<MountImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                MountImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun MountImpactRow(
    item: MountImpactItemModel,
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
