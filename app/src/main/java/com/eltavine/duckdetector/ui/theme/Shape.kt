package com.eltavine.duckdetector.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

val Shapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

object ShapeTokens {
    val CornerLarge = RoundedCornerShape(16.dp)
    val CornerLargeIncreased = RoundedCornerShape(20.dp)
    val CornerExtraLarge = RoundedCornerShape(28.dp)
    val CornerExtraLargeIncreased = RoundedCornerShape(32.dp)
    val CornerFull = RoundedCornerShape(50)
}
