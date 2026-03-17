package com.eltavine.duckdetector.ui.theme

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween

object MotionTokens {
    object Duration {
        const val Short4 = 200
        const val Medium2 = 300
    }

    val CardPressScale = spring<Float>(
        dampingRatio = Spring.DampingRatioMediumBouncy,
        stiffness = Spring.StiffnessLow,
    )

    val PageTransition = spring<Float>(
        dampingRatio = Spring.DampingRatioNoBouncy,
        stiffness = Spring.StiffnessMediumLow,
    )

    val IconRotation = tween<Float>(
        durationMillis = Duration.Medium2,
        easing = FastOutSlowInEasing,
    )

    val FadeInOut = tween<Float>(
        durationMillis = Duration.Short4,
        easing = LinearOutSlowInEasing,
    )
}
