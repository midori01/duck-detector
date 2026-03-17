package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs

enum class AppDestination {
    MAIN,
    SETTINGS,
}

enum class StartupGateState {
    LOADING,
    REQUIRES_DECISION,
    READY,
}

fun resolveStartupGateState(prefs: TeeNetworkPrefs?): StartupGateState = when {
    prefs == null -> StartupGateState.LOADING
    !prefs.consentAsked -> StartupGateState.REQUIRES_DECISION
    else -> StartupGateState.READY
}

fun shouldCreateDetectorViewModels(gateState: StartupGateState): Boolean {
    return gateState == StartupGateState.READY
}
