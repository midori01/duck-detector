package com.eltavine.duckdetector.features.dangerousapps.domain

enum class DangerousAppCategory(
    val displayName: String,
) {
    HOOK_FRAMEWORK("Hook framework"),
    APP_HIDE_TOOL("App hiding"),
    ROOT_TOOL("Root tool"),
    LOCATION_SPOOF("Fake location"),
    MOD_TOOL("Cracking / mod"),
    CHAT_HOOK("QQ / WeChat hook"),
    SYSTEM_MODIFICATION("System modification"),
    DEVICE_ID_MODIFICATION("Device ID modification"),
    PRIVACY_BYPASS("Privacy bypass"),
    BACKGROUND_CONTROL("Freezer / background"),
    TERMINAL_DEV("Terminal / dev"),
    MISC("Misc"),
}
