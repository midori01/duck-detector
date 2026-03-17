package com.eltavine.duckdetector

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadStore
import com.eltavine.duckdetector.ui.DuckDetectorApp
import com.eltavine.duckdetector.ui.theme.DuckDetectorTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EarlyMountPreloadStore.capture(intent)
        enableEdgeToEdge()
        setContent {
            DuckDetectorTheme {
                DuckDetectorApp()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        EarlyMountPreloadStore.capture(intent)
    }
}
