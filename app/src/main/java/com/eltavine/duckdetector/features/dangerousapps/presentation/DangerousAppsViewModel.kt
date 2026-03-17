package com.eltavine.duckdetector.features.dangerousapps.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.dangerousapps.data.repository.DangerousAppsRepository
import com.eltavine.duckdetector.features.dangerousapps.data.rules.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class DangerousAppsViewModel(
    private val repository: DangerousAppsRepository,
    private val mapper: DangerousAppsCardModelMapper = DangerousAppsCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        DangerousAppsUiState(
            stage = DangerousAppsUiStage.LOADING,
            report = DangerousAppsReport.loading(DangerousAppsCatalog.targets),
            cardModel = mapper.map(DangerousAppsReport.loading(DangerousAppsCatalog.targets)),
        ),
    )
    val uiState: StateFlow<DangerousAppsUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = DangerousAppsReport.loading(DangerousAppsCatalog.targets)
            _uiState.update {
                it.copy(
                    stage = DangerousAppsUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == DangerousAppsStage.FAILED) {
                        DangerousAppsUiStage.FAILED
                    } else {
                        DangerousAppsUiStage.READY
                    },
                    report = report,
                    cardModel = mapper.map(report),
                )
            }
        }
    }

    companion object {
        fun factory(context: Context): ViewModelProvider.Factory {
            val appContext = context.applicationContext
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return DangerousAppsViewModel(DangerousAppsRepository(appContext)) as T
                }
            }
        }
    }
}
