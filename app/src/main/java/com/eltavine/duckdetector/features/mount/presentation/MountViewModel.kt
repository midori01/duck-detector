package com.eltavine.duckdetector.features.mount.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.mount.data.repository.MountRepository
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class MountViewModel(
    private val repository: MountRepository,
    private val mapper: MountCardModelMapper = MountCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        MountUiState(
            stage = MountUiStage.LOADING,
            report = MountReport.loading(),
            cardModel = mapper.map(MountReport.loading()),
        ),
    )
    val uiState: StateFlow<MountUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = MountReport.loading()
            _uiState.update {
                it.copy(
                    stage = MountUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == MountStage.FAILED) {
                        MountUiStage.FAILED
                    } else {
                        MountUiStage.READY
                    },
                    report = report,
                    cardModel = mapper.map(report),
                )
            }
        }
    }

    companion object {
        fun factory(): ViewModelProvider.Factory {
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return MountViewModel(MountRepository()) as T
                }
            }
        }
    }
}
