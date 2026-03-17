package com.eltavine.duckdetector.features.kernelcheck.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.kernelcheck.data.repository.KernelCheckRepository
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class KernelCheckViewModel(
    private val repository: KernelCheckRepository,
    private val mapper: KernelCheckCardModelMapper = KernelCheckCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        KernelCheckUiState(
            stage = KernelCheckUiStage.LOADING,
            report = KernelCheckReport.loading(),
            cardModel = mapper.map(KernelCheckReport.loading()),
        ),
    )
    val uiState: StateFlow<KernelCheckUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = KernelCheckReport.loading()
            _uiState.update {
                it.copy(
                    stage = KernelCheckUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == KernelCheckStage.FAILED) {
                        KernelCheckUiStage.FAILED
                    } else {
                        KernelCheckUiStage.READY
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
                    return KernelCheckViewModel(KernelCheckRepository()) as T
                }
            }
        }
    }
}
