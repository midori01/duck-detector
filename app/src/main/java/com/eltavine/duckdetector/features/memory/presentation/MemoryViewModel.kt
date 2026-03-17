package com.eltavine.duckdetector.features.memory.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.memory.data.repository.MemoryRepository
import com.eltavine.duckdetector.features.memory.domain.MemoryReport
import com.eltavine.duckdetector.features.memory.domain.MemoryStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class MemoryViewModel(
    private val repository: MemoryRepository,
    private val mapper: MemoryCardModelMapper = MemoryCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        MemoryUiState(
            stage = MemoryUiStage.LOADING,
            report = MemoryReport.loading(),
            cardModel = mapper.map(MemoryReport.loading()),
        ),
    )
    val uiState: StateFlow<MemoryUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = MemoryReport.loading()
            _uiState.update {
                it.copy(
                    stage = MemoryUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == MemoryStage.FAILED) {
                        MemoryUiStage.FAILED
                    } else {
                        MemoryUiStage.READY
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
                    return MemoryViewModel(MemoryRepository()) as T
                }
            }
        }
    }
}
