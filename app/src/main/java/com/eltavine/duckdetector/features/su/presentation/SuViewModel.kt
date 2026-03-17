package com.eltavine.duckdetector.features.su.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.su.data.repository.SuRepository
import com.eltavine.duckdetector.features.su.domain.SuReport
import com.eltavine.duckdetector.features.su.domain.SuStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class SuViewModel(
    private val repository: SuRepository,
    private val mapper: SuCardModelMapper = SuCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SuUiState(
            stage = SuUiStage.LOADING,
            report = SuReport.loading(),
            cardModel = mapper.map(SuReport.loading()),
        ),
    )
    val uiState: StateFlow<SuUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = SuReport.loading()
            _uiState.update {
                it.copy(
                    stage = SuUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == SuStage.FAILED) SuUiStage.FAILED else SuUiStage.READY,
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
                    return SuViewModel(SuRepository()) as T
                }
            }
        }
    }
}
