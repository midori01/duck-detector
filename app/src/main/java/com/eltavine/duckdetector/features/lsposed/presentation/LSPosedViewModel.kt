package com.eltavine.duckdetector.features.lsposed.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.lsposed.data.repository.LSPosedRepository
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class LSPosedViewModel(
    private val repository: LSPosedRepository,
    private val mapper: LSPosedCardModelMapper = LSPosedCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        LSPosedUiState(
            stage = LSPosedUiStage.LOADING,
            report = LSPosedReport.loading(),
            cardModel = mapper.map(LSPosedReport.loading()),
        ),
    )
    val uiState: StateFlow<LSPosedUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = LSPosedReport.loading()
            _uiState.update {
                it.copy(
                    stage = LSPosedUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == LSPosedStage.FAILED) {
                        LSPosedUiStage.FAILED
                    } else {
                        LSPosedUiStage.READY
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
                    return LSPosedViewModel(LSPosedRepository(appContext)) as T
                }
            }
        }
    }
}
