package com.eltavine.duckdetector.features.selinux.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.selinux.data.repository.SelinuxRepository
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class SelinuxViewModel(
    private val repository: SelinuxRepository,
    private val mapper: SelinuxCardModelMapper = SelinuxCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SelinuxUiState(
            stage = SelinuxUiStage.LOADING,
            report = SelinuxReport.loading(),
            cardModel = mapper.map(SelinuxReport.loading()),
        ),
    )
    val uiState: StateFlow<SelinuxUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = SelinuxReport.loading()
            _uiState.update {
                it.copy(
                    stage = SelinuxUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == SelinuxStage.FAILED) SelinuxUiStage.FAILED else SelinuxUiStage.READY,
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
                    return SelinuxViewModel(SelinuxRepository()) as T
                }
            }
        }
    }
}
