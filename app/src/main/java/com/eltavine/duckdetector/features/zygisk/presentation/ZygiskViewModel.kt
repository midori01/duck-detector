package com.eltavine.duckdetector.features.zygisk.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.zygisk.data.repository.ZygiskRepository
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class ZygiskViewModel(
    private val repository: ZygiskRepository,
    private val mapper: ZygiskCardModelMapper = ZygiskCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        ZygiskUiState(
            stage = ZygiskUiStage.LOADING,
            report = ZygiskReport.loading(),
            cardModel = mapper.map(ZygiskReport.loading()),
        ),
    )
    val uiState: StateFlow<ZygiskUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = ZygiskReport.loading()
            _uiState.update {
                it.copy(
                    stage = ZygiskUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == ZygiskStage.FAILED) {
                        ZygiskUiStage.FAILED
                    } else {
                        ZygiskUiStage.READY
                    },
                    report = report,
                    cardModel = mapper.map(report),
                )
            }
        }
    }

    companion object {
        fun factory(
            context: Context,
        ): ViewModelProvider.Factory {
            val appContext = context.applicationContext
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return ZygiskViewModel(ZygiskRepository(appContext)) as T
                }
            }
        }
    }
}
