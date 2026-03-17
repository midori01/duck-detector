package com.eltavine.duckdetector.features.bootloader.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.bootloader.data.repository.BootloaderRepository
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class BootloaderViewModel(
    private val repository: BootloaderRepository,
    private val mapper: BootloaderCardModelMapper = BootloaderCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        BootloaderUiState(
            stage = BootloaderUiStage.LOADING,
            report = BootloaderReport.loading(),
            cardModel = mapper.map(BootloaderReport.loading()),
        ),
    )
    val uiState: StateFlow<BootloaderUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = BootloaderReport.loading()
            _uiState.update {
                it.copy(
                    stage = BootloaderUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == BootloaderStage.FAILED) {
                        BootloaderUiStage.FAILED
                    } else {
                        BootloaderUiStage.READY
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
                    return BootloaderViewModel(BootloaderRepository(appContext)) as T
                }
            }
        }
    }
}
