package com.eltavine.duckdetector.features.customrom.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.customrom.data.repository.CustomRomRepository
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class CustomRomViewModel(
    private val repository: CustomRomRepository,
    private val mapper: CustomRomCardModelMapper = CustomRomCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        CustomRomUiState(
            stage = CustomRomUiStage.LOADING,
            report = CustomRomReport.loading(),
            cardModel = mapper.map(CustomRomReport.loading()),
        ),
    )
    val uiState: StateFlow<CustomRomUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = CustomRomReport.loading()
            _uiState.update {
                it.copy(
                    stage = CustomRomUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == CustomRomStage.FAILED) {
                        CustomRomUiStage.FAILED
                    } else {
                        CustomRomUiStage.READY
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
                    return CustomRomViewModel(CustomRomRepository(appContext)) as T
                }
            }
        }
    }
}
