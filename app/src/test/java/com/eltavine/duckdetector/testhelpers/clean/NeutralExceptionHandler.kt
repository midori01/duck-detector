package com.eltavine.duckdetector.testhelpers.clean

class NeutralExceptionHandler : Thread.UncaughtExceptionHandler {
    override fun uncaughtException(
        thread: Thread,
        throwable: Throwable,
    ) = Unit
}
