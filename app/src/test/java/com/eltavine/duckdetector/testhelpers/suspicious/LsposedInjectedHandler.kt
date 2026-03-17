package com.eltavine.duckdetector.testhelpers.suspicious

class LsposedInjectedHandler : Thread.UncaughtExceptionHandler {
    override fun uncaughtException(
        thread: Thread,
        throwable: Throwable,
    ) = Unit
}
