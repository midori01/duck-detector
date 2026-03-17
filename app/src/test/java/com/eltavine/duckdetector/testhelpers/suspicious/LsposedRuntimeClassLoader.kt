package com.eltavine.duckdetector.testhelpers.suspicious

import com.eltavine.duckdetector.testhelpers.clean.NeutralLoader

class LsposedRuntimeClassLoader(
    parent: ClassLoader?,
) : NeutralLoader(parent)
