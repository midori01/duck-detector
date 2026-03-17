import java.util.Locale

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

val apkBuildTypes = mutableSetOf<String>()

android {
    namespace = "com.eltavine.duckdetector"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.eltavine.duckdetector"
        minSdk = 29
        targetSdk = 36
        versionCode = 201
        versionName = "26.3.1-alpha"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        configureEach {
            apkBuildTypes += name
        }

        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
    lint {
        baseline = file("lint-baseline.xml")
    }
}

afterEvaluate {
    val apkVersionName = android.defaultConfig.versionName ?: "unknown"
    apkBuildTypes.forEach { buildTypeName ->
        val assembleTaskName = "assemble" + buildTypeName.replaceFirstChar { firstChar ->
            if (firstChar.isLowerCase()) {
                firstChar.titlecase(Locale.ROOT)
            } else {
                firstChar.toString()
            }
        }

        tasks.findByName(assembleTaskName)?.doLast {
            val renamedFileName = "Duck Detector-$apkVersionName-Universal.apk"
            val outputDirectories = listOf(
                layout.buildDirectory.dir("outputs/apk/$buildTypeName").get().asFile,
                projectDir.resolve(buildTypeName)
            )

            outputDirectories.forEach { outputDirectory ->
                if (!outputDirectory.exists()) {
                    return@forEach
                }

                val renamedApk = outputDirectory.resolve(renamedFileName)
                val producedApk = outputDirectory
                    .listFiles()
                    ?.filter { file ->
                        file.isFile &&
                                file.extension == "apk" &&
                                file.name != renamedApk.name
                    }
                    ?.maxByOrNull { file -> file.lastModified() }
                    ?: return@forEach

                if (renamedApk.exists()) {
                    renamedApk.delete()
                }
                producedApk.copyTo(renamedApk, overwrite = true)
                producedApk.delete()
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.material)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.soter.wrapper)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.junit)
    testImplementation(libs.junit)
    testImplementation(libs.json)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    debugImplementation(libs.androidx.ui.tooling)
}
