#include <jni.h>

#include <string>

#include "zygisk/probes/fd_trap.h"

extern "C" JNIEXPORT jint JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_fdtrap_ZygiskFdTrapNativeBridge_nativeSetupTrapFd(
        JNIEnv *env,
        jobject,
        jstring cache_dir
) {
    const char *raw_cache_dir = env->GetStringUTFChars(cache_dir, nullptr);
    const std::string path = raw_cache_dir == nullptr ? std::string() : std::string(raw_cache_dir);
    if (raw_cache_dir != nullptr) {
        env->ReleaseStringUTFChars(cache_dir, raw_cache_dir);
    }
    return duckdetector::zygisk::setup_trap_fd(path);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_fdtrap_ZygiskFdTrapNativeBridge_nativeVerifyTrapFd(
        JNIEnv *,
        jobject,
        jint fd
) {
    return duckdetector::zygisk::verify_trap_fd(fd);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_fdtrap_ZygiskFdTrapNativeBridge_nativeGetTrapDetails(
        JNIEnv *env,
        jobject
) {
    return env->NewStringUTF(duckdetector::zygisk::get_trap_details().c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_fdtrap_ZygiskFdTrapNativeBridge_nativeCleanupTrapFd(
        JNIEnv *,
        jobject,
        jint fd
) {
    duckdetector::zygisk::cleanup_trap_fd(fd);
}
