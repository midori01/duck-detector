#include <jni.h>

#include <string>

#include "mount/detector_core.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_mount_data_native_MountNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject
) {
    const duckdetector::mount::MountSnapshot snapshot = duckdetector::mount::collect_snapshot();
    return to_jstring(env, duckdetector::mount::encode_snapshot(snapshot));
}
