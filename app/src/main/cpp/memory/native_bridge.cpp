#include <jni.h>

#include <string>

#include "memory/common/codec.h"
#include "memory/snapshot_builder.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_memory_data_native_MemoryNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, duckdetector::memory::encode_snapshot(
            duckdetector::memory::collect_snapshot()));
}
