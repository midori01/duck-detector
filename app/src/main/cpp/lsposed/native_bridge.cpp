#include <jni.h>

#include <string>

#include "lsposed/common/codec.h"
#include "lsposed/snapshot_builder.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_lsposed_data_native_LSPosedNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject
) {
    return to_jstring(
            env,
            duckdetector::lsposed::encode_snapshot(duckdetector::lsposed::collect_snapshot())
    );
}
