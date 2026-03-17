#include <jni.h>

#include <string>

#include "zygisk/common/codec.h"
#include "zygisk/snapshot_builder.h"

namespace {

    jstring to_jstring(
            JNIEnv *env,
            const std::string &value
    ) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_native_ZygiskNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject
) {
    return to_jstring(
            env,
            duckdetector::zygisk::encode_snapshot(duckdetector::zygisk::collect_snapshot())
    );
}
