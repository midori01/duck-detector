#include <jni.h>

#include <string>
#include <vector>

#include "playintegrityfix/common/codec.h"
#include "playintegrityfix/snapshot_builder.h"

namespace {

    std::vector<std::string> read_property_names(
            JNIEnv *env,
            jobjectArray property_names
    ) {
        std::vector<std::string> keys;
        if (property_names == nullptr) {
            return keys;
        }

        const jsize count = env->GetArrayLength(property_names);
        keys.reserve(static_cast<size_t>(count));
        for (jsize index = 0; index < count; ++index) {
            auto *java_key = static_cast<jstring>(env->GetObjectArrayElement(property_names,
                                                                             index));
            if (java_key == nullptr) {
                continue;
            }

            const char *chars = env->GetStringUTFChars(java_key, nullptr);
            if (chars != nullptr) {
                keys.emplace_back(chars);
                env->ReleaseStringUTFChars(java_key, chars);
            }
            env->DeleteLocalRef(java_key);
        }
        return keys;
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_playintegrityfix_data_native_PlayIntegrityFixNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject,
        jobjectArray property_names
) {
    return to_jstring(
            env,
            duckdetector::playintegrityfix::encode_snapshot(
                    duckdetector::playintegrityfix::collect_snapshot(
                            read_property_names(env, property_names))
            )
    );
}
