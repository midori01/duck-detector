#include <jni.h>

#include <cerrno>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

    bool stat_exists(const std::string &path) {
        struct stat st{};
#if defined(__aarch64__) || defined(__x86_64__)
        const int result = static_cast<int>(syscall(__NR_newfstatat, AT_FDCWD, path.c_str(), &st, 0));
#else
        const int result = static_cast<int>(syscall(__NR_fstatat64, AT_FDCWD, path.c_str(), &st,
                                                    0));
#endif
        if (result == 0) {
            return true;
        }
        return errno != ENOENT;
    }

    bool package_exists(const std::string &package_name) {
        return stat_exists("/data/data/" + package_name) ||
               stat_exists("/data/user/0/" + package_name);
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_dangerousapps_data_native_DangerousAppsNativeBridge_nativeStatPackages(
        JNIEnv *env,
        jobject,
        jobjectArray package_names) {
    if (package_names == nullptr) {
        return to_jstring(env, "");
    }

    const jsize count = env->GetArrayLength(package_names);
    std::string output;

    for (jsize index = 0; index < count; ++index) {
        auto *java_package = static_cast<jstring>(env->GetObjectArrayElement(package_names, index));
        if (java_package == nullptr) {
            continue;
        }

        const char *chars = env->GetStringUTFChars(java_package, nullptr);
        if (chars != nullptr) {
            const std::string package_name(chars);
            env->ReleaseStringUTFChars(java_package, chars);

            if (package_exists(package_name)) {
                output.append(package_name);
                output.push_back('\n');
            }
        }

        env->DeleteLocalRef(java_package);
    }

    return to_jstring(env, output);
}
