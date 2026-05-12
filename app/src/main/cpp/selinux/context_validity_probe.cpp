/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "selinux/context_validity_probe.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <utility>
#include <unistd.h>

namespace duckdetector::selinux {
    namespace {

        constexpr const char *kProcAttrCurrentPath = "/proc/self/attr/current";
        constexpr const char *kSelinuxContextPath = "/sys/fs/selinux/context";
        constexpr const char *kExpectedCarrierType = "app_zygote";
        constexpr const char *kKsuContext = "u:r:ksu:s0";
        constexpr const char *kKsuFileContext = "u:object_r:ksu_file:s0";
        constexpr const char *magiskFileContext = "u:object_r:magisk_file:s0";
        constexpr const char *kNegativeControlContext = "u:r:duckdetector_context_oracle_sentinel:s0";
        constexpr const char *kStockFileControlContext = "u:object_r:system_data_file:s0";
        constexpr const char *kNegativeFileControlContext =
                "u:object_r:duckdetector_context_oracle_sentinel_file:s0";
        constexpr const char *kQueryMethod = "raw selinuxfs write";
        constexpr const char *kDirtyPolicyQueryMethod =
                "android.os.SELinux.checkSELinuxAccess";
        constexpr const char *kSelinuxClassName = "android/os/SELinux";
        constexpr const char *kAppZygoteContext = "u:r:app_zygote:s0";
        constexpr const char *kIsolatedAppContext = "u:r:isolated_app:s0";
        constexpr const char *kUntrustedAppContext = "u:r:untrusted_app:s0";
        constexpr const char *kDirtyPolicySentinelFileContext =
                "u:object_r:duckdetector_dirty_policy_sentinel:s0";
        constexpr const char *kSystemServerContext = "u:r:system_server:s0";
        constexpr const char *kMagiskContext = "u:r:magisk:s0";
        constexpr const char *kLsposedFileContext = "u:object_r:lsposed_file:s0";

        struct ContextCheckResult {
            std::optional<bool> valid;
            std::string note;
        };

        struct ControlPairResult {
            ContextCheckResult first;
            ContextCheckResult second;
            bool stable = false;
        };

        struct DirtyPolicySymbols {
            jclass selinux_class = nullptr;
            jmethodID check_access = nullptr;
            jmethodID is_enabled = nullptr;
            jmethodID is_enforced = nullptr;
            std::string failure_reason;
        };

        struct DirtyPolicyStableAccessCheck {
            std::optional<bool> value;
            bool stable = false;
        };

        std::string trim(std::string value) {
            while (!value.empty() &&
                   (value.back() == '\n' || value.back() == '\r' || value.back() == '\0' ||
                    value.back() == ' ' || value.back() == '\t')) {
                value.pop_back();
            }
            while (!value.empty() &&
                   (value.front() == ' ' || value.front() == '\t')) {
                value.erase(value.begin());
            }
            return value;
        }

        std::string read_process_context() {
            std::ifstream input(kProcAttrCurrentPath);
            if (!input) {
                return {};
            }

            std::string context;
            std::getline(input, context, '\0');
            return trim(std::move(context));
        }

        std::string context_type(const std::string &context) {
            const std::size_t first = context.find(':');
            if (first == std::string::npos) {
                return {};
            }
            const std::size_t second = context.find(':', first + 1);
            if (second == std::string::npos) {
                return {};
            }
            const std::size_t third = context.find(':', second + 1);
            if (third == std::string::npos) {
                return context.substr(second + 1);
            }
            return context.substr(second + 1, third - second - 1);
        }

        void append_note(ContextValidityProbeSnapshot &snapshot, std::string note) {
            if (!note.empty()) {
                note += '\n';
                snapshot.notes.push_back(std::move(note));
            }
        }

        void append_dirty_note(DirtyPolicyProbeSnapshot &snapshot, std::string note) {
            if (!note.empty()) {
                snapshot.notes.push_back(std::move(note));
            }
        }

        void append_dirty_boolean_note(
                DirtyPolicyProbeSnapshot &snapshot,
                const char *label,
                const std::optional<bool> &value
        ) {
            std::string line(label);
            line += '=';
            if (value.has_value()) {
                line += *value ? "true" : "false";
            } else {
                line += "unavailable";
            }
            append_dirty_note(snapshot, std::move(line));
        }

        void append_boolean_note(
                ContextValidityProbeSnapshot &snapshot,
                const char *label,
                const std::optional<bool> &value
        ) {
            if (!value.has_value()) {
                append_note(snapshot, std::string(label) + "=unavailable");
                return;
            }
            append_note(snapshot, std::string(label) + (*value ? "=yes" : "=no"));
        }

        bool stable_result(
                const ContextCheckResult &first,
                const ContextCheckResult &second
        ) {
            return first.valid.has_value() == second.valid.has_value() &&
                   (!first.valid.has_value() || *first.valid == *second.valid);
        }

        ContextCheckResult check_context_validity(const char *context);
        DirtyPolicyProbeSnapshot collect_dirty_policy_snapshot(
                JNIEnv *env,
                const std::string &carrier_context
        );

        void clear_pending_exception(JNIEnv *env) {
            if (env != nullptr && env->ExceptionCheck()) {
                env->ExceptionClear();
            }
        }

        DirtyPolicySymbols load_dirty_policy_symbols(JNIEnv *env) {
            DirtyPolicySymbols symbols;
            if (env == nullptr) {
                symbols.failure_reason = "android.os.SELinux.checkSELinuxAccess unavailable.";
                return symbols;
            }

            symbols.selinux_class = static_cast<jclass>(env->FindClass(kSelinuxClassName));
            if (symbols.selinux_class == nullptr || env->ExceptionCheck()) {
                clear_pending_exception(env);
                symbols.failure_reason = "android.os.SELinux.checkSELinuxAccess unavailable.";
                return symbols;
            }

            symbols.check_access = env->GetStaticMethodID(
                    symbols.selinux_class,
                    "checkSELinuxAccess",
                    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z"
            );
            if (symbols.check_access == nullptr || env->ExceptionCheck()) {
                clear_pending_exception(env);
                env->DeleteLocalRef(symbols.selinux_class);
                symbols.selinux_class = nullptr;
                symbols.failure_reason = "android.os.SELinux.checkSELinuxAccess unavailable.";
                return symbols;
            }

            symbols.is_enabled = env->GetStaticMethodID(
                    symbols.selinux_class,
                    "isSELinuxEnabled",
                    "()Z"
            );
            if (symbols.is_enabled == nullptr || env->ExceptionCheck()) {
                clear_pending_exception(env);
                symbols.is_enabled = nullptr;
            }

            symbols.is_enforced = env->GetStaticMethodID(
                    symbols.selinux_class,
                    "isSELinuxEnforced",
                    "()Z"
            );
            if (symbols.is_enforced == nullptr || env->ExceptionCheck()) {
                clear_pending_exception(env);
                symbols.is_enforced = nullptr;
            }

            return symbols;
        }

        DirtyPolicyProbeSnapshot dirty_policy_failure(std::string message) {
            DirtyPolicyProbeSnapshot snapshot;
            snapshot.query_method = kDirtyPolicyQueryMethod;
            snapshot.failure_reason = message;
            snapshot.notes.push_back(std::move(message));
            return snapshot;
        }

        DirtyPolicyProbeSnapshot safe_collect_dirty_policy_snapshot(
                JNIEnv *env,
                const std::string &carrier_context
        ) {
            try {
                return collect_dirty_policy_snapshot(env, carrier_context);
            } catch (const std::exception &error) {
                return dirty_policy_failure(
                        std::string("Dirty policy probe failed: ") + error.what()
                );
            } catch (...) {
                return dirty_policy_failure(
                        "Dirty policy probe failed with an unknown native exception."
                );
            }
        }

        std::optional<bool> dirty_policy_access_allowed(
                JNIEnv *env,
                const DirtyPolicySymbols &symbols,
                const char *source_context,
                const char *target_context,
                const char *class_name,
                const char *permission
        ) {
            if (env == nullptr || symbols.selinux_class == nullptr || symbols.check_access == nullptr) {
                return std::nullopt;
            }

            jstring source = env->NewStringUTF(source_context);
            jstring target = env->NewStringUTF(target_context);
            jstring class_name_value = env->NewStringUTF(class_name);
            jstring permission_value = env->NewStringUTF(permission);
            if (source == nullptr || target == nullptr || class_name_value == nullptr || permission_value == nullptr) {
                if (source != nullptr) {
                    env->DeleteLocalRef(source);
                }
                if (target != nullptr) {
                    env->DeleteLocalRef(target);
                }
                if (class_name_value != nullptr) {
                    env->DeleteLocalRef(class_name_value);
                }
                if (permission_value != nullptr) {
                    env->DeleteLocalRef(permission_value);
                }
                clear_pending_exception(env);
                return std::nullopt;
            }

            const jboolean allowed = env->CallStaticBooleanMethod(
                    symbols.selinux_class,
                    symbols.check_access,
                    source,
                    target,
                    class_name_value,
                    permission_value
            );
            const bool has_exception = env->ExceptionCheck();

            env->DeleteLocalRef(source);
            env->DeleteLocalRef(target);
            env->DeleteLocalRef(class_name_value);
            env->DeleteLocalRef(permission_value);

            if (has_exception) {
                clear_pending_exception(env);
                return std::nullopt;
            }

            return allowed == JNI_TRUE;
        }

        DirtyPolicyStableAccessCheck repeat_dirty_policy_access_check(
                JNIEnv *env,
                const DirtyPolicySymbols &symbols,
                const char *source_context,
                const char *target_context,
                const char *class_name,
                const char *permission
        ) {
            const std::optional<bool> first = dirty_policy_access_allowed(
                    env,
                    symbols,
                    source_context,
                    target_context,
                    class_name,
                    permission
            );
            const std::optional<bool> second = dirty_policy_access_allowed(
                    env,
                    symbols,
                    source_context,
                    target_context,
                    class_name,
                    permission
            );
            const bool stable = first.has_value() &&
                                second.has_value() &&
                                *first == *second;
            return {
                    .value = stable ? first : std::nullopt,
                    .stable = stable,
            };
        }

        std::optional<bool> dirty_policy_static_boolean(
                JNIEnv *env,
                const DirtyPolicySymbols &symbols,
                jmethodID method
        ) {
            if (env == nullptr || symbols.selinux_class == nullptr || method == nullptr) {
                return std::nullopt;
            }

            const jboolean value = env->CallStaticBooleanMethod(symbols.selinux_class, method);
            if (env->ExceptionCheck()) {
                clear_pending_exception(env);
                return std::nullopt;
            }
            return value == JNI_TRUE;
        }

        void release_dirty_policy_symbols(
                JNIEnv *env,
                DirtyPolicySymbols &symbols
        ) {
            if (env != nullptr && symbols.selinux_class != nullptr) {
                env->DeleteLocalRef(symbols.selinux_class);
                symbols.selinux_class = nullptr;
            }
        }

        DirtyPolicyProbeSnapshot collect_dirty_policy_snapshot(
                JNIEnv *env,
                const std::string &carrier_context
        ) {
            DirtyPolicyProbeSnapshot snapshot;
            snapshot.query_method = kDirtyPolicyQueryMethod;

            DirtyPolicySymbols symbols = load_dirty_policy_symbols(env);
            if (symbols.check_access == nullptr) {
                return dirty_policy_failure(symbols.failure_reason);
            }
            snapshot.available = true;

            const std::optional<bool> selinux_enabled =
                    dirty_policy_static_boolean(env, symbols, symbols.is_enabled);
            if (selinux_enabled == false) {
                snapshot.failure_reason = "SELinux is disabled.";
                append_dirty_note(snapshot, snapshot.failure_reason);
                release_dirty_policy_symbols(env, symbols);
                return snapshot;
            }
            const std::optional<bool> selinux_enforced =
                    dirty_policy_static_boolean(env, symbols, symbols.is_enforced);
            if (selinux_enforced == false) {
                snapshot.failure_reason = "SELinux is permissive.";
                append_dirty_note(snapshot, snapshot.failure_reason);
                release_dirty_policy_symbols(env, symbols);
                return snapshot;
            }

            if (carrier_context.empty()) {
                snapshot.failure_reason = "Current process SELinux context unreadable.";
                append_dirty_note(snapshot, snapshot.failure_reason);
                release_dirty_policy_symbols(env, symbols);
                return snapshot;
            }

            snapshot.carrier_context = carrier_context;
            snapshot.carrier_matches_expected = context_type(carrier_context) == kExpectedCarrierType;
            append_dirty_note(snapshot, std::string("Carrier context: ") + carrier_context);
            append_dirty_note(snapshot, std::string("Expected carrier type: ") + kExpectedCarrierType);
            append_dirty_note(snapshot, std::string("Query method: ") + kDirtyPolicyQueryMethod);

            if (!snapshot.carrier_matches_expected) {
                snapshot.failure_reason = "Carrier context is not app_zygote.";
                append_dirty_note(snapshot, snapshot.failure_reason);
                release_dirty_policy_symbols(env, symbols);
                return snapshot;
            }

            snapshot.probe_attempted = true;

            const DirtyPolicyStableAccessCheck access_control =
                    repeat_dirty_policy_access_check(
                            env,
                            symbols,
                            kAppZygoteContext,
                            kIsolatedAppContext,
                            "process",
                            "dyntransition"
                    );
            const DirtyPolicyStableAccessCheck negative_control =
                    repeat_dirty_policy_access_check(
                            env,
                            symbols,
                            kUntrustedAppContext,
                            kDirtyPolicySentinelFileContext,
                            "file",
                            "read"
                    );

            snapshot.access_control_allowed = access_control.value;
            snapshot.negative_control_rejected =
                    negative_control.value.has_value()
                    ? std::optional<bool>(!*negative_control.value)
                    : std::nullopt;
            snapshot.controls_passed =
                    access_control.stable &&
                    negative_control.stable &&
                    access_control.value == true &&
                    negative_control.value == false;

            if (!access_control.stable || !negative_control.stable) {
                snapshot.failure_reason = "Dirty policy oracle self-test failed.";
                append_dirty_note(
                        snapshot,
                        std::string("Positive control stable=") +
                        (access_control.stable ? "true" : "false")
                );
                append_dirty_note(
                        snapshot,
                        std::string("Negative control stable=") +
                        (negative_control.stable ? "true" : "false")
                );
                append_dirty_note(
                        snapshot,
                        "The SELinux access oracle was not trusted because its controls were unstable."
                );
            }

            if (!snapshot.controls_passed) {
                if (snapshot.failure_reason.empty()) {
                    snapshot.failure_reason = "Dirty policy oracle self-test failed.";
                }
                append_dirty_boolean_note(
                        snapshot,
                        "Positive control accepted",
                        access_control.value
                );
                append_dirty_boolean_note(
                        snapshot,
                        "Negative control rejected",
                        snapshot.negative_control_rejected
                );
                append_dirty_note(snapshot, "The SELinux access oracle did not pass its self-test.");
            }

            const DirtyPolicyStableAccessCheck system_server_execmem =
                    repeat_dirty_policy_access_check(
                            env,
                            symbols,
                            kSystemServerContext,
                            kSystemServerContext,
                            "process",
                            "execmem"
                    );
            const DirtyPolicyStableAccessCheck magisk_binder_call =
                    repeat_dirty_policy_access_check(
                            env,
                            symbols,
                            kUntrustedAppContext,
                            kMagiskContext,
                            "binder",
                            "call"
                    );
            const DirtyPolicyStableAccessCheck ksu_binder_call =
                    repeat_dirty_policy_access_check(
                            env,
                            symbols,
                            kUntrustedAppContext,
                            kKsuContext,
                            "binder",
                            "call"
                    );
            const DirtyPolicyStableAccessCheck lsposed_file_read =
                    repeat_dirty_policy_access_check(
                            env,
                            symbols,
                            kUntrustedAppContext,
                            kLsposedFileContext,
                            "file",
                            "read"
                    );

            snapshot.stable = system_server_execmem.stable &&
                              magisk_binder_call.stable &&
                              ksu_binder_call.stable &&
                              lsposed_file_read.stable;

            append_dirty_boolean_note(snapshot, "Positive control accepted", access_control.value);
            append_dirty_boolean_note(
                    snapshot,
                    "Negative control rejected",
                    snapshot.negative_control_rejected
            );
            append_dirty_boolean_note(snapshot, "system_server execmem", system_server_execmem.value);
            append_dirty_boolean_note(snapshot, "Magisk binder call", magisk_binder_call.value);
            append_dirty_boolean_note(snapshot, "KernelSU binder call", ksu_binder_call.value);
            append_dirty_boolean_note(snapshot, "LSPosed file read", lsposed_file_read.value);

            snapshot.system_server_execmem_allowed = system_server_execmem.value;
            snapshot.magisk_binder_call_allowed = magisk_binder_call.value;
            snapshot.ksu_binder_call_allowed = ksu_binder_call.value;
            snapshot.lsposed_file_read_allowed = lsposed_file_read.value;

            if (!snapshot.stable) {
                if (snapshot.failure_reason.empty()) {
                    snapshot.failure_reason = "Dirty policy oracle repeatability failed.";
                }
                append_dirty_note(
                        snapshot,
                        "One or more dirty policy queries were unstable across repeated checks."
                );
            }

            release_dirty_policy_symbols(env, symbols);
            return snapshot;
        }

        bool pair_matches_expected(
                const ControlPairResult &pair,
                const bool expected_valid
        ) {
            return pair.stable &&
                   pair.first.valid.has_value() &&
                   *pair.first.valid == expected_valid;
        }

        std::optional<bool> pair_valid_value(const ControlPairResult &pair) {
            if (!pair_matches_expected(pair, true) && !pair_matches_expected(pair, false)) {
                return std::nullopt;
            }
            return pair.first.valid;
        }

        std::optional<bool> pair_rejected_value(const ControlPairResult &pair) {
            if (!pair.stable || !pair.first.valid.has_value()) {
                return std::nullopt;
            }
            return !*pair.first.valid;
        }

        ControlPairResult check_context_pair_validity(const char *context) {
            ControlPairResult result;
            result.first = check_context_validity(context);
            result.second = check_context_validity(context);
            result.stable = stable_result(result.first, result.second);
            return result;
        }

        void append_repeat_note(
                ContextValidityProbeSnapshot &snapshot,
                const char *label,
                const ContextCheckResult &result
        ) {
            std::string line(label);
            line += '=';
            if (result.valid.has_value()) {
                line += *result.valid ? "valid" : "invalid";
            } else {
                line += "unavailable";
            }
            if (!result.note.empty()) {
                line += " (";
                line += result.note;
                line += ')';
            }
            append_note(snapshot, std::move(line));
        }

        ContextCheckResult check_context_validity(const char *context) {
            ContextCheckResult result;

            int fd = open(kSelinuxContextPath, O_RDWR | O_CLOEXEC);
            if (fd < 0) {
                result.valid = false;
                result.note = std::string("Unavailable: ") + context + " errno=" + strerror(errno);
                return result;
            }

            const ssize_t written = write(fd, context, std::strlen(context) + 1);
            const int error = errno;
            close(fd);

            if (written >= 0) {
                result.valid = true;
                return result;
            }

            result.valid = false;
            result.note = std::string("Unavailable: ") + context + " errno=" + strerror(error);
            return result;
        }

    }  // namespace

    ContextValidityProbeSnapshot collect_context_validity_snapshot(JNIEnv *env) {
        ContextValidityProbeSnapshot snapshot;
        snapshot.query_method = kQueryMethod;

        const std::string carrier_context = read_process_context();
        snapshot.dirty_policy = safe_collect_dirty_policy_snapshot(env, carrier_context);
        if (carrier_context.empty()) {
            snapshot.failure_reason = "Current process SELinux context unreadable.";
            return snapshot;
        }

        snapshot.available = true;
        snapshot.carrier_context = carrier_context;
        snapshot.carrier_matches_expected = context_type(carrier_context) == kExpectedCarrierType;
        append_note(snapshot, std::string("Carrier context: ") + carrier_context);
        append_note(snapshot, std::string("Expected carrier type: ") + kExpectedCarrierType);

        if (!snapshot.carrier_matches_expected) {
            snapshot.failure_reason = "Carrier context is not app_zygote.";
            append_note(snapshot, "The oracle is only meaningful from an app_zygote carrier.");
            return snapshot;
        }

        snapshot.probe_attempted = true;

        const ControlPairResult carrier_control = check_context_pair_validity(carrier_context.c_str());
        const ControlPairResult negative_control = check_context_pair_validity(kNegativeControlContext);
        const ControlPairResult file_control = check_context_pair_validity(kStockFileControlContext);
        const ControlPairResult negative_file_control =
                check_context_pair_validity(kNegativeFileControlContext);

        snapshot.carrier_control_valid = pair_valid_value(carrier_control);
        snapshot.negative_control_rejected = pair_rejected_value(negative_control);
        snapshot.file_control_valid = pair_valid_value(file_control);
        snapshot.file_negative_control_rejected = pair_rejected_value(negative_file_control);
        snapshot.oracle_controls_passed =
                pair_matches_expected(carrier_control, true) &&
                pair_matches_expected(negative_control, false) &&
                pair_matches_expected(file_control, true) &&
                pair_matches_expected(negative_file_control, false);

        append_note(snapshot, std::string("Query method: ") + kQueryMethod);
        append_note(snapshot, std::string("Positive control context: ") + carrier_context);
        append_note(snapshot, std::string("Negative control context: ") + kNegativeControlContext);
        append_note(snapshot, std::string("File control context: ") + kStockFileControlContext);
        append_note(snapshot,
                    std::string("File negative control context: ") + kNegativeFileControlContext);
        append_note(snapshot, carrier_control.first.note);
        append_note(snapshot, negative_control.first.note);
        append_note(snapshot, file_control.first.note);
        append_note(snapshot, negative_file_control.first.note);
        if (!carrier_control.stable) {
            append_note(snapshot, "Carrier control repeated inconsistently.");
        }
        if (!negative_control.stable) {
            append_note(snapshot, "Negative control repeated inconsistently.");
        }
        if (!file_control.stable) {
            append_note(snapshot, "File control repeated inconsistently.");
        }
        if (!negative_file_control.stable) {
            append_note(snapshot, "File negative control repeated inconsistently.");
        }
        append_boolean_note(snapshot, "Carrier control valid", snapshot.carrier_control_valid);
        append_boolean_note(snapshot, "Negative control rejected", snapshot.negative_control_rejected);
        append_boolean_note(snapshot, "File control valid", snapshot.file_control_valid);
        append_boolean_note(snapshot,
                            "File negative control rejected",
                            snapshot.file_negative_control_rejected);

        if (!snapshot.oracle_controls_passed) {
            snapshot.failure_reason = "Context validity oracle self-test failed.";
            append_note(snapshot,
                        "KSU-specific context queries were skipped to avoid interpreting an untrusted oracle.");
            return snapshot;
        }

        const ContextCheckResult domain_first = check_context_validity(kKsuContext);
        const ContextCheckResult domain_second = check_context_validity(kKsuContext);
        const ContextCheckResult file_first = check_context_validity(kKsuFileContext);
        const ContextCheckResult file_second = check_context_validity(kKsuFileContext);
        const ContextCheckResult magisk_file_first = check_context_validity(magiskFileContext);
        const ContextCheckResult magisk_file_second = check_context_validity(magiskFileContext);

        const bool domain_stable = stable_result(domain_first, domain_second);
        const bool file_stable = stable_result(file_first, file_second);
        const bool magisk_file_stable = stable_result(magisk_file_first, magisk_file_second);
        snapshot.ksu_results_stable = domain_stable && file_stable && magisk_file_stable;

        append_repeat_note(snapshot, "u:r:ksu:s0 test repeat 1", domain_first);
        append_repeat_note(snapshot, "u:r:ksu:s0 test repeat 2", domain_second);
        append_repeat_note(snapshot, "u:object_r:ksu_file:s0 test repeat 1", file_first);
        append_repeat_note(snapshot, "u:object_r:ksu_file:s0 repeat 2", file_second);
        append_repeat_note(snapshot, "u:object_r:magisk_file:s0 repeat 1", magisk_file_first);
        append_repeat_note(snapshot, "u:object_r:magisk_file:s0 repeat 2", magisk_file_second);

        if (!snapshot.ksu_results_stable) {
            snapshot.failure_reason = "Context validity oracle repeatability failed.";
            append_note(snapshot,
                        "The root-specific context verdict changed across repeated writes, so it was not trusted.");
            return snapshot;
        }

        const ContextCheckResult& ksu_domain_result = domain_first;
        const ContextCheckResult& ksu_file_result = file_first;
        const ContextCheckResult& magisk_file_result = magisk_file_first;

        snapshot.ksu_domain_valid = ksu_domain_result.valid;
        snapshot.ksu_file_valid = ksu_file_result.valid;
        snapshot.magisk_file_valid = magisk_file_result.valid;
        append_note(snapshot, ksu_domain_result.note);
        append_note(snapshot, ksu_file_result.note);
        append_note(snapshot, magisk_file_result.note);

        if (ksu_domain_result.valid.has_value() || ksu_file_result.valid.has_value() || magisk_file_result.valid.has_value()) {

            if (ksu_domain_result.valid.value()) {
                append_note(snapshot, "u:r:ksu:s0 was found by live policy.");
            }

            if (ksu_file_result.valid.value()) {
                append_note(snapshot, "u:object_r:ksu_file:s0 was found by live policy.");
            }

            if (magisk_file_result.valid.value()) {
                append_note(snapshot, "u:object_r:magisk_file:s0 was found by live policy.");
            }
            return snapshot;
        }

        snapshot.failure_reason = "Context validity probe could not complete both checks.";
        return snapshot;
    }

}  // namespace duckdetector::selinux
