#include "nativeroot/probes/path_probe.h"

#include "nativeroot/common/io_utils.h"

namespace duckdetector::nativeroot {
    namespace {

        enum class SuspiciousPathCategory {
            kRootManager,
        };

        struct PathRule {
            const char *path;
            const char *label;
            SuspiciousPathCategory category;
            bool kernel_su;
            bool apatch;
            bool magisk;
            Severity severity;
        };

        constexpr PathRule kPathRules[] = {
                {"/data/adb/ksud",           "KernelSU daemon",    SuspiciousPathCategory::kRootManager, true,  false, false, Severity::kDanger},
                {"/data/adb/ksu",            "KernelSU directory", SuspiciousPathCategory::kRootManager, true,  false, false, Severity::kDanger},
                {"/data/adb/ksu/bin",        "KernelSU binaries",  SuspiciousPathCategory::kRootManager, true,  false, false, Severity::kDanger},
                {"/data/adb/ksu/modules",    "KernelSU modules",   SuspiciousPathCategory::kRootManager, true,  false, false, Severity::kDanger},
                {"/data/adb/apd",            "APatch daemon",      SuspiciousPathCategory::kRootManager, false, true,  false, Severity::kDanger},
                {"/data/adb/ap",             "APatch directory",   SuspiciousPathCategory::kRootManager, false, true,  false, Severity::kDanger},
                {"/data/adb/ap/bin",         "APatch binaries",    SuspiciousPathCategory::kRootManager, false, true,  false, Severity::kDanger},
                {"/data/adb/ap/modules",     "APatch modules",     SuspiciousPathCategory::kRootManager, false, true,  false, Severity::kDanger},
                {"/data/adb/apatch",         "APatch residue",     SuspiciousPathCategory::kRootManager, false, true,  false, Severity::kDanger},
                {"/data/adb/magisk",         "Magisk directory",   SuspiciousPathCategory::kRootManager, false, false, true,  Severity::kDanger},
                {"/data/adb/magisk/magiskd", "Magisk daemon",      SuspiciousPathCategory::kRootManager, false, false, true,  Severity::kDanger},
                {"/sbin/.magisk",            "Magisk hidden dir",  SuspiciousPathCategory::kRootManager, false, false, true,  Severity::kDanger},
        };

        const char *category_label(const SuspiciousPathCategory category) {
            switch (category) {
                case SuspiciousPathCategory::kRootManager:
                    return "Root manager";
            }
            return "Residue";
        }

    }  // namespace

    ProbeResult run_path_probe() {
        ProbeResult result;
        result.checked_count = static_cast<int>(sizeof(kPathRules) / sizeof(kPathRules[0]));

        for (const PathRule &rule: kPathRules) {
            if (!file_exists(rule.path) && !dir_exists(rule.path)) {
                continue;
            }
            result.flags.kernel_su = result.flags.kernel_su || rule.kernel_su;
            result.flags.apatch = result.flags.apatch || rule.apatch;
            result.flags.magisk = result.flags.magisk || rule.magisk;
            result.hit_count += 1;
            result.findings.push_back(
                    Finding{
                            .group = "PATH",
                            .label = rule.label,
                            .value = "Present",
                            .detail = std::string("Category: ") + category_label(rule.category) +
                                      "\n" + rule.path,
                            .severity = rule.severity,
                    }
            );
        }

        return result;
    }

}  // namespace duckdetector::nativeroot
