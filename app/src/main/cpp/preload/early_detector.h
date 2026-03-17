#ifndef DUCKDETECTOR_PRELOAD_EARLY_DETECTOR_H
#define DUCKDETECTOR_PRELOAD_EARLY_DETECTOR_H

#include <cstdint>
#include <string>
#include <vector>

namespace duckdetector::preload {

    struct EarlyMountPreloadResult {
        bool futileHideDetected = false;
        bool minorDevGapDetected = false;
        bool peerGroupGapDetected = false;
        bool mountIdGapDetected = false;
        bool mntStringsDetected = false;

        std::int64_t nsMntCtimeDeltaNs = 0;
        std::int64_t mountInfoCtimeDeltaNs = 0;
        std::string mntStringsSource;
        std::string mntStringsTarget;
        std::string mntStringsFs;

        std::vector<std::string> findings;

        bool detected = false;
        std::string detectionMethod;
        std::string details;
    };

    EarlyMountPreloadResult run_early_detection();

    bool detect_futile_hide(EarlyMountPreloadResult &result);

    bool detect_mnt_strings_anomaly(EarlyMountPreloadResult &result);

    bool detect_mount_id_loophole(EarlyMountPreloadResult &result);

    bool detect_minor_dev_gap(EarlyMountPreloadResult &result);

    bool detect_peer_group_gap(EarlyMountPreloadResult &result);

    bool is_preload_context_valid();

    const EarlyMountPreloadResult *get_stored_result();

    bool has_early_detection_run();

    void reset_early_detection();

}  // namespace duckdetector::preload

#endif  // DUCKDETECTOR_PRELOAD_EARLY_DETECTOR_H
