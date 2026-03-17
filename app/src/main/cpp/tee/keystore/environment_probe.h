#ifndef DUCKDETECTOR_TEE_KEYSTORE_ENVIRONMENT_PROBE_H
#define DUCKDETECTOR_TEE_KEYSTORE_ENVIRONMENT_PROBE_H

#include <string>
#include <vector>

namespace ducktee::keystore {

    struct EnvironmentSnapshot {
        bool tracing_detected = false;
        int page_size = 0;
        std::string timing_summary;
        std::vector<std::string> suspicious_mappings;
    };

    EnvironmentSnapshot collect_environment();

}  // namespace ducktee::keystore

#endif  // DUCKDETECTOR_TEE_KEYSTORE_ENVIRONMENT_PROBE_H
