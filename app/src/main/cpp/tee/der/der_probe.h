#ifndef DUCKDETECTOR_TEE_DER_DER_PROBE_H
#define DUCKDETECTOR_TEE_DER_DER_PROBE_H

#include <cstdint>
#include <vector>

namespace ducktee::der {

    struct DerSnapshot {
        bool primary_detected = false;
        bool secondary_detected = false;
        std::vector<std::string> findings;
    };

    DerSnapshot scan_leaf_der(const std::vector<std::uint8_t> &bytes);

}  // namespace ducktee::der

#endif  // DUCKDETECTOR_TEE_DER_DER_PROBE_H
