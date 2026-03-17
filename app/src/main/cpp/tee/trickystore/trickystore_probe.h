#ifndef DUCKDETECTOR_TEE_TRICKYSTORE_PROBE_H
#define DUCKDETECTOR_TEE_TRICKYSTORE_PROBE_H

#include <string>
#include <vector>

namespace ducktee::trickystore {

    struct ProbeSnapshot {
        bool detected = false;
        bool got_hook_detected = false;
        bool syscall_mismatch_detected = false;
        bool inline_hook_detected = false;
        bool honeypot_detected = false;
        std::string details;
        std::vector<std::string> methods;
    };

    ProbeSnapshot inspect_process();

}  // namespace ducktee::trickystore

#endif  // DUCKDETECTOR_TEE_TRICKYSTORE_PROBE_H
