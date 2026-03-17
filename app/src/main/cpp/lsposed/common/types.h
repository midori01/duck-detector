#ifndef DUCKDETECTOR_LSPOSED_COMMON_TYPES_H
#define DUCKDETECTOR_LSPOSED_COMMON_TYPES_H

#include <string>
#include <vector>

namespace duckdetector::lsposed {

    enum class Severity {
        kDanger,
        kWarning,
    };

    struct NativeTrace {
        std::string group;
        std::string label;
        std::string detail;
        Severity severity = Severity::kWarning;
    };

    struct ProbeResult {
        bool available = true;
        int hit_count = 0;
        int scanned_count = 0;
        std::vector<NativeTrace> traces;
    };

    struct Snapshot {
        bool available = false;
        bool heap_available = false;
        int maps_hit_count = 0;
        int maps_scanned_lines = 0;
        int heap_hit_count = 0;
        int heap_scanned_regions = 0;
        std::vector<NativeTrace> traces;
    };

    const char *to_string(Severity severity);

}  // namespace duckdetector::lsposed

#endif  // DUCKDETECTOR_LSPOSED_COMMON_TYPES_H
