#ifndef DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_TYPES_H
#define DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_TYPES_H

#include <map>
#include <string>
#include <vector>

namespace duckdetector::playintegrityfix {

    enum class TraceSeverity {
        kDanger,
        kWarning,
    };

    struct RuntimeTrace {
        std::string label;
        std::string detail;
        TraceSeverity severity = TraceSeverity::kWarning;
    };

    struct Snapshot {
        bool available = false;
        std::map<std::string, std::string> native_properties;
        std::vector<RuntimeTrace> runtime_traces;
    };

    const char *to_string(TraceSeverity severity);

}  // namespace duckdetector::playintegrityfix

#endif  // DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_TYPES_H
