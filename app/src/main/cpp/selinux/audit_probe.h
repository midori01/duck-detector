#ifndef DUCKDETECTOR_SELINUX_AUDIT_PROBE_H
#define DUCKDETECTOR_SELINUX_AUDIT_PROBE_H

#include <string>
#include <vector>

namespace duckdetector::selinux {

    struct AuditProbeSnapshot {
        bool available = false;
        bool callback_installed = false;
        bool probe_ran = false;
        bool denial_observed = false;
        bool allow_observed = false;
        std::string probe_marker;
        std::string failure_reason;
        std::vector<std::string> callback_lines;
    };

    AuditProbeSnapshot collect_audit_snapshot();

}  // namespace duckdetector::selinux

#endif  // DUCKDETECTOR_SELINUX_AUDIT_PROBE_H
