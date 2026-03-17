#include "nativeroot/snapshot_builder.h"

#include <set>
#include <string>

#include "nativeroot/common/codec.h"
#include "nativeroot/probes/kernel_probe.h"
#include "nativeroot/probes/path_probe.h"
#include "nativeroot/probes/process_probe.h"
#include "nativeroot/probes/property_probe.h"
#include "nativeroot/probes/prctl_probe.h"
#include "nativeroot/probes/susfs_probe.h"

namespace duckdetector::nativeroot {
    namespace {

        void append_probe_findings(
                Snapshot &snapshot,
                const ProbeResult &probe,
                std::set<std::string> &dedupe
        ) {
            merge_flags(snapshot.flags, probe.flags);
            for (const Finding &finding: probe.findings) {
                const std::string key = finding.group + "|" + finding.label + "|" + finding.detail;
                if (!dedupe.insert(key).second) {
                    continue;
                }
                snapshot.findings.push_back(finding);
            }
        }

    }  // namespace

    Snapshot collect_snapshot() {
        Snapshot snapshot;
        snapshot.available = true;

        const ProbeResult prctl_probe = run_prctl_probe();
        const ProbeResult susfs_probe = run_susfs_probe();
        const ProbeResult path_probe = run_path_probe();
        const ProbeResult process_probe = run_process_probe();
        const ProbeResult kernel_probe = run_kernel_probe();
        const ProbeResult property_probe = run_property_probe();

        snapshot.kernel_su_version = prctl_probe.numeric_value;
        snapshot.prctl_probe_hit = prctl_probe.flags.kernel_su;
        snapshot.susfs_probe_hit = susfs_probe.flags.susfs;
        snapshot.path_hit_count = path_probe.hit_count;
        snapshot.path_check_count = path_probe.checked_count;
        snapshot.process_hit_count = process_probe.hit_count;
        snapshot.process_checked_count = process_probe.checked_count;
        snapshot.process_denied_count = process_probe.denied_count;
        snapshot.kernel_hit_count = kernel_probe.hit_count;
        snapshot.kernel_source_count = kernel_probe.checked_count;
        snapshot.property_hit_count = property_probe.hit_count;
        snapshot.property_check_count = property_probe.checked_count;

        std::set<std::string> dedupe;
        append_probe_findings(snapshot, prctl_probe, dedupe);
        append_probe_findings(snapshot, susfs_probe, dedupe);
        append_probe_findings(snapshot, path_probe, dedupe);
        append_probe_findings(snapshot, process_probe, dedupe);
        append_probe_findings(snapshot, kernel_probe, dedupe);
        append_probe_findings(snapshot, property_probe, dedupe);

        return snapshot;
    }

}  // namespace duckdetector::nativeroot
