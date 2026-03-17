#include "playintegrityfix/snapshot_builder.h"

#include "playintegrityfix/probes/maps_probe.h"
#include "playintegrityfix/probes/property_probe.h"

namespace duckdetector::playintegrityfix {

    Snapshot collect_snapshot(const std::vector<std::string> &property_keys) {
        Snapshot snapshot;
        snapshot.available = true;
        snapshot.native_properties = read_properties(property_keys);
        snapshot.runtime_traces = scan_runtime_maps();
        return snapshot;
    }

}  // namespace duckdetector::playintegrityfix
