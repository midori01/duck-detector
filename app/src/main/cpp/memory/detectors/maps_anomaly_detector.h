#ifndef DUCKDETECTOR_MEMORY_DETECTORS_MAPS_ANOMALY_DETECTOR_H
#define DUCKDETECTOR_MEMORY_DETECTORS_MAPS_ANOMALY_DETECTOR_H

#include "memory/common/types.h"

#include <vector>

namespace duckdetector::memory {

    MapsSignals detect_maps_anomalies(
            const std::vector<MapEntry> &maps,
            const std::vector<SmapsEntry> &smaps
    );

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_DETECTORS_MAPS_ANOMALY_DETECTOR_H
