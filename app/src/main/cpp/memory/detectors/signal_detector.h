#ifndef DUCKDETECTOR_MEMORY_DETECTORS_SIGNAL_DETECTOR_H
#define DUCKDETECTOR_MEMORY_DETECTORS_SIGNAL_DETECTOR_H

#include "memory/common/types.h"

#include <vector>

namespace duckdetector::memory {

    SignalSignals detect_signal_anomalies(const std::vector<MapEntry> &maps);

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_DETECTORS_SIGNAL_DETECTOR_H
