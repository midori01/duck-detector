#ifndef DUCKDETECTOR_MEMORY_DETECTORS_FUNCTION_HOOK_DETECTOR_H
#define DUCKDETECTOR_MEMORY_DETECTORS_FUNCTION_HOOK_DETECTOR_H

#include "memory/common/types.h"

#include <vector>

namespace duckdetector::memory {

    HookSignals detect_function_hooks(const std::vector<MapEntry> &maps);

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_DETECTORS_FUNCTION_HOOK_DETECTOR_H
