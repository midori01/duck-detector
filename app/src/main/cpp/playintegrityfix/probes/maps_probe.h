#ifndef DUCKDETECTOR_PLAYINTEGRITYFIX_PROBES_MAPS_PROBE_H
#define DUCKDETECTOR_PLAYINTEGRITYFIX_PROBES_MAPS_PROBE_H

#include "playintegrityfix/common/types.h"

#include <vector>

namespace duckdetector::playintegrityfix {

    std::vector<RuntimeTrace> scan_runtime_maps();

}  // namespace duckdetector::playintegrityfix

#endif  // DUCKDETECTOR_PLAYINTEGRITYFIX_PROBES_MAPS_PROBE_H
