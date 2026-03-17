#ifndef DUCKDETECTOR_MEMORY_COMMON_CODEC_H
#define DUCKDETECTOR_MEMORY_COMMON_CODEC_H

#include "memory/common/types.h"

#include <string>

namespace duckdetector::memory {

    std::string escape_value(const std::string &value);

    std::string encode_snapshot(const Snapshot &snapshot);

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_COMMON_CODEC_H
