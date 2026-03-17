#ifndef DUCKDETECTOR_LSPOSED_COMMON_CODEC_H
#define DUCKDETECTOR_LSPOSED_COMMON_CODEC_H

#include <string>

#include "lsposed/common/types.h"

namespace duckdetector::lsposed {

    std::string encode_snapshot(const Snapshot &snapshot);

}  // namespace duckdetector::lsposed

#endif  // DUCKDETECTOR_LSPOSED_COMMON_CODEC_H
