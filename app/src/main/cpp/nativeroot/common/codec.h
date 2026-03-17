#ifndef DUCKDETECTOR_NATIVEROOT_COMMON_CODEC_H
#define DUCKDETECTOR_NATIVEROOT_COMMON_CODEC_H

#include <string>

#include "nativeroot/common/types.h"

namespace duckdetector::nativeroot {

    std::string encode_snapshot(const Snapshot &snapshot);

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_COMMON_CODEC_H
