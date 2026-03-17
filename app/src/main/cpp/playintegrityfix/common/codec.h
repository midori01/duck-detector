#ifndef DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_CODEC_H
#define DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_CODEC_H

#include "playintegrityfix/common/types.h"

#include <string>

namespace duckdetector::playintegrityfix {

    std::string encode_snapshot(const Snapshot &snapshot);

}  // namespace duckdetector::playintegrityfix

#endif  // DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_CODEC_H
