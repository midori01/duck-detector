#pragma once

#include <string>

#include "zygisk/common/types.h"

namespace duckdetector::zygisk {

    std::string escape_value(const std::string &value);

    std::string encode_snapshot(const Snapshot &snapshot);

}  // namespace duckdetector::zygisk
