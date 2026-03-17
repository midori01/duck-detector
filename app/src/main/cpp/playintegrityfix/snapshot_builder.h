#ifndef DUCKDETECTOR_PLAYINTEGRITYFIX_SNAPSHOT_BUILDER_H
#define DUCKDETECTOR_PLAYINTEGRITYFIX_SNAPSHOT_BUILDER_H

#include "playintegrityfix/common/types.h"

#include <vector>
#include <string>

namespace duckdetector::playintegrityfix {

Snapshot collect_snapshot(const std::vector<std::string>& property_keys);

}  // namespace duckdetector::playintegrityfix

#endif  // DUCKDETECTOR_PLAYINTEGRITYFIX_SNAPSHOT_BUILDER_H
