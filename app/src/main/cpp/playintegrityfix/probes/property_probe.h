#ifndef DUCKDETECTOR_PLAYINTEGRITYFIX_PROBES_PROPERTY_PROBE_H
#define DUCKDETECTOR_PLAYINTEGRITYFIX_PROBES_PROPERTY_PROBE_H

#include <map>
#include <string>
#include <vector>

namespace duckdetector::playintegrityfix {

    std::map<std::string, std::string> read_properties(const std::vector<std::string> &keys);

}  // namespace duckdetector::playintegrityfix

#endif  // DUCKDETECTOR_PLAYINTEGRITYFIX_PROBES_PROPERTY_PROBE_H
