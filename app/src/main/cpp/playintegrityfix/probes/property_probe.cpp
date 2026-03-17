#include "playintegrityfix/probes/property_probe.h"

#include <sys/system_properties.h>

namespace duckdetector::playintegrityfix {

    std::map<std::string, std::string> read_properties(const std::vector<std::string> &keys) {
        std::map<std::string, std::string> properties;
        for (const std::string &key: keys) {
            char buffer[PROP_VALUE_MAX] = {};
            const int length = __system_property_get(key.c_str(), buffer);
            if (length > 0) {
                properties[key] = std::string(buffer, static_cast<size_t>(length));
            } else {
                properties[key] = "";
            }
        }
        return properties;
    }

}  // namespace duckdetector::playintegrityfix
