#pragma once

#include <map>
#include <string>
#include <vector>

namespace systemproperties {

    std::string trim_copy(const std::string &value);

    std::string escape_value(std::string value);

    std::string read_text_file(const char *path, size_t max_bytes = 16384);

    std::string read_system_property(const std::string &key);

    std::map<std::string, std::string> read_system_properties(const std::vector<std::string> &keys);

}  // namespace systemproperties
