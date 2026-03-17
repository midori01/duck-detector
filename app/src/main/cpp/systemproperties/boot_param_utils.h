#pragma once

#include <map>
#include <set>
#include <string>

namespace systemproperties {

    std::map<std::string, std::string> parse_cmdline_params(
            const std::string &raw_cmdline,
            const std::set<std::string> &interesting_keys
    );

    std::map<std::string, std::string> parse_bootconfig_params(
            const std::string &raw_bootconfig,
            const std::set<std::string> &interesting_keys
    );

}  // namespace systemproperties
